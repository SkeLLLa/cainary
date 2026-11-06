//! Pure OTLP/JSON classification and value helpers.
//!
//! `classify(export, doc)` validates the selected OTLP signal and returns borrowed
//! `Classified`, `ResourceOut`, `ScopeOut`, `Record`, and `Field` values. Record
//! and field names remain available for local drift checks; consumers must apply
//! their output policy before displaying payload-derived names or values.
//! `summarize(&classified)` produces an owned, `Serialize`-ready summary with
//! per-name counts and the union of catalogued attributes. `mask` returns only
//! a type and length, `text_of` extracts bounded scalar text for matching, and
//! `mask_match` produces the brief's bounded match display. `ClassifyError`
//! contains fixed categories and numeric indexes only; it never stores JSON
//! error text, input keys, or input values.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use super::otel_catalog::{self, Attr, Catalog, Export, Group, Item, ItemKind, Vendor};

/// A classified OTLP document. `records` includes metric data points and span
/// events; `unknown` counts records with no matching catalog item.
#[derive(Debug, Clone)]
pub struct Classified<'a> {
    pub export: Export,
    pub vendor: Option<Vendor>,
    pub service: Option<(String, Option<String>)>,
    pub resources: Vec<ResourceOut<'a>>,
    pub records: usize,
    pub unknown: usize,
}

/// One OTLP resource and its instrumentation scopes.
#[derive(Debug, Clone)]
pub struct ResourceOut<'a> {
    pub attrs: Vec<Field<'a>>,
    pub scopes: Vec<ScopeOut<'a>>,
}

/// One instrumentation scope and its records.
#[derive(Debug, Clone)]
pub struct ScopeOut<'a> {
    pub name: String,
    pub version: Option<String>,
    pub records: Vec<Record<'a>>,
}

/// A log record, metric data point, span, or span event.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    /// Borrowed from the document for metrics and spans, so the points of one metric (and the
    /// events of one span) share one name instead of cloning it per record.
    pub name: Cow<'a, str>,
    pub kind: ItemKind,
    pub item: Option<&'static Item>,
    /// Metric data points: the OTLP family (`sum`, `gauge`, `histogram`, …).
    pub family: Option<&'static str>,
    pub parent: Option<Cow<'a, str>>,
    pub body: Option<&'a Value>,
    pub fields: Vec<Field<'a>>,
}

/// An OTLP attribute and its catalog match, if any.
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub key: String,
    pub attr: Option<&'static Attr>,
    /// The OTLP `AnyValue` object. Call [`mask`] before displaying it.
    pub value: &'a Value,
}

/// Fixed error categories. The optional index is an input-independent numeric
/// position within the selected signal array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyError {
    /// The document root was not a JSON object.
    NotObject,
    /// The required OTLP signal root was absent.
    MissingRoot(&'static str),
    /// A signal object or array had an invalid shape.
    BadShape { index: Option<usize> },
}

/// One catalog attribute in a serializable summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SummaryAttr {
    pub key: String,
    pub group: Option<Group>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag: Option<&'static str>,
    pub known: bool,
}

/// One record-name group in a serializable summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SummaryRecord {
    pub name: String,
    pub kind: ItemKind,
    pub count: usize,
    pub known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub what: Option<&'static str>,
    pub attrs: Vec<SummaryAttr>,
}

/// JSON-friendly view used by the net crate's JSON-lines `summary` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub identity: Vec<String>,
    pub resource: Vec<String>,
    pub records: Vec<SummaryRecord>,
}

/// Classifies an OTLP/JSON document for the given signal.
pub fn classify<'a>(export: Export, doc: &'a Value) -> Result<Classified<'a>, ClassifyError> {
    if !doc.is_object() {
        return Err(ClassifyError::NotObject);
    }

    let (root_name, scope_name, records_name) = signal_names(export);
    let root = doc
        .get(root_name)
        .ok_or(ClassifyError::MissingRoot(root_name))?;
    let root = root
        .as_array()
        .ok_or(ClassifyError::BadShape { index: None })?;

    let mut classified = Classified {
        export,
        vendor: None,
        service: None,
        resources: Vec::with_capacity(root.len()),
        records: 0,
        unknown: 0,
    };

    for (resource_index, resource_group) in root.iter().enumerate() {
        if !resource_group.is_object() {
            return Err(ClassifyError::BadShape {
                index: Some(resource_index),
            });
        }
        let resource = resource_group.get("resource");
        if resource.is_some_and(|value| !value.is_object()) {
            return Err(ClassifyError::BadShape {
                index: Some(resource_index),
            });
        }
        let service = resource.and_then(service_from_resource);
        if classified.service.is_none() {
            classified.service = service.clone();
        }
        let service_vendor = service
            .as_ref()
            .and_then(|(name, _)| vendor_from_service(name));

        let scopes = resource_group.get(scope_name);
        let scopes = match scopes {
            None => &[][..],
            Some(scopes) => scopes
                .as_array()
                .ok_or(ClassifyError::BadShape {
                    index: Some(resource_index),
                })?
                .as_slice(),
        };
        let mut out_scopes = Vec::with_capacity(scopes.len());
        let mut resource_vendor = service_vendor;

        for scope_group in scopes {
            let scope = scope_group.as_object().ok_or(ClassifyError::BadShape {
                index: Some(resource_index),
            })?;
            let (name, version) = scope_metadata(scope, resource_index)?;
            let records = scope
                .get(records_name)
                .map(|value| {
                    value.as_array().ok_or(ClassifyError::BadShape {
                        index: Some(resource_index),
                    })
                })
                .transpose()?
                .map_or(&[][..], Vec::as_slice);

            let local_vendor = service_vendor.or_else(|| vendor_from_scope(&name));
            if resource_vendor.is_none() {
                resource_vendor = local_vendor;
            }
            if classified.vendor.is_none() {
                classified.vendor = local_vendor;
            }
            let cat = local_vendor.map(otel_catalog::catalog);
            let out_records = match export {
                Export::Logs | Export::Beta => classify_logs(
                    records,
                    cat,
                    export,
                    resource_index,
                    &mut classified.records,
                    &mut classified.unknown,
                )?,
                Export::Metrics => classify_metrics(
                    records,
                    cat,
                    export,
                    resource_index,
                    &mut classified.records,
                    &mut classified.unknown,
                )?,
                Export::Traces => classify_spans(
                    records,
                    cat,
                    export,
                    resource_index,
                    &mut classified.records,
                    &mut classified.unknown,
                )?,
            };
            out_scopes.push(ScopeOut {
                name,
                version,
                records: out_records,
            });
        }

        let cat = resource_vendor.map(otel_catalog::catalog);
        let attrs = resource
            .and_then(|value| value.get("attributes"))
            .map(|attrs| classify_fields(attrs, cat, None, export, resource_index))
            .transpose()?
            .unwrap_or_default();
        classified.resources.push(ResourceOut {
            attrs,
            scopes: out_scopes,
        });
    }

    Ok(classified)
}

/// Builds the JSON-friendly identity/resource key lists and per-name summary.
pub fn summarize(classified: &Classified<'_>) -> Summary {
    let mut identity = BTreeSet::new();
    let mut resource = BTreeSet::new();
    let mut records: BTreeMap<String, SummaryRecord> = BTreeMap::new();

    for resource_out in &classified.resources {
        collect_group_keys(&resource_out.attrs, &mut identity, &mut resource);
        for scope in &resource_out.scopes {
            for record in &scope.records {
                collect_group_keys(&record.fields, &mut identity, &mut resource);
                let known = record.item.is_some();
                let entry =
                    records
                        .entry(record.name.to_string())
                        .or_insert_with(|| SummaryRecord {
                            name: record.name.to_string(),
                            kind: record.kind,
                            count: 0,
                            known,
                            what: record.item.map(|item| item.what),
                            attrs: Vec::new(),
                        });
                entry.count += 1;
                entry.known &= known;
                let mut attrs: BTreeMap<String, SummaryAttr> = entry
                    .attrs
                    .drain(..)
                    .map(|attr| (attr.key.clone(), attr))
                    .collect();
                for field in &record.fields {
                    let attr = field.attr;
                    attrs
                        .entry(field.key.clone())
                        .or_insert_with(|| SummaryAttr {
                            key: field.key.clone(),
                            group: attr.map(|attr| attr.group),
                            flag: attr.and_then(|attr| attr.gate).map(|gate| gate.flag),
                            known: attr.is_some(),
                        });
                }
                entry.attrs = attrs.into_values().collect();
            }
        }
    }

    Summary {
        identity: identity.into_iter().collect(),
        resource: resource.into_iter().collect(),
        records: records.into_values().collect(),
    }
}

fn collect_group_keys(
    fields: &[Field<'_>],
    identity: &mut BTreeSet<String>,
    resource: &mut BTreeSet<String>,
) {
    for field in fields {
        match field.attr.map(|attr| attr.group) {
            Some(Group::Identity) => {
                identity.insert(field.key.clone());
            }
            Some(Group::Resource) => {
                resource.insert(field.key.clone());
            }
            _ => {}
        }
    }
}

fn signal_names(export: Export) -> (&'static str, &'static str, &'static str) {
    match export {
        Export::Logs | Export::Beta => ("resourceLogs", "scopeLogs", "logRecords"),
        Export::Metrics => ("resourceMetrics", "scopeMetrics", "metrics"),
        Export::Traces => ("resourceSpans", "scopeSpans", "spans"),
    }
}

fn service_from_resource(resource: &Value) -> Option<(String, Option<String>)> {
    let attributes = resource.get("attributes")?.as_array()?;
    let mut name = None;
    let mut version = None;
    for attribute in attributes {
        let Some(object) = attribute.as_object() else {
            continue;
        };
        let Some(key) = object.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = object.get("value") else {
            continue;
        };
        match key {
            "service.name" => name = any_string(value).map(str::to_owned),
            "service.version" => version = any_string(value).map(str::to_owned),
            _ => {}
        }
    }
    name.map(|name| (name, version))
}

fn scope_metadata(
    scope_group: &serde_json::Map<String, Value>,
    index: usize,
) -> Result<(String, Option<String>), ClassifyError> {
    let scope = scope_group
        .get("scope")
        .or_else(|| scope_group.get("instrumentationLibrary"));
    let Some(scope) = scope else {
        return Ok((String::new(), None));
    };
    let scope = scope
        .as_object()
        .ok_or(ClassifyError::BadShape { index: Some(index) })?;
    let name = match scope.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(name)) => name.clone(),
        _ => return Err(ClassifyError::BadShape { index: Some(index) }),
    };
    let version = match scope.get("version") {
        None | Some(Value::Null) => None,
        Some(Value::String(version)) => Some(version.clone()),
        _ => return Err(ClassifyError::BadShape { index: Some(index) }),
    };
    Ok((name, version))
}

fn vendor_from_service(name: &str) -> Option<Vendor> {
    if matches!(name, "claude-code" | "claude-code-desktop") {
        Some(Vendor::ClaudeCode)
    } else if name.starts_with("codex") {
        Some(Vendor::Codex)
    } else {
        None
    }
}

fn vendor_from_scope(name: &str) -> Option<Vendor> {
    if name.starts_with("com.anthropic.claude_code") {
        Some(Vendor::ClaudeCode)
    } else if name.starts_with("codex_otel") {
        Some(Vendor::Codex)
    } else {
        None
    }
}

fn classify_logs<'a>(
    values: &'a [Value],
    cat: Option<&'static Catalog>,
    export: Export,
    index: usize,
    record_count: &mut usize,
    unknown_count: &mut usize,
) -> Result<Vec<Record<'a>>, ClassifyError> {
    let mut records = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .as_object()
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        let raw_fields = object.get("attributes");
        let unclassified = raw_fields
            .map(|fields| parse_fields(fields, index))
            .transpose()?
            .unwrap_or_default();
        let event_name = unclassified
            .iter()
            .find(|(key, _)| key == "event.name")
            .and_then(|(_, value)| any_string(value));
        let body = object.get("body");
        let body_name = body.and_then(any_string);
        let body_is_record_name = body_name.is_some_and(|name| {
            safe_body_name(name)
                && (event_name
                    .is_some_and(|event| names_equal_with_vendor_prefix(name, event, cat))
                    || cat.is_some_and(|cat| cat.item(name, export).is_some()))
        });
        let fallback_name = event_name.unwrap_or_default();
        let name = if body_is_record_name {
            body_name.unwrap_or_default().to_owned()
        } else {
            normalize_event_name(fallback_name, cat, export)
        };
        let item = lookup_item(name.as_str(), cat, export);
        let fields = unclassified
            .into_iter()
            .map(|(key, value)| make_field(key, value, cat, item, export))
            .collect();
        if item.is_none() {
            *unknown_count += 1;
        }
        *record_count += 1;
        records.push(Record {
            name: Cow::Owned(name),
            kind: ItemKind::Event,
            item,
            family: None,
            parent: None,
            body,
            fields,
        });
    }
    Ok(records)
}

fn classify_metrics<'a>(
    values: &'a [Value],
    cat: Option<&'static Catalog>,
    export: Export,
    index: usize,
    record_count: &mut usize,
    unknown_count: &mut usize,
) -> Result<Vec<Record<'a>>, ClassifyError> {
    const FAMILIES: [&str; 5] = [
        "sum",
        "gauge",
        "histogram",
        "exponentialHistogram",
        "summary",
    ];
    let mut records = Vec::new();
    for metric in values {
        let object = metric
            .as_object()
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        let name: Cow<'a, str> = match object.get("name") {
            Some(Value::String(name)) => Cow::Borrowed(name.as_str()),
            None | Some(Value::Null) => Cow::Borrowed(""),
            _ => return Err(ClassifyError::BadShape { index: Some(index) }),
        };
        let item = lookup_item(&name, cat, export);
        let mut had_family = false;
        for family_name in FAMILIES {
            let Some(family_value) = object.get(family_name) else {
                continue;
            };
            had_family = true;
            let family = family_value
                .as_object()
                .ok_or(ClassifyError::BadShape { index: Some(index) })?;
            let Some(points) = family.get("dataPoints") else {
                continue;
            };
            let points = points
                .as_array()
                .ok_or(ClassifyError::BadShape { index: Some(index) })?;
            for point in points {
                let point = point
                    .as_object()
                    .ok_or(ClassifyError::BadShape { index: Some(index) })?;
                let raw_fields = point.get("attributes");
                let fields = raw_fields
                    .map(|fields| classify_fields(fields, cat, item, export, index))
                    .transpose()?
                    .unwrap_or_default();
                if item.is_none() {
                    *unknown_count += 1;
                }
                *record_count += 1;
                records.push(Record {
                    name: name.clone(),
                    kind: ItemKind::Metric,
                    item,
                    family: Some(family_name),
                    parent: None,
                    body: None,
                    fields,
                });
            }
        }
        if !had_family {
            if item.is_none() {
                *unknown_count += 1;
            }
            *record_count += 1;
            records.push(Record {
                name,
                kind: ItemKind::Metric,
                item,
                family: None,
                parent: None,
                body: None,
                fields: Vec::new(),
            });
        }
    }
    Ok(records)
}

fn classify_spans<'a>(
    values: &'a [Value],
    cat: Option<&'static Catalog>,
    export: Export,
    index: usize,
    record_count: &mut usize,
    unknown_count: &mut usize,
) -> Result<Vec<Record<'a>>, ClassifyError> {
    let mut records = Vec::new();
    for span in values {
        let span = span
            .as_object()
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        let name = string_member(span, "name", index)?.unwrap_or_default();
        let item = lookup_item(&name, cat, export);
        let fields = span
            .get("attributes")
            .map(|attrs| classify_fields(attrs, cat, item, export, index))
            .transpose()?
            .unwrap_or_default();
        if item.is_none() {
            *unknown_count += 1;
        }
        *record_count += 1;
        records.push(Record {
            name: name.clone(),
            kind: ItemKind::Span,
            item,
            family: None,
            parent: None,
            body: None,
            fields,
        });

        let events = match span.get("events") {
            None => &[][..],
            Some(events) => events
                .as_array()
                .ok_or(ClassifyError::BadShape { index: Some(index) })?
                .as_slice(),
        };
        for event in events {
            let event = event
                .as_object()
                .ok_or(ClassifyError::BadShape { index: Some(index) })?;
            let event_name = string_member(event, "name", index)?.unwrap_or_default();
            let item = lookup_item(&event_name, cat, export);
            let fields = event
                .get("attributes")
                .map(|attrs| classify_fields(attrs, cat, item, export, index))
                .transpose()?
                .unwrap_or_default();
            if item.is_none() {
                *unknown_count += 1;
            }
            *record_count += 1;
            records.push(Record {
                name: event_name,
                kind: ItemKind::SpanEvent,
                item,
                family: None,
                parent: Some(name.clone()),
                body: None,
                fields,
            });
        }
    }
    Ok(records)
}

fn string_member<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<Option<Cow<'a, str>>, ClassifyError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(Cow::Borrowed(value.as_str()))),
        _ => Err(ClassifyError::BadShape { index: Some(index) }),
    }
}

fn parse_fields(value: &Value, index: usize) -> Result<Vec<(String, &Value)>, ClassifyError> {
    let attributes = value
        .as_array()
        .ok_or(ClassifyError::BadShape { index: Some(index) })?;
    let mut fields = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        let attribute = attribute
            .as_object()
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        let key = attribute
            .get("key")
            .and_then(Value::as_str)
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        let value = attribute
            .get("value")
            .ok_or(ClassifyError::BadShape { index: Some(index) })?;
        fields.push((key.to_owned(), value));
    }
    Ok(fields)
}

fn classify_fields<'a>(
    value: &'a Value,
    cat: Option<&'static Catalog>,
    item: Option<&'static Item>,
    export: Export,
    index: usize,
) -> Result<Vec<Field<'a>>, ClassifyError> {
    let values = parse_fields(value, index)?;
    Ok(values
        .into_iter()
        .map(|(key, value)| make_field(key, value, cat, item, export))
        .collect())
}

fn make_field<'a>(
    key: String,
    value: &'a Value,
    cat: Option<&'static Catalog>,
    item: Option<&'static Item>,
    export: Export,
) -> Field<'a> {
    let attr = cat.and_then(|cat| cat.attr(item, &key, export));
    Field { key, attr, value }
}

fn lookup_item(name: &str, cat: Option<&'static Catalog>, export: Export) -> Option<&'static Item> {
    cat.and_then(|cat| cat.item(name, export))
}

fn normalize_event_name(name: &str, cat: Option<&'static Catalog>, export: Export) -> String {
    let Some(cat) = cat else {
        return name.to_owned();
    };
    if cat.item(name, export).is_some() {
        return name.to_owned();
    }
    let prefix = match cat.vendor {
        Vendor::ClaudeCode => "claude_code.",
        Vendor::Codex => "codex.",
    };
    let normalized = format!("{prefix}{name}");
    if cat.item(&normalized, export).is_some() {
        normalized
    } else {
        name.to_owned()
    }
}

fn names_equal_with_vendor_prefix(left: &str, right: &str, cat: Option<&Catalog>) -> bool {
    if left == right {
        return true;
    }
    let Some(cat) = cat else {
        return false;
    };
    let prefix = match cat.vendor {
        Vendor::ClaudeCode => "claude_code.",
        Vendor::Codex => "codex.",
    };
    left.strip_prefix(prefix) == Some(right) || right.strip_prefix(prefix) == Some(left)
}

fn safe_body_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
}

fn any_string(value: &Value) -> Option<&str> {
    value
        .get("stringValue")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
}

/// Returns a type-and-length description without including payload content.
pub fn mask(value: &Value) -> String {
    if let Some(value) = value.get("stringValue").and_then(Value::as_str) {
        return format!("<string, {} chars>", value.chars().count());
    }
    if value.get("intValue").is_some() {
        return "<int>".to_owned();
    }
    if value.get("doubleValue").is_some() {
        return "<double>".to_owned();
    }
    if value.get("boolValue").is_some() {
        return "<bool>".to_owned();
    }
    if let Some(values) = value
        .get("arrayValue")
        .and_then(|array| array.get("values"))
        .and_then(Value::as_array)
    {
        return format!("<array, {} items>", values.len());
    }
    if let Some(values) = value
        .get("kvlistValue")
        .and_then(|list| list.get("values"))
        .and_then(Value::as_array)
    {
        return format!("<kvlist, {} keys>", values.len());
    }
    if let Some(bytes) = value.get("bytesValue").and_then(Value::as_str) {
        return format!("<bytes, {} chars>", bytes.chars().count());
    }

    match value {
        Value::Null => "<empty>".to_owned(),
        Value::String(value) => format!("<string, {} chars>", value.chars().count()),
        Value::Number(number) if number.is_i64() || number.is_u64() => "<int>".to_owned(),
        Value::Number(_) => "<double>".to_owned(),
        Value::Bool(_) => "<bool>".to_owned(),
        Value::Array(values) => format!("<array, {} items>", values.len()),
        Value::Object(object) if object.is_empty() => "<empty>".to_owned(),
        Value::Object(object) => format!("<kvlist, {} keys>", object.len()),
    }
}

/// Extracts scalar strings and numbers recursively, stopping after 32 levels.
/// Paths are relative to the supplied AnyValue: `""`, `"[0]"`, or `".key"`.
pub fn text_of(value: &Value) -> Vec<(String, Cow<'_, str>)> {
    let mut found = Vec::new();
    text_of_inner(value, String::new(), 0, &mut found);
    found
}

fn text_of_inner<'a>(
    value: &'a Value,
    path: String,
    depth: usize,
    found: &mut Vec<(String, Cow<'a, str>)>,
) {
    if depth >= 32 {
        return;
    }
    if let Some(value) = value.get("stringValue").and_then(Value::as_str) {
        found.push((path, Cow::Borrowed(value)));
        return;
    }
    if let Some(value) = value.get("intValue") {
        push_scalar_text(value, path, found);
        return;
    }
    if let Some(value) = value.get("doubleValue") {
        push_scalar_text(value, path, found);
        return;
    }
    if let Some(values) = value
        .get("arrayValue")
        .and_then(|array| array.get("values"))
        .and_then(Value::as_array)
    {
        for (index, value) in values.iter().enumerate() {
            text_of_inner(value, format!("{path}[{index}]"), depth + 1, found);
        }
        return;
    }
    if let Some(values) = value
        .get("kvlistValue")
        .and_then(|list| list.get("values"))
        .and_then(Value::as_array)
    {
        for entry in values {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let (Some(key), Some(value)) =
                (entry.get("key").and_then(Value::as_str), entry.get("value"))
            else {
                continue;
            };
            text_of_inner(value, format!("{path}.{key}"), depth + 1, found);
        }
        return;
    }
    if let Some(value) = value.as_str() {
        found.push((path, Cow::Borrowed(value)));
        return;
    }
    match value {
        Value::Number(_) => push_scalar_text(value, path, found),
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                text_of_inner(value, format!("{path}[{index}]"), depth + 1, found);
            }
        }
        Value::Object(_) | Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn push_scalar_text<'a>(value: &'a Value, path: String, found: &mut Vec<(String, Cow<'a, str>)>) {
    match value {
        Value::String(value) => found.push((path, Cow::Borrowed(value))),
        Value::Number(value) => found.push((path, Cow::Owned(value.to_string()))),
        _ => {}
    }
}

/// Reduces a match to the requested short prefix and Unicode character count.
pub fn mask_match(value: &str) -> String {
    let count = value.chars().count();
    if count >= 8 {
        let prefix: String = value.chars().take(3).collect();
        format!("{prefix}…({count} chars)")
    } else {
        format!("…({count} chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_never_echoes_a_string_value() {
        let secret = "alice@example-corp.com";
        let value = serde_json::json!({ "stringValue": secret });
        let masked = mask(&value);
        assert_eq!(masked, "<string, 22 chars>");
        assert!(!masked.contains(secret));
    }

    #[test]
    fn log_body_is_used_only_when_it_is_a_safe_agreeing_name() {
        let doc = serde_json::json!({
            "resourceLogs": [{
                "resource": { "attributes": [
                    { "key": "service.name", "value": { "stringValue": "claude-code" } }
                ] },
                "scopeLogs": [{ "scope": { "name": "com.anthropic.claude_code.events" },
                    "logRecords": [
                        { "body": { "stringValue": "claude_code.api_request" }, "attributes": [
                            { "key": "event.name", "value": { "stringValue": "api_request" } }
                        ] },
                        { "body": { "stringValue": "private@example.com" }, "attributes": [
                            { "key": "event.name", "value": { "stringValue": "api_request" } }
                        ] },
                        { "body": { "stringValue": "claude_code.unknown" }, "attributes": [] }
                    ]
                }]
            }]
        });
        let classified = classify(Export::Logs, &doc).expect("valid OTLP logs");
        let records = &classified.resources[0].scopes[0].records;
        assert_eq!(records[0].name, "claude_code.api_request");
        assert_eq!(records[1].name, "claude_code.api_request");
        assert_eq!(records[2].name, "");
        assert_eq!(
            records[1].body.and_then(any_string),
            Some("private@example.com")
        );
    }

    #[test]
    fn classify_errors_contain_only_fixed_categories_and_indexes() {
        let error = classify(Export::Logs, &Value::Null).unwrap_err();
        assert_eq!(error, ClassifyError::NotObject);
        let error = classify(
            Export::Logs,
            &serde_json::json!({ "resourceLogs": ["secret"] }),
        )
        .unwrap_err();
        assert_eq!(error, ClassifyError::BadShape { index: Some(0) });
    }

    #[test]
    fn mask_and_text_helpers_cover_otlp_any_values() {
        let value = serde_json::json!({
            "kvlistValue": { "values": [
                { "key": "nested", "value": { "arrayValue": { "values": [
                    { "stringValue": "token" }, { "intValue": "12" }
                ] } } }
            ] }
        });
        assert_eq!(mask(&value), "<kvlist, 1 keys>");
        let texts = text_of(&value);
        assert_eq!(texts.len(), 2);
        assert_eq!(texts[0].0, ".nested[0]");
        assert_eq!(texts[0].1, "token");
        assert_eq!(texts[1].0, ".nested[1]");
        assert_eq!(texts[1].1, "12");
    }

    #[test]
    fn mask_match_uses_unicode_character_count() {
        assert_eq!(mask_match("abcdefgh"), "abc…(8 chars)");
        assert_eq!(mask_match("猫犬"), "…(2 chars)");
    }
}
