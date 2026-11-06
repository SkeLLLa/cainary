//! Routing, content checks and the OTLP/JSON pipeline (design §8.2, §14.2): from a request body
//! to the owned events the output thread prints. Pure: no I/O.
//!
//! Classification is `cainary_core::rules::otel_classify`; this module applies the output policy
//! (design §14.2) to everything it returns: names print verbatim only when they are catalog
//! entries or pass the name rule after a complete red-flag scan, values are masked.

use crate::http::Head;
use crate::output::{AlertEvent, BatchEvent, ErrorEvent, escape};
use crate::redflag::{Hit, Matcher, Scanner};
use cainary_core::rules::otel_catalog::{self, Export, Group, Item, ItemKind};
use cainary_core::rules::otel_classify::{self, Field};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

pub const MAX_RECORDS: usize = 10_000;
pub const MAX_ATTRS: usize = 20_000;
pub const MAX_ALERT_GROUPS: usize = 1024;
pub const MAX_EVENT_SAMPLES: usize = 8;
pub const MAX_IDENT: usize = 256;
/// A raw `--show-values` match is cut here; the limits of §14 still apply.
const MAX_RAW_MATCH: usize = 1024;
const MAX_DEPTH: usize = 32;
/// Text-mode output kept per batch, and per value (design §14.1: retained output is bounded).
const MAX_TEXT_BODY: usize = 256 << 10;
const MAX_TEXT_VALUE: usize = 512;
/// What the output thread adds in front of a batch's JSON tail.
const ENVELOPE_BYTES: usize = 256;

pub const PROTOBUF_MESSAGE: &str = "cainary-otel-debug reads OTLP/JSON only: set OTEL_EXPORTER_OTLP_PROTOCOL=http/json (Claude Code) or protocol = \"json\" in the otlp-http exporter (Codex)";
pub const COMPRESSED_MESSAGE: &str =
    "compressed bodies aren't supported; unset OTEL_EXPORTER_OTLP_COMPRESSION or set it to none";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Logs,
    Metrics,
    Traces,
}

impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Signal::Logs => "logs",
            Signal::Metrics => "metrics",
            Signal::Traces => "traces",
        }
    }
    pub fn path(self) -> &'static str {
        match self {
            Signal::Logs => "/v1/logs",
            Signal::Metrics => "/v1/metrics",
            Signal::Traces => "/v1/traces",
        }
    }
}

/// `/v1/logs` and friends, the only paths an error line may echo.
pub fn known_path(path: &str) -> Option<&'static str> {
    [Signal::Logs, Signal::Metrics, Signal::Traces]
        .into_iter()
        .map(Signal::path)
        .find(|p| *p == path)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Signal(Signal),
    NotFound,
    /// A known path with another method (OPTIONS included: there is no CORS).
    NotAllowed,
}

pub fn route(method: &str, path: &str) -> Route {
    let signal = match path {
        "/v1/logs" => Some(Signal::Logs),
        "/v1/metrics" => Some(Signal::Metrics),
        "/v1/traces" => Some(Signal::Traces),
        _ => None,
    };
    match (method, signal) {
        ("OPTIONS", _) => Route::NotAllowed,
        ("POST", Some(s)) => Route::Signal(s),
        (_, Some(_)) => Route::NotAllowed,
        (_, None) => Route::NotFound,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reject {
    pub status: u16,
    pub message: &'static str,
}

/// `Content-Type` must be `application/json` (parameters ignored); `Content-Encoding` absent
/// or `identity`.
pub fn check_content(head: &Head) -> Result<(), Reject> {
    let ct = head.header("content-type").unwrap_or("");
    let media = ct.split(';').next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("application/json") {
        return Err(Reject {
            status: 415,
            message: PROTOBUF_MESSAGE,
        });
    }
    let enc = head.header("content-encoding").unwrap_or("identity").trim();
    if !enc.eq_ignore_ascii_case("identity") {
        return Err(Reject {
            status: 415,
            message: COMPRESSED_MESSAGE,
        });
    }
    Ok(())
}

pub fn parse(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body)
        .map_err(|e| format!("invalid JSON (line {}, column {})", e.line(), e.column()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// 400
    Shape(Signal),
    /// 413
    TooMany,
    /// 413: the summary alone is over the output line cap.
    TooLarge,
}

impl Fail {
    pub fn status(&self) -> u16 {
        match self {
            Fail::Shape(_) => 400,
            Fail::TooMany | Fail::TooLarge => 413,
        }
    }
    pub fn message(&self) -> String {
        match self {
            Fail::Shape(s) => format!("not an OTLP {} document", s.name()),
            Fail::TooMany => "too many records or attributes in one request".to_string(),
            Fail::TooLarge => "too many distinct names for one output line".to_string(),
        }
    }
}

// ── caps before any allocation ───────────────────────────────────────────────────────────────

fn len_of(v: &Value, key: &str) -> usize {
    v.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

/// Counts records and attributes straight from the JSON, leniently (shape errors are the
/// classifier's to report), so an oversized request is refused before anything is built.
fn precount(signal: Signal, doc: &Value) -> Result<(), Fail> {
    let (root, scopes, items) = match signal {
        Signal::Logs => ("resourceLogs", "scopeLogs", "logRecords"),
        Signal::Metrics => ("resourceMetrics", "scopeMetrics", "metrics"),
        Signal::Traces => ("resourceSpans", "scopeSpans", "spans"),
    };
    let (mut records, mut attrs) = (0usize, 0usize);
    let over = |records: usize, attrs: usize| {
        if records > MAX_RECORDS || attrs > MAX_ATTRS {
            Err(Fail::TooMany)
        } else {
            Ok(())
        }
    };
    let empty = Vec::new();
    for r in doc.get(root).and_then(Value::as_array).unwrap_or(&empty) {
        attrs += r.get("resource").map_or(0, |x| len_of(x, "attributes"));
        for s in r.get(scopes).and_then(Value::as_array).unwrap_or(&empty) {
            for it in s.get(items).and_then(Value::as_array).unwrap_or(&empty) {
                match signal {
                    Signal::Logs => {
                        records += 1;
                        attrs += len_of(it, "attributes");
                    }
                    Signal::Traces => {
                        records += 1 + len_of(it, "events");
                        attrs += len_of(it, "attributes");
                        for e in it.get("events").and_then(Value::as_array).unwrap_or(&empty) {
                            attrs += len_of(e, "attributes");
                        }
                    }
                    Signal::Metrics => {
                        let mut any = false;
                        for fam in [
                            "sum",
                            "gauge",
                            "histogram",
                            "exponentialHistogram",
                            "summary",
                        ] {
                            let Some(f) = it.get(fam) else { continue };
                            any = true;
                            let points = f
                                .get("dataPoints")
                                .and_then(Value::as_array)
                                .unwrap_or(&empty);
                            records += points.len();
                            attrs += points
                                .iter()
                                .map(|p| len_of(p, "attributes"))
                                .sum::<usize>();
                            over(records, attrs)?;
                        }
                        records += usize::from(!any);
                    }
                }
                over(records, attrs)?;
            }
        }
    }
    over(records, attrs)
}

// ── masking helpers ──────────────────────────────────────────────────────────────────────────

/// `(type, len)` of an OTLP AnyValue, for the `F` objects.
fn any_type(v: &Value) -> (&'static str, Option<usize>) {
    let n = |k: &str| v.get(k);
    if let Some(s) = n("stringValue").and_then(Value::as_str) {
        ("string", Some(s.chars().count()))
    } else if n("intValue").is_some() {
        ("int", None)
    } else if n("doubleValue").is_some() {
        ("double", None)
    } else if n("boolValue").is_some() {
        ("bool", None)
    } else if let Some(a) = n("arrayValue") {
        ("array", Some(len_of(a, "values")))
    } else if let Some(k) = n("kvlistValue") {
        ("kvlist", Some(len_of(k, "values")))
    } else if let Some(b) = n("bytesValue").and_then(Value::as_str) {
        ("bytes", Some(b.chars().count()))
    } else {
        ("empty", None)
    }
}

/// The value as text, for `--show-values` only.
fn raw(v: &Value) -> String {
    for k in [
        "stringValue",
        "intValue",
        "doubleValue",
        "boolValue",
        "bytesValue",
    ] {
        match v.get(k) {
            Some(Value::String(s)) => return s.clone(),
            Some(other) => return other.to_string(),
            None => {}
        }
    }
    for k in ["arrayValue", "kvlistValue"] {
        if let Some(inner) = v.get(k) {
            return inner.to_string();
        }
    }
    String::new()
}

/// Whether an AnyValue nests deeper than `text_of` looks (it stops silently at 32).
fn too_deep(v: &Value, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return v.get("arrayValue").is_some() || v.get("kvlistValue").is_some();
    }
    let kids = |k: &str| {
        v.get(k)
            .and_then(|a| a.get("values"))
            .and_then(Value::as_array)
    };
    kids("arrayValue").is_some_and(|a| a.iter().any(|c| too_deep(c, depth + 1)))
        || kids("kvlistValue").is_some_and(|a| {
            a.iter()
                .any(|c| c.get("value").is_some_and(|c| too_deep(c, depth + 1)))
        })
}

fn group_str(g: Group) -> &'static str {
    match g {
        Group::Identity => "identity",
        Group::Resource => "resource",
        Group::Event => "event",
        Group::Content => "content",
    }
}

fn kind_str(k: ItemKind) -> &'static str {
    match k {
        ItemKind::Event => "event",
        ItemKind::Metric => "metric",
        ItemKind::Span => "span",
        ItemKind::SpanEvent => "span-event",
    }
}

// ── naming policy and alerts (design §14.2) ──────────────────────────────────────────────────

/// `^[A-Za-z0-9_.:/-]{1,128}$`
fn safe_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Label {
    Key,
    Name,
}

#[derive(Default)]
struct Namer {
    map: HashMap<(Label, String), String>,
    keys: usize,
    names: usize,
}

impl Namer {
    /// Verbatim when `known` (an exact catalog name) or safe and cleanly scanned; else a
    /// request-local label.
    fn name(&mut self, s: &str, kind: Label, known: bool, flagged: bool) -> String {
        if known || (safe_name(s) && !flagged) {
            return s.to_string();
        }
        let (n, word) = match kind {
            Label::Key => (&mut self.keys, "key"),
            Label::Name => (&mut self.names, "name"),
        };
        self.map
            .entry((kind, s.to_string()))
            .or_insert_with(|| {
                *n += 1;
                format!("<unknown-{word}-{n}>")
            })
            .clone()
    }
}

struct AlertGroup {
    pattern: usize,
    where_: &'static str,
    attribute: Option<String>,
    event: Option<String>,
    events: Vec<String>,
    count: u64,
    matched: String,
}

pub struct Ctx {
    pub matcher: Arc<Matcher>,
    pub show_values: bool,
}

struct Proc<'m> {
    scanner: Scanner<'m>,
    namer: Namer,
    groups: Vec<AlertGroup>,
    index: HashMap<(usize, Option<String>, &'static str), usize>,
    show: bool,
    hits: Vec<Hit>,
    /// Record names sanitized once per distinct raw slice: the points of one metric, and the
    /// events of one span, share one name.
    name_cache: HashMap<(usize, usize), String>,
}

/// Appends within the text budget; once it is spent, one marker and nothing more.
fn push_capped(text: &mut String, add: &str) {
    const MARK: &str = "… (output truncated)\n";
    if text.len() + add.len() + MARK.len() <= MAX_TEXT_BODY {
        text.push_str(add);
    } else if !text.ends_with(MARK) {
        text.push_str(MARK);
    }
}

fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

impl<'m> Proc<'m> {
    fn new(ctx: &'m Ctx) -> Proc<'m> {
        Proc {
            scanner: ctx.matcher.scanner(),
            namer: Namer::default(),
            groups: Vec::new(),
            index: HashMap::new(),
            show: ctx.show_values,
            hits: Vec::new(),
            name_cache: HashMap::new(),
        }
    }

    fn record(
        &mut self,
        text: &str,
        hits: &[Hit],
        where_: &'static str,
        attribute: Option<&str>,
        event: Option<&str>,
    ) {
        for h in hits {
            let key = (h.pattern, attribute.map(str::to_string), where_);
            let slot = match self.index.get(&key) {
                Some(i) => *i,
                None => {
                    if self.groups.len() >= MAX_ALERT_GROUPS {
                        self.scanner.incomplete = true;
                        continue;
                    }
                    let matched = &text[h.start..h.end];
                    self.groups.push(AlertGroup {
                        pattern: h.pattern,
                        where_,
                        attribute: attribute.map(|a| cut(a, MAX_IDENT)),
                        event: event.map(|e| cut(e, MAX_IDENT)),
                        events: Vec::new(),
                        count: 0,
                        matched: if self.show {
                            cut(matched, MAX_RAW_MATCH)
                        } else {
                            otel_classify::mask_match(matched)
                        },
                    });
                    self.index.insert(key, self.groups.len() - 1);
                    self.groups.len() - 1
                }
            };
            let g = &mut self.groups[slot];
            g.count += 1;
            if let Some(e) = event
                && g.events.len() < MAX_EVENT_SAMPLES
                && !g.events.iter().any(|x| x == e)
            {
                g.events.push(cut(e, MAX_IDENT));
            }
        }
    }

    /// Scans a name-like string and returns its displayed form.
    fn scan_name(
        &mut self,
        s: &str,
        kind: Label,
        known: bool,
        where_: &'static str,
        attribute: Option<&str>,
        event: Option<&str>,
    ) -> String {
        if s.is_empty() {
            return "<empty>".to_string();
        }
        let mut hits = std::mem::take(&mut self.hits);
        hits.clear();
        let complete = self.scanner.scan(s, &mut hits);
        // Verbatim only after a complete, negative scan (design §14.2).
        let shown = self
            .namer
            .name(s, kind, known, !hits.is_empty() || !complete);
        // An alert names a flagged key by its label, never by the key itself.
        let attr = if where_ == "key" || where_ == "resource" {
            Some(shown.as_str())
        } else {
            attribute
        };
        self.record(s, &hits, where_, attr, event);
        self.hits = hits;
        shown
    }

    /// A name's displayed form without raising alerts (the caller already scanned it elsewhere).
    fn shown(&mut self, s: &str, kind: Label, known: bool) -> String {
        if s.is_empty() {
            return "<empty>".to_string();
        }
        let mut hits = std::mem::take(&mut self.hits);
        hits.clear();
        let complete = self.scanner.scan(s, &mut hits);
        let shown = self
            .namer
            .name(s, kind, known, !hits.is_empty() || !complete);
        self.hits = hits;
        shown
    }

    /// A record or span name, scanned and sanitized once per raw slice.
    fn record_name(&mut self, raw: &str, known: bool) -> String {
        let slice = (raw.as_ptr() as usize, raw.len());
        if let Some(n) = self.name_cache.get(&slice) {
            return n.clone();
        }
        let n = if raw.is_empty() {
            "(unnamed)".to_string()
        } else {
            self.scan_name(raw, Label::Name, known, "name", None, None)
        };
        self.name_cache.insert(slice, n.clone());
        n
    }

    fn scan_value(
        &mut self,
        v: &Value,
        where_: &'static str,
        attribute: Option<&str>,
        event: Option<&str>,
    ) {
        if self.scanner.is_empty() {
            return;
        }
        if too_deep(v, 0) {
            self.scanner.incomplete = true;
        }
        let mut hits = std::mem::take(&mut self.hits);
        for (path, text) in otel_classify::text_of(v) {
            hits.clear();
            self.scanner.scan(&text, &mut hits);
            self.record(&text, &hits, where_, attribute, event);
            // A nested key is part of the path.
            if let Some(key) = path.rsplit_once('.').map(|(_, k)| k)
                && !key.is_empty()
            {
                hits.clear();
                self.scanner.scan(key, &mut hits);
                self.record(key, &hits, where_, attribute, event);
            }
        }
        self.hits = hits;
    }

    fn display(&self, v: &Value) -> String {
        if self.show {
            raw(v)
        } else {
            otel_classify::mask(v)
        }
    }

    fn text_value(&self, v: &Value) -> String {
        escape(&cut(&self.display(v), MAX_TEXT_VALUE))
    }

    /// The `F` object of design §8.6.
    fn field(&self, label: &str, f: &Field<'_>) -> Value {
        let (ty, len) = any_type(f.value);
        let mut m = Map::new();
        m.insert("key".into(), json!(label));
        m.insert("group".into(), json!(f.attr.map(|a| group_str(a.group))));
        if let Some(flag) = f.attr.and_then(|a| a.gate).map(|g| g.flag) {
            m.insert("flag".into(), json!(flag));
        }
        m.insert("known".into(), json!(f.attr.is_some()));
        m.insert("type".into(), json!(ty));
        if let Some(n) = len {
            m.insert("len".into(), json!(n));
        }
        m.insert("value".into(), json!(self.display(f.value)));
        Value::Object(m)
    }

    /// The displayed key of a field: verbatim for an exact catalog key (a wildcard entry such
    /// as `vcs.ref.head.*` matches attacker-chosen suffixes, so those take the name rule).
    fn key_label(&mut self, f: &Field<'_>, where_: &'static str, event: Option<&str>) -> String {
        let exact = f.attr.is_some_and(|a| a.key == f.key);
        self.scan_name(&f.key, Label::Key, exact, where_, None, event)
    }
}

pub struct Prepared {
    pub batch: BatchEvent,
    pub extra: Vec<ErrorEvent>,
}

/// What the text block keeps of a record name's first occurrence.
struct Shown {
    key: String,
    group: Option<Group>,
    flag: Option<&'static str>,
    known: bool,
    text: String,
}

type SummaryAttr = (String, Option<Group>, Option<&'static str>, bool);

struct Entry {
    name: String,
    kind: ItemKind,
    known: bool,
    what: Option<&'static str>,
    count: usize,
    attrs: Vec<SummaryAttr>,
    seen: HashSet<String>,
    first: Vec<Shown>,
}

pub fn process(signal: Signal, bytes: usize, doc: &Value, ctx: &Ctx) -> Result<Prepared, Fail> {
    precount(signal, doc)?;
    let export = match signal {
        Signal::Logs => Export::Logs,
        Signal::Metrics => Export::Metrics,
        Signal::Traces => Export::Traces,
    };
    let c = otel_classify::classify(export, doc).map_err(|_| Fail::Shape(signal))?;
    let mut p = Proc::new(ctx);

    let service = c.service.as_ref().map(|(n, v)| {
        (
            p.shown(n, Label::Name, false),
            v.as_deref().map(|v| p.shown(v, Label::Name, false)),
        )
    });
    let vendor = c.vendor.map(|v| otel_catalog::catalog(v).product);
    let catalog = c.vendor.map(|v| otel_catalog::catalog(v).label());

    let mut resource_json = Vec::new();
    let mut identity: BTreeSet<String> = BTreeSet::new();
    let mut resource_keys: BTreeSet<String> = BTreeSet::new();
    let mut resource_line: Vec<String> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut entry_index: HashMap<(String, &'static str), usize> = HashMap::new();

    for res in &c.resources {
        let mut attrs = Vec::new();
        for f in &res.attrs {
            let label = p.key_label(f, "resource", None);
            p.scan_value(f.value, "resource", Some(&label), None);
            attrs.push(p.field(&label, f));
            match f.attr.map(|a| a.group) {
                Some(Group::Identity) => {
                    identity.insert(label.clone());
                }
                _ => {
                    resource_keys.insert(label.clone());
                }
            }
            if resource_line.len() < 32 {
                resource_line.push(format!("{} {}", escape(&label), p.text_value(f.value)));
            }
        }

        let mut scopes_json = Vec::new();
        for sc in &res.scopes {
            let scope_name = p.scan_name(&sc.name, Label::Name, false, "scope", None, None);
            let version = sc
                .version
                .as_deref()
                .map(|v| p.scan_name(v, Label::Name, false, "scope", None, None));
            let mut recs_json = Vec::new();
            for r in &sc.records {
                let known_name = r.item.is_some_and(|i| i.name == &*r.name);
                let name = p.record_name(&r.name, known_name);
                if let Some(b) = r.body {
                    p.scan_value(b, "body", None, Some(&name));
                }
                let mut fields = Vec::with_capacity(r.fields.len());
                let mut shown_fields: Vec<(String, &Field<'_>)> =
                    Vec::with_capacity(r.fields.len());
                for f in &r.fields {
                    let label = p.key_label(f, "key", Some(&name));
                    p.scan_value(f.value, "value", Some(&label), Some(&name));
                    fields.push(p.field(&label, f));
                    match f.attr.map(|a| a.group) {
                        Some(Group::Identity) => {
                            identity.insert(label.clone());
                        }
                        Some(Group::Resource) => {
                            resource_keys.insert(label.clone());
                        }
                        _ => {}
                    }
                    shown_fields.push((label, f));
                }

                let idx = match entry_index.get(&(name.clone(), kind_str(r.kind))) {
                    Some(i) => *i,
                    None => {
                        entries.push(Entry {
                            name: name.clone(),
                            kind: r.kind,
                            known: r.item.is_some(),
                            what: r.item.map(|i: &Item| i.what),
                            count: 0,
                            attrs: Vec::new(),
                            seen: HashSet::new(),
                            first: shown_fields
                                .iter()
                                .take(32)
                                .map(|(label, f)| Shown {
                                    key: label.clone(),
                                    group: f.attr.map(|a| a.group),
                                    flag: f.attr.and_then(|a| a.gate).map(|g| g.flag),
                                    known: f.attr.is_some(),
                                    text: p.text_value(f.value),
                                })
                                .collect(),
                        });
                        entry_index.insert((name.clone(), kind_str(r.kind)), entries.len() - 1);
                        entries.len() - 1
                    }
                };
                let e = &mut entries[idx];
                e.count += 1;
                e.known &= r.item.is_some();
                for (label, f) in &shown_fields {
                    if e.seen.insert(label.clone()) {
                        e.attrs.push((
                            label.clone(),
                            f.attr.map(|a| a.group),
                            f.attr.and_then(|a| a.gate).map(|g| g.flag),
                            f.attr.is_some(),
                        ));
                    }
                }

                let mut rec = Map::new();
                rec.insert("name".into(), json!(name));
                rec.insert("kind".into(), json!(kind_str(r.kind)));
                rec.insert("known".into(), json!(r.item.is_some()));
                if r.kind == ItemKind::Metric {
                    if let Some(u) = r.item.and_then(|i| i.unit) {
                        rec.insert("unit".into(), json!(u));
                    }
                    if let Some(f) = r.family {
                        rec.insert("metricType".into(), json!(f));
                    }
                }
                if let Some(parent) = r.parent.as_deref() {
                    let parent = p.record_name(parent, false);
                    rec.insert("span".into(), json!(parent));
                }
                rec.insert("attrs".into(), Value::Array(fields));
                recs_json.push(Value::Object(rec));
            }
            scopes_json.push(json!({"name": scope_name, "version": version, "records": recs_json}));
        }
        resource_json.push(json!({"attrs": attrs, "scopes": scopes_json}));
    }

    // Text block.
    let mut text_body = String::new();
    if !resource_line.is_empty() {
        push_capped(
            &mut text_body,
            &format!("resource   {}\n", resource_line.join(" · ")),
        );
    }
    if !identity.is_empty() {
        let ids: Vec<String> = identity.iter().take(32).map(|k| escape(k)).collect();
        push_capped(
            &mut text_body,
            &format!("identity   {} (on every record)\n", ids.join(" · ")),
        );
    }
    for e in &entries {
        let what = e.what.map(|w| format!("   {w}")).unwrap_or_default();
        let flag = if e.known { "" } else { "   NOT IN CATALOG" };
        push_capped(
            &mut text_body,
            &format!("{} ×{}{what}{flag}\n", escape(&e.name), e.count),
        );
        let line = |pred: &dyn Fn(&Shown) -> bool, with_flag: bool| -> String {
            e.first
                .iter()
                .filter(|s| s.group != Some(Group::Identity) && s.group != Some(Group::Resource))
                .filter(|s| pred(s))
                .map(|s| match (with_flag, s.flag) {
                    (true, Some(f)) => format!("{} {} ({f})", escape(&s.key), s.text),
                    _ => format!("{} {}", escape(&s.key), s.text),
                })
                .collect::<Vec<_>>()
                .join(" · ")
        };
        let event = line(&|s| s.known && s.group != Some(Group::Content), false);
        if !event.is_empty() {
            push_capped(&mut text_body, &format!("  event    {event}\n"));
        }
        let content = line(&|s| s.known && s.group == Some(Group::Content), true);
        if !content.is_empty() {
            push_capped(&mut text_body, &format!("  content  {content}\n"));
        }
        let unknown = line(&|s| !s.known, false);
        if !unknown.is_empty() {
            push_capped(&mut text_body, &format!("  NOT IN CATALOG  {unknown}\n"));
        }
    }

    let summary = json!({
        "identity": identity,
        "resource": resource_keys,
        "records": entries.iter().map(|e| {
            let mut m = Map::new();
            m.insert("name".into(), json!(e.name));
            m.insert("kind".into(), json!(kind_str(e.kind)));
            m.insert("count".into(), json!(e.count));
            m.insert("known".into(), json!(e.known));
            if let Some(w) = e.what {
                m.insert("what".into(), json!(w));
            }
            m.insert("attrs".into(), Value::Array(e.attrs.iter().map(|(k, g, f, known)| {
                let mut a = Map::new();
                a.insert("key".into(), json!(k));
                a.insert("group".into(), json!(g.map(group_str)));
                if let Some(f) = f {
                    a.insert("flag".into(), json!(f));
                }
                a.insert("known".into(), json!(known));
                Value::Object(a)
            }).collect()));
            Value::Object(m)
        }).collect::<Vec<_>>(),
    });

    let mut alerts = Vec::new();
    for g in &p.groups {
        let pat = &p.scanner.patterns()[g.pattern];
        let mut m = Map::new();
        m.insert("pattern".into(), json!(pat.name));
        m.insert("preset".into(), json!(pat.preset));
        m.insert("signal".into(), json!(signal.name()));
        m.insert("event".into(), json!(g.event));
        m.insert("events".into(), json!(g.events));
        m.insert("attribute".into(), json!(g.attribute));
        m.insert("where".into(), json!(g.where_));
        m.insert("count".into(), json!(g.count));
        m.insert("match".into(), json!(g.matched));
        let text = format!(
            "⚠ red flag {}: {} · {} (×{}): {}",
            escape(&pat.name),
            escape(g.event.as_deref().unwrap_or(g.where_)),
            escape(g.attribute.as_deref().unwrap_or("-")),
            g.count,
            escape(&g.matched),
        );
        alerts.push(AlertEvent {
            tail: Value::Object(m).to_string(),
            text,
        });
    }

    let resources_value = Value::Array(resource_json);
    let resources_text = resources_value.to_string();
    let summary_text = summary.to_string();
    let omit = resources_text.len() + summary_text.len() + 2048 + ENVELOPE_BYTES
        > crate::output::MAX_LINE_BYTES;

    let service_json = service
        .as_ref()
        .map(|(n, v)| json!({"name": n, "version": v}))
        .unwrap_or(Value::Null);
    let mut m = Map::new();
    m.insert("signal".into(), json!(signal.name()));
    m.insert("path".into(), json!(signal.path()));
    m.insert("bytes".into(), json!(bytes));
    m.insert("vendor".into(), json!(vendor));
    m.insert("service".into(), service_json);
    m.insert("catalog".into(), json!(catalog));
    m.insert("records".into(), json!(c.records));
    m.insert("notInCatalog".into(), json!(c.unknown));
    m.insert("summary".into(), summary);
    if omit {
        m.insert("resourcesOmitted".into(), json!(true));
    } else {
        m.insert("resources".into(), resources_value);
    }
    let incomplete = p.scanner.incomplete;
    if incomplete {
        m.insert("scanIncomplete".into(), json!(true));
    }
    let tail = Value::Object(m).to_string();
    // The summary always stays, so if it alone can't fit one line the batch can't be shown.
    if tail.len() + ENVELOPE_BYTES > crate::output::MAX_LINE_BYTES {
        return Err(Fail::TooLarge);
    }
    let header = format!(
        "{} · {} · {} records",
        signal.name(),
        catalog.as_deref().unwrap_or("unknown vendor"),
        c.records
    );
    let extra = if incomplete {
        vec![ErrorEvent::other(
            "red-flags",
            "red-flag matching stopped early: a size or time budget was reached, so some values were not scanned",
        )]
    } else {
        Vec::new()
    };
    Ok(Prepared {
        batch: BatchEvent {
            tail,
            text_header: header,
            text_body,
            alerts,
        },
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redflag::{Kind, Pattern, presets};

    fn ctx(show: bool) -> Ctx {
        let pats = presets::PRESETS
            .iter()
            .filter(|p| p.default_on)
            .map(presets::Preset::pattern)
            .collect();
        Ctx {
            matcher: Arc::new(Matcher::new(pats).unwrap()),
            show_values: show,
        }
    }

    fn sv(s: &str) -> Value {
        json!({"stringValue": s})
    }

    fn attr(k: &str, v: Value) -> Value {
        json!({"key": k, "value": v})
    }

    fn logs(res_attrs: Vec<Value>, scope: Value, records: Vec<Value>) -> Value {
        json!({"resourceLogs": [{"resource": {"attributes": res_attrs},
            "scopeLogs": [{"scope": scope, "logRecords": records}]}]})
    }

    #[test]
    fn routes() {
        assert_eq!(route("POST", "/v1/logs"), Route::Signal(Signal::Logs));
        assert_eq!(route("POST", "/v1/metrics"), Route::Signal(Signal::Metrics));
        assert_eq!(route("POST", "/v1/traces"), Route::Signal(Signal::Traces));
        assert_eq!(route("GET", "/v1/logs"), Route::NotAllowed);
        assert_eq!(route("OPTIONS", "/v1/logs"), Route::NotAllowed);
        assert_eq!(route("OPTIONS", "/x"), Route::NotAllowed);
        assert_eq!(route("POST", "/x"), Route::NotFound);
        assert_eq!(route("POST", "/v1/logs/"), Route::NotFound);
        assert_eq!(known_path("/v1/logs"), Some("/v1/logs"));
        assert_eq!(known_path("/secret"), None);
    }

    fn head(headers: &[(&str, &str)]) -> Head {
        Head {
            method: "POST".into(),
            target: "/v1/logs".into(),
            minor: 1,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn content_checks() {
        assert_eq!(
            check_content(&head(&[("content-type", "application/json")])),
            Ok(())
        );
        assert_eq!(
            check_content(&head(&[(
                "content-type",
                "Application/JSON; charset=utf-8"
            )])),
            Ok(())
        );
        assert_eq!(
            check_content(&head(&[
                ("content-type", "application/json"),
                ("content-encoding", "identity")
            ])),
            Ok(())
        );
        for ct in ["application/x-protobuf", "", "text/plain"] {
            let e = check_content(&head(&[("content-type", ct)])).unwrap_err();
            assert_eq!((e.status, e.message), (415, PROTOBUF_MESSAGE));
        }
        assert!(PROTOBUF_MESSAGE.contains("OTEL_EXPORTER_OTLP_PROTOCOL"));
        let e = check_content(&head(&[
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        ]))
        .unwrap_err();
        assert_eq!((e.status, e.message), (415, COMPRESSED_MESSAGE));
    }

    fn run(doc: &Value, show: bool) -> (Value, Vec<Value>, Prepared) {
        let c = ctx(show);
        let p = process(Signal::Logs, 100, doc, &c).unwrap();
        let batch: Value = serde_json::from_str(&p.batch.tail).unwrap();
        let alerts = p
            .batch
            .alerts
            .iter()
            .map(|a| serde_json::from_str(&a.tail).unwrap())
            .collect();
        (batch, alerts, p)
    }

    #[test]
    fn secrets_are_masked_and_alerted() {
        let doc = logs(
            vec![
                attr("service.name", sv("claude-code")),
                attr("service.version", sv("2.1.316")),
            ],
            json!({"name": "com.anthropic.claude_code.events", "version": "2.1.316"}),
            vec![
                json!({"body": sv("claude_code.tool_result"), "attributes": [
                    attr("event.name", sv("tool_result")),
                    attr("user.email", sv("alice@example-corp.com")),
                    attr("tool_input", sv("export K=AKIAIOSFODNN7EXAMPLE")),
                ]}),
            ],
        );
        let (batch, alerts, p) = run(&doc, false);
        let all = format!(
            "{}{}{}",
            p.batch.tail,
            p.batch.text_body,
            alerts.iter().map(|a| a.to_string()).collect::<String>()
        );
        assert!(!all.contains("alice@example-corp.com") && !all.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(batch["vendor"], "claude-code");
        assert_eq!(
            batch["service"],
            json!({"name": "claude-code", "version": "2.1.316"})
        );
        assert_eq!(batch["records"], 1);
        let by = |name: &str| {
            alerts
                .iter()
                .find(|a| a["pattern"] == name)
                .unwrap()
                .clone()
        };
        assert_eq!(by("email")["match"], "ali…(22 chars)");
        assert_eq!(by("email")["attribute"], "user.email");
        assert_eq!(by("email")["where"], "value");
        assert_eq!(by("email")["event"], "claude_code.tool_result");
        assert_eq!(by("aws-access-key")["match"], "AKI…(20 chars)");
        assert_eq!(by("aws-access-key")["attribute"], "tool_input");

        let (batch, alerts, _) = run(&doc, true);
        let all = batch.to_string() + &alerts.iter().map(|a| a.to_string()).collect::<String>();
        assert!(all.contains("alice@example-corp.com") && all.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn a_secret_in_every_string_position_never_appears() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let doc = json!({"resourceLogs": [{"resource": {"attributes": [
                attr(secret, sv("v")), attr("service.name", sv(secret)), attr("service.version", sv(secret))]},
            "scopeLogs": [{"scope": {"name": secret, "version": secret},
              "logRecords": [{"body": sv(secret), "attributes": [
                  attr(secret, sv(secret)),
                  attr("event.name", sv(secret)),
                  attr("nested", json!({"kvlistValue": {"values": [{"key": secret, "value": sv(secret)}]}})),
                  attr("arr", json!({"arrayValue": {"values": [sv(secret)]}}))]}]}]}]});
        let (batch, alerts, p) = run(&doc, false);
        let all = format!(
            "{}\n{}\n{}\n{}",
            p.batch.tail,
            p.batch.text_header,
            p.batch.text_body,
            alerts
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(!all.contains(secret), "{all}");
        assert!(!alerts.is_empty());
        assert!(all.contains("<unknown-key-1>") || all.contains("<unknown-name-1>"));
        let _ = batch;
    }

    #[test]
    fn names_follow_the_policy() {
        // A name that isn't flagged and is plain stays; an odd one is labelled, same label twice.
        let doc = logs(
            vec![],
            json!({"name": "scope with spaces"}),
            vec![
                json!({"attributes": [attr("tool_name", sv("x")), attr("a key", sv("x")), attr("a key", sv("y"))]}),
            ],
        );
        let (batch, _, _) = run(&doc, false);
        let attrs = &batch["resources"][0]["scopes"][0]["records"][0]["attrs"];
        assert_eq!(attrs[0]["key"], "tool_name");
        assert_eq!(attrs[1]["key"], "<unknown-key-1>");
        assert_eq!(attrs[2]["key"], "<unknown-key-1>");
        assert_eq!(
            batch["resources"][0]["scopes"][0]["name"],
            "<unknown-name-1>"
        );
    }

    #[test]
    fn terminal_escapes_in_show_values_text() {
        let osc = "x\u{1b}]52;c;c2VjcmV0\u{7}y";
        let doc = logs(
            vec![attr("k", sv(osc))],
            json!({"name": "s"}),
            vec![json!({})],
        );
        let (_, _, p) = run(&doc, true);
        assert!(!p.batch.text_body.contains('\u{1b}') && !p.batch.text_body.contains('\u{7}'));
        assert!(p.batch.text_body.contains("\\u{1b}]52"));
    }

    #[test]
    fn alerts_aggregate_per_group() {
        let recs: Vec<Value> = (0..20)
            .map(|i| json!({"attributes": [attr("event.name", sv(&format!("e{i}"))), attr("m", sv("bob@example-corp.com"))]}))
            .collect();
        let (_, alerts, _) = run(&logs(vec![], json!({"name": "s"}), recs), false);
        let email: Vec<_> = alerts.iter().filter(|a| a["pattern"] == "email").collect();
        assert_eq!(email.len(), 1);
        assert_eq!(email[0]["count"], 20);
        assert_eq!(
            email[0]["events"].as_array().unwrap().len(),
            MAX_EVENT_SAMPLES
        );
    }

    #[test]
    fn custom_patterns_and_where_values() {
        let c = Ctx {
            matcher: Arc::new(
                Matcher::new(vec![Pattern {
                    name: "customer".into(),
                    kind: Kind::Text,
                    pattern: "acme".into(),
                    case_sensitive: false,
                    preset: false,
                }])
                .unwrap(),
            ),
            show_values: false,
        };
        let doc = json!({"resourceMetrics": [{"resource": {"attributes": [attr("host", sv("ACME-1"))]},
            "scopeMetrics": [{"scope": {"name": "acme.meter"}, "metrics": [
              {"name": "acme_count", "sum": {"dataPoints": [{"attributes": [attr("acmekey", sv("v"))]}]}}]}]}]});
        let p = process(Signal::Metrics, 1, &doc, &c).unwrap();
        let wheres: Vec<String> = p
            .batch
            .alerts
            .iter()
            .map(|a| {
                serde_json::from_str::<Value>(&a.tail).unwrap()["where"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        for w in ["resource", "scope", "name", "key"] {
            assert!(wheres.iter().any(|x| x == w), "{w}: {wheres:?}");
        }
    }

    #[test]
    fn shape_errors_are_fixed_messages() {
        let c = ctx(false);
        for (sig, doc) in [
            (Signal::Logs, json!([])),
            (Signal::Logs, json!({})),
            (Signal::Logs, json!({"resourceMetrics": []})),
            (Signal::Logs, json!({"resourceLogs": "SECRET"})),
            (
                Signal::Logs,
                json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [{"attributes": [{"nokey": "SECRET"}]}]}]}]}),
            ),
            (Signal::Metrics, json!({"resourceMetrics": ["SECRET"]})),
        ] {
            let e = process(sig, 1, &doc, &c).err().unwrap();
            assert_eq!(e.status(), 400);
            assert!(!e.message().contains("SECRET"));
            assert!(e.message().starts_with("not an OTLP"));
        }
        assert_eq!(
            parse(b"{\"a\": SECRET").unwrap_err(),
            "invalid JSON (line 1, column 7)"
        );
        assert!(!parse(b"SECRET").unwrap_err().contains("SECRET"));
    }

    #[test]
    fn caps_on_records_and_attributes() {
        let c = ctx(false);
        let recs: Vec<Value> = (0..MAX_RECORDS + 1).map(|_| json!({})).collect();
        let e = process(Signal::Logs, 1, &logs(vec![], json!({}), recs), &c)
            .err()
            .unwrap();
        assert_eq!(e, Fail::TooMany);
        assert_eq!(e.status(), 413);
        let many: Vec<Value> = (0..MAX_ATTRS + 1)
            .map(|i| attr(&format!("k{i}"), sv("v")))
            .collect();
        let e = process(Signal::Logs, 1, &logs(many, json!({}), vec![]), &c)
            .err()
            .unwrap();
        assert_eq!(e, Fail::TooMany);
        let ok: Vec<Value> = (0..MAX_RECORDS).map(|_| json!({})).collect();
        assert!(process(Signal::Logs, 1, &logs(vec![], json!({}), ok), &c).is_ok());
    }

    #[test]
    fn metric_points_and_span_events_each_count() {
        let c = ctx(false);
        let doc = json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
            {"name": "m", "gauge": {"dataPoints": [{}, {}]}},
            {"name": "h", "histogram": {"dataPoints": [{}]}}]}]}]});
        let p = process(Signal::Metrics, 1, &doc, &c).unwrap();
        assert!(p.batch.tail.contains("\"records\":3"));
        let doc = json!({"resourceSpans": [{"scopeSpans": [{"spans": [
            {"name": "s", "events": [{"name": "e"}]}]}]}]});
        let p = process(Signal::Traces, 1, &doc, &c).unwrap();
        assert!(p.batch.tail.contains("\"records\":2"));
        assert!(p.batch.tail.contains("span-event"));
    }

    #[test]
    fn oversized_resources_are_omitted_but_the_summary_stays() {
        let c = ctx(false);
        let attrs: Vec<Value> = (0..9000)
            .map(|i| attr(&format!("k{i}"), sv(&"v".repeat(50))))
            .collect();
        let recs: Vec<Value> = (0..100)
            .map(|_| json!({"attributes": attrs.iter().take(150).cloned().collect::<Vec<_>>()}))
            .collect();
        let p = process(Signal::Logs, 1, &logs(vec![], json!({}), recs), &c).unwrap();
        let v: Value = serde_json::from_str(&p.batch.tail).unwrap();
        assert_eq!(v["resourcesOmitted"], true);
        assert!(v.get("resources").is_none());
        assert!(v["summary"]["records"].is_array());
    }

    #[test]
    fn scan_budget_marks_the_batch_incomplete() {
        let c = ctx(false);
        let big = "a".repeat(crate::redflag::MAX_LEAF_BYTES + 10);
        let doc = logs(
            vec![],
            json!({}),
            vec![json!({"attributes": [attr("k", sv(&big))]})],
        );
        let p = process(Signal::Logs, 1, &doc, &c).unwrap();
        assert!(p.batch.tail.contains("\"scanIncomplete\":true"));
        assert_eq!(p.extra.len(), 1);
        assert!(p.extra[0].tail.contains("red-flags"));
    }

    fn secret_ctx() -> Ctx {
        let p = Pattern {
            name: "secret".into(),
            kind: Kind::Text,
            pattern: "SECRET-TOKEN".into(),
            case_sensitive: true,
            preset: false,
        };
        Ctx {
            matcher: Arc::new(Matcher::new(vec![p]).unwrap()),
            show_values: false,
        }
    }

    #[test]
    fn a_huge_metric_name_is_sanitized_once_not_per_point() {
        let c = ctx(false);
        let name = "n".repeat(6 << 20);
        let points: Vec<Value> = (0..MAX_RECORDS).map(|_| json!({})).collect();
        let doc = json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
            {"name": name, "sum": {"dataPoints": points}}]}]}]});
        let p = process(Signal::Metrics, 1, &doc, &c).unwrap();
        assert!(p.batch.tail.len() < 1 << 20, "{}", p.batch.tail.len());
        assert!(!p.batch.tail.contains("nnnnnnnn"));
        assert!(p.batch.tail.contains("<unknown-name-1>"));
        assert!(p.batch.tail.contains("\"records\":10000"));
    }

    #[test]
    fn an_exhausted_budget_never_lets_a_name_through_unscanned() {
        let c = secret_ctx();
        let pad = "p".repeat(crate::redflag::MAX_LEAF_BYTES);
        let attrs: Vec<Value> = (0..20)
            .map(|i| attr(&format!("pad{i}"), sv(&pad)))
            .collect();
        let doc = logs(
            attrs,
            json!({"name": "SECRET-TOKEN", "version": "SECRET-TOKEN"}),
            vec![json!({"attributes": [attr("SECRET-TOKEN", sv("v"))]})],
        );
        let p = process(Signal::Logs, 1, &doc, &c).unwrap();
        let all = format!(
            "{}{}{}",
            p.batch.tail, p.batch.text_header, p.batch.text_body
        );
        assert!(!all.contains("SECRET-TOKEN"), "{all}");
        assert!(p.batch.tail.contains("scanIncomplete"));
    }

    #[test]
    fn a_summary_over_the_line_cap_is_rejected() {
        let c = ctx(false);
        let spans: Vec<Value> = (0..MAX_RECORDS)
            .map(|i| json!({"name": format!("{i:0>128}")}))
            .collect();
        let doc = json!({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]});
        let e = process(Signal::Traces, 1, &doc, &c).err().unwrap();
        assert_eq!(e, Fail::TooLarge);
        assert_eq!(e.status(), 413);
    }

    #[test]
    fn show_values_text_output_is_bounded() {
        let c = ctx(true);
        let big = "x".repeat(3 << 20);
        let attrs: Vec<Value> = (0..3).map(|i| attr(&format!("k{i}"), sv(&big))).collect();
        let doc = logs(attrs, json!({"name": "s"}), vec![json!({})]);
        let p = process(Signal::Logs, 1, &doc, &c).unwrap();
        assert!(p.batch.text_body.len() < MAX_TEXT_BODY + 64);
        assert!(p.batch.tail.len() + ENVELOPE_BYTES <= crate::output::MAX_LINE_BYTES);
    }

    #[test]
    fn wildcard_catalog_keys_classify_but_do_not_print_attacker_suffixes() {
        let c = ctx(false);
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let doc = logs(
            vec![attr("service.name", sv("claude-code"))],
            json!({"name": "com.anthropic.claude_code.events"}),
            vec![
                json!({"body": sv("claude_code.tool_result"), "attributes": [
                attr("event.name", sv("tool_result")),
                attr(&format!("vcs.ref.head.{secret}"), sv("x"))]}),
            ],
        );
        let p = process(Signal::Logs, 1, &doc, &c).unwrap();
        let all = format!("{}{}", p.batch.tail, p.batch.text_body);
        assert!(!all.contains(secret), "{all}");
        let v: Value = serde_json::from_str(&p.batch.tail).unwrap();
        let attrs = &v["resources"][0]["scopes"][0]["records"][0]["attrs"];
        let f = attrs
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["known"] == true && a["key"].as_str().unwrap().starts_with("<unknown-key"))
            .expect("classified but labelled");
        assert_eq!(f["flag"], "OTEL_LOG_TOOL_DETAILS");
    }
}
