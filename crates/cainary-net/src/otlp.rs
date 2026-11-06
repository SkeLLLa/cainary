//! Routing, content checks and the OTLP/JSON pipeline (design §8.2, §14.2): from a request body
//! to the owned events the output thread prints. Pure: no I/O.
//!
//! **Phase 1 stand-in.** `walk` reads the OTLP structure without the vendor catalog; it is
//! replaced by `cainary_core::rules::otel_classify` when that lands.

use crate::http::Head;
use crate::output::{AlertEvent, BatchEvent, ErrorEvent, escape};
use crate::redflag::{Hit, Matcher, Scanner};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
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
    fn root(self) -> &'static str {
        match self {
            Signal::Logs => "resourceLogs",
            Signal::Metrics => "resourceMetrics",
            Signal::Traces => "resourceSpans",
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

// ── structure walk (phase 1 stand-in) ────────────────────────────────────────────────────────

struct Attr<'a> {
    key: &'a str,
    value: &'a Value,
}

struct Rec<'a> {
    name: &'a str,
    kind: &'static str,
    body: Option<&'a Value>,
    attrs: Vec<Attr<'a>>,
}

struct Scope<'a> {
    name: &'a str,
    version: Option<&'a str>,
    recs: Vec<Rec<'a>>,
}

struct Res<'a> {
    attrs: Vec<Attr<'a>>,
    scopes: Vec<Scope<'a>>,
}

struct Walker {
    signal: Signal,
    records: usize,
    attrs: usize,
}

type W<T> = Result<T, Fail>;

impl Walker {
    fn shape(&self) -> Fail {
        Fail::Shape(self.signal)
    }

    fn arr<'a>(&self, v: &'a Value, key: &str) -> W<&'a [Value]> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(&[]),
            Some(Value::Array(a)) => Ok(a),
            Some(_) => Err(self.shape()),
        }
    }

    fn obj<'a>(&self, v: &'a Value) -> W<&'a Value> {
        if v.is_object() {
            Ok(v)
        } else {
            Err(self.shape())
        }
    }

    fn attrs<'a>(&mut self, v: &'a Value) -> W<Vec<Attr<'a>>> {
        let list = self.arr(v, "attributes")?;
        self.attrs += list.len();
        if self.attrs > MAX_ATTRS {
            return Err(Fail::TooMany);
        }
        list.iter()
            .map(
                |a| match (a.get("key").and_then(Value::as_str), a.get("value")) {
                    (Some(key), Some(value)) => Ok(Attr { key, value }),
                    (Some(key), None) => Ok(Attr {
                        key,
                        value: &Value::Null,
                    }),
                    _ => Err(self.shape()),
                },
            )
            .collect()
    }

    fn count(&mut self, n: usize) -> W<()> {
        self.records += n;
        if self.records > MAX_RECORDS {
            Err(Fail::TooMany)
        } else {
            Ok(())
        }
    }

    fn walk<'a>(&mut self, doc: &'a Value) -> W<Vec<Res<'a>>> {
        let root = self.signal.root();
        if !doc.is_object() || !doc.get(root).is_some_and(Value::is_array) {
            return Err(self.shape());
        }
        let scope_key = match self.signal {
            Signal::Logs => "scopeLogs",
            Signal::Metrics => "scopeMetrics",
            Signal::Traces => "scopeSpans",
        };
        let mut out = Vec::new();
        for r in self.arr(doc, root)? {
            let r = self.obj(r)?;
            let attrs = match r.get("resource") {
                Some(res) => self.attrs(self.obj(res)?)?,
                None => Vec::new(),
            };
            let mut scopes = Vec::new();
            for s in self.arr(r, scope_key)? {
                let s = self.obj(s)?;
                let (name, version) = match s.get("scope") {
                    Some(sc) => (
                        sc.get("name").and_then(Value::as_str).unwrap_or(""),
                        sc.get("version").and_then(Value::as_str),
                    ),
                    None => ("", None),
                };
                let recs = match self.signal {
                    Signal::Logs => self.logs(s)?,
                    Signal::Metrics => self.metrics(s)?,
                    Signal::Traces => self.spans(s)?,
                };
                scopes.push(Scope {
                    name,
                    version,
                    recs,
                });
            }
            out.push(Res { attrs, scopes });
        }
        Ok(out)
    }

    fn logs<'a>(&mut self, scope: &'a Value) -> W<Vec<Rec<'a>>> {
        let items = self.arr(scope, "logRecords")?;
        self.count(items.len())?;
        let mut recs = Vec::new();
        for l in items {
            let l = self.obj(l)?;
            let attrs = self.attrs(l)?;
            let event_name = attrs
                .iter()
                .find(|a| a.key == "event.name")
                .and_then(|a| a.value.get("stringValue"))
                .and_then(Value::as_str);
            let body = l.get("body");
            let from_body = body
                .and_then(|b| b.get("stringValue"))
                .and_then(Value::as_str)
                .filter(|b| is_event_name(b))
                .filter(|b| event_name.is_some_and(|e| e == *b || b.ends_with(&format!(".{e}"))));
            recs.push(Rec {
                name: from_body.or(event_name).unwrap_or(""),
                kind: "event",
                body,
                attrs,
            });
        }
        Ok(recs)
    }

    fn metrics<'a>(&mut self, scope: &'a Value) -> W<Vec<Rec<'a>>> {
        let mut recs = Vec::new();
        for m in self.arr(scope, "metrics")? {
            let m = self.obj(m)?;
            let name = m.get("name").and_then(Value::as_str).unwrap_or("");
            for kind in [
                "sum",
                "gauge",
                "histogram",
                "exponentialHistogram",
                "summary",
            ] {
                let Some(body) = m.get(kind) else { continue };
                let points = self.arr(self.obj(body)?, "dataPoints")?;
                self.count(points.len())?;
                for p in points {
                    let p = self.obj(p)?;
                    recs.push(Rec {
                        name,
                        kind: "metric",
                        body: None,
                        attrs: self.attrs(p)?,
                    });
                }
            }
        }
        Ok(recs)
    }

    fn spans<'a>(&mut self, scope: &'a Value) -> W<Vec<Rec<'a>>> {
        let items = self.arr(scope, "spans")?;
        self.count(items.len())?;
        let mut recs = Vec::new();
        for s in items {
            let s = self.obj(s)?;
            recs.push(Rec {
                name: s.get("name").and_then(Value::as_str).unwrap_or(""),
                kind: "span",
                body: None,
                attrs: self.attrs(s)?,
            });
            let events = self.arr(s, "events")?;
            self.count(events.len())?;
            for e in events {
                let e = self.obj(e)?;
                recs.push(Rec {
                    name: e.get("name").and_then(Value::as_str).unwrap_or(""),
                    kind: "span-event",
                    body: None,
                    attrs: self.attrs(e)?,
                });
            }
        }
        Ok(recs)
    }
}

/// `^[a-z][a-z0-9_.]*$`
fn is_event_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.')
}

// ── masking helpers (phase 1 stand-ins for the core's) ───────────────────────────────────────

/// `(type, len)` of an OTLP AnyValue.
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
        (
            "array",
            Some(
                a.get("values")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
            ),
        )
    } else if let Some(k) = n("kvlistValue") {
        (
            "kvlist",
            Some(
                k.get("values")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
            ),
        )
    } else if let Some(b) = n("bytesValue").and_then(Value::as_str) {
        ("bytes", Some(b.chars().count()))
    } else {
        ("empty", None)
    }
}

pub fn mask(v: &Value) -> String {
    match any_type(v) {
        ("string", Some(n)) => format!("<string, {n} chars>"),
        ("array", Some(n)) => format!("<array, {n} items>"),
        ("kvlist", Some(n)) => format!("<kvlist, {n} keys>"),
        ("bytes", Some(n)) => format!("<bytes, {n} chars>"),
        ("empty", _) => "<empty>".to_string(),
        (t, _) => format!("<{t}>"),
    }
}

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

/// `n >= 8`: the first 3 characters and the length; shorter: the length only.
pub fn mask_match(s: &str) -> String {
    let n = s.chars().count();
    if n >= 8 {
        format!("{}…({n} chars)", s.chars().take(3).collect::<String>())
    } else {
        format!("…({n} chars)")
    }
}

/// Strings and numbers inside an AnyValue, recursively. Returns false when `MAX_DEPTH` cut it.
fn visit_texts(v: &Value, depth: usize, f: &mut dyn FnMut(&str)) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let mut complete = true;
    for k in ["stringValue", "intValue", "doubleValue"] {
        match v.get(k) {
            Some(Value::String(s)) => f(s),
            Some(Value::Number(n)) => f(&n.to_string()),
            _ => {}
        }
    }
    if let Some(items) = v
        .get("arrayValue")
        .and_then(|a| a.get("values"))
        .and_then(Value::as_array)
    {
        for i in items {
            complete &= visit_texts(i, depth + 1, f);
        }
    }
    if let Some(items) = v
        .get("kvlistValue")
        .and_then(|a| a.get("values"))
        .and_then(Value::as_array)
    {
        for kv in items {
            if let Some(k) = kv.get("key").and_then(Value::as_str) {
                f(k);
            }
            if let Some(inner) = kv.get("value") {
                complete &= visit_texts(inner, depth + 1, f);
            }
        }
    }
    complete
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
    /// Verbatim when `known` (in the catalog) or safe and unflagged; else a request-local label.
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

struct Group {
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
    groups: Vec<Group>,
    index: HashMap<(usize, Option<String>, &'static str), usize>,
    show: bool,
    hits: Vec<Hit>,
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
                    self.groups.push(Group {
                        pattern: h.pattern,
                        where_,
                        attribute: attribute.map(|a| cut(a, MAX_IDENT)),
                        event: event.map(|e| cut(e, MAX_IDENT)),
                        events: Vec::new(),
                        count: 0,
                        matched: if self.show {
                            cut(matched, MAX_RAW_MATCH)
                        } else {
                            mask_match(matched)
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
        let mut hits = std::mem::take(&mut self.hits);
        hits.clear();
        let complete = self.scanner.scan(s, &mut hits);
        let shown = self
            .namer
            .name(s, kind, known, !hits.is_empty() || !complete);
        self.hits = hits;
        shown
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
        let mut texts: Vec<String> = Vec::new();
        if !visit_texts(v, 0, &mut |t| texts.push(t.to_string())) {
            self.scanner.incomplete = true;
        }
        let mut hits = std::mem::take(&mut self.hits);
        for t in &texts {
            hits.clear();
            self.scanner.scan(t, &mut hits);
            self.record(t, &hits, where_, attribute, event);
        }
        self.hits = hits;
    }

    fn field(&self, key: &str, v: &Value) -> Value {
        let (ty, len) = any_type(v);
        let value = if self.show { raw(v) } else { mask(v) };
        let mut m = Map::new();
        m.insert("key".into(), json!(key));
        m.insert("group".into(), Value::Null);
        m.insert("known".into(), json!(false));
        m.insert("type".into(), json!(ty));
        if let Some(n) = len {
            m.insert("len".into(), json!(n));
        }
        m.insert("value".into(), json!(value));
        Value::Object(m)
    }

    fn text_value(&self, v: &Value) -> String {
        escape(&cut(
            &if self.show { raw(v) } else { mask(v) },
            MAX_TEXT_VALUE,
        ))
    }
}

pub struct Prepared {
    pub batch: BatchEvent,
    pub extra: Vec<ErrorEvent>,
}

fn vendor_of(service: Option<&str>) -> Option<&'static str> {
    match service {
        Some("claude-code" | "claude-code-desktop") => Some("claude-code"),
        Some(s) if s.starts_with("codex") => Some("codex"),
        _ => None,
    }
}

fn str_attr<'a>(attrs: &[Attr<'a>], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.key == key)
        .and_then(|a| a.value.get("stringValue"))
        .and_then(Value::as_str)
}

struct Summary {
    name: String,
    kind: &'static str,
    count: usize,
    keys: Vec<String>,
}

pub fn process(signal: Signal, bytes: usize, doc: &Value, ctx: &Ctx) -> Result<Prepared, Fail> {
    let mut w = Walker {
        signal,
        records: 0,
        attrs: 0,
    };
    let resources = w.walk(doc)?;
    let mut p = Proc::new(ctx);

    let mut service: Option<(String, Option<String>)> = None;
    let mut vendor = None;
    let mut resource_json = Vec::new();
    let mut resource_keys: Vec<String> = Vec::new();
    let mut text_body = String::new();
    let mut summaries: Vec<Summary> = Vec::new();
    let mut summary_index: HashMap<(String, &'static str), usize> = HashMap::new();
    let mut name_cache: HashMap<(usize, usize), String> = HashMap::new();

    for res in &resources {
        let mut attrs = Vec::new();
        let mut line = Vec::new();
        for (i, a) in res.attrs.iter().enumerate() {
            let label = p.scan_name(a.key, Label::Key, false, "resource", None, None);
            p.scan_value(a.value, "resource", Some(&label), None);
            attrs.push(p.field(&label, a.value));
            if i < 32 {
                line.push(format!("{} {}", escape(&label), p.text_value(a.value)));
            }
            if !resource_keys.contains(&label) {
                resource_keys.push(label);
            }
        }
        if service.is_none()
            && let Some(name) = str_attr(&res.attrs, "service.name")
        {
            vendor = vendor_of(Some(name));
            let name = p.shown(name, Label::Name, false);
            let version =
                str_attr(&res.attrs, "service.version").map(|v| p.shown(v, Label::Name, false));
            service = Some((name, version));
        }
        if !line.is_empty() {
            push_capped(
                &mut text_body,
                &format!("resource   {}\n", line.join(" · ")),
            );
        }

        let mut scopes_json = Vec::new();
        for sc in &res.scopes {
            let scope_name = p.scan_name(sc.name, Label::Name, false, "scope", None, None);
            let version = sc
                .version
                .map(|v| p.scan_name(v, Label::Name, false, "scope", None, None));
            let mut recs_json = Vec::new();
            for r in &sc.recs {
                // Sanitized once per distinct raw slice: all points of a metric share one name.
                let slice = (r.name.as_ptr() as usize, r.name.len());
                let name = match name_cache.get(&slice) {
                    Some(n) => n.clone(),
                    None => {
                        let n = if r.name.is_empty() {
                            "(unnamed)".to_string()
                        } else {
                            p.scan_name(r.name, Label::Name, false, "name", None, None)
                        };
                        name_cache.insert(slice, n.clone());
                        n
                    }
                };
                if let Some(b) = r.body {
                    p.scan_value(b, "body", None, Some(&name));
                }
                let mut fields = Vec::new();
                let mut keys = Vec::new();
                for a in &r.attrs {
                    let label = p.scan_name(a.key, Label::Key, false, "key", None, Some(&name));
                    p.scan_value(a.value, "value", Some(&label), Some(&name));
                    fields.push(p.field(&label, a.value));
                    keys.push(label);
                }
                match summary_index
                    .get(&(name.clone(), r.kind))
                    .map(|i| &mut summaries[*i])
                {
                    Some(s) => {
                        s.count += 1;
                        for k in keys {
                            if !s.keys.contains(&k) {
                                s.keys.push(k);
                            }
                        }
                    }
                    None => {
                        summary_index.insert((name.clone(), r.kind), summaries.len());
                        summaries.push(Summary {
                            name: name.clone(),
                            kind: r.kind,
                            count: 1,
                            keys,
                        });
                    }
                }
                recs_json
                    .push(json!({"name": name, "kind": r.kind, "known": false, "attrs": fields}));
            }
            scopes_json.push(json!({"name": scope_name, "version": version, "records": recs_json}));
        }
        resource_json.push(json!({"attrs": attrs, "scopes": scopes_json}));
    }

    for s in &summaries {
        push_capped(
            &mut text_body,
            &format!("{} ×{}\n", escape(&s.name), s.count),
        );
        let keys: Vec<String> = s.keys.iter().take(16).map(|k| escape(k)).collect();
        if !keys.is_empty() {
            push_capped(
                &mut text_body,
                &format!("  attrs    {}\n", keys.join(" · ")),
            );
        }
    }

    let summary = json!({
        "identity": [],
        "resource": resource_keys,
        "records": summaries.iter().map(|s| json!({
            "name": s.name, "kind": s.kind, "count": s.count, "known": false,
            "attrs": s.keys.iter().map(|k| json!({"key": k, "group": null, "known": false})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
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
    m.insert("catalog".into(), Value::Null);
    m.insert("records".into(), json!(w.records));
    m.insert("notInCatalog".into(), json!(0));
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
        vendor.unwrap_or("unknown vendor"),
        w.records
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

    #[test]
    fn mask_formats() {
        assert_eq!(mask(&sv("alice@example-corp.com")), "<string, 22 chars>");
        assert_eq!(mask(&json!({"intValue": "5"})), "<int>");
        assert_eq!(mask(&json!({"doubleValue": 1.5})), "<double>");
        assert_eq!(mask(&json!({"boolValue": true})), "<bool>");
        assert_eq!(
            mask(&json!({"arrayValue": {"values": [sv("a"), sv("b"), sv("c")]}})),
            "<array, 3 items>"
        );
        assert_eq!(
            mask(&json!({"kvlistValue": {"values": [{"key":"a","value":sv("x")}]}})),
            "<kvlist, 1 keys>"
        );
        assert_eq!(
            mask(&json!({"bytesValue": "AAAAAAAAAAAA"})),
            "<bytes, 12 chars>"
        );
        assert_eq!(mask(&json!({})), "<empty>");
        assert_eq!(mask_match("AKIAIOSFODNN7EXAMPLE"), "AKI…(20 chars)");
        assert_eq!(mask_match("short"), "…(5 chars)");
        assert_eq!(mask_match("exactly8"), "exa…(8 chars)");
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
}
