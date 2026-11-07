//! OTLP/HTTP protobuf bodies transcoded into OTLP/JSON (design §8.2): `to_json` turns an
//! `Export*ServiceRequest` into the `serde_json::Value` that `otlp` already consumes for JSON
//! bodies, so everything downstream stays one pipeline. Pure: no I/O, no dependencies, no
//! `unsafe`.
//!
//! Field numbers come from opentelemetry-proto **tag v1.5.0**
//! (<https://github.com/open-telemetry/opentelemetry-proto/tree/v1.5.0/opentelemetry/proto>):
//! `collector/*/v1/*_service.proto`, `common/v1/common.proto`, `resource/v1/resource.proto`,
//! `logs/v1/logs.proto`, `metrics/v1/metrics.proto` and `trace/v1/trace.proto`. Each message is
//! a static table of `(number, JSON name, kind)`; fields that are not in a table are skipped by
//! wire type like any unknown field.
//!
//! The output follows the OTLP JSON encoding: lowerCamelCase names, trace and span ids as
//! lowercase hex, other bytes as base64, enums as numbers, 64-bit integers as decimal strings,
//! whole doubles below 2^53 as integers (as protojson does), non-finite doubles as `"NaN"` / `"Infinity"` / `"-Infinity"`, absent scalars and empty
//! repeated fields omitted, a present message always emitted (even `{}`).
//!
//! Protobuf semantics: a singular scalar seen twice keeps the last, a singular message seen
//! twice is merged, setting one member of a oneof removes the others, repeated scalars may be
//! packed or not, and a field whose wire type does not fit its declared type is skipped as
//! unknown. Nesting and output size are bounded, so no input can exhaust the stack or memory
//! beyond the limits below.

use crate::otlp::Signal;
use serde_json::{Map, Number, Value};

/// Message nesting deeper than this is refused.
const MAX_DEPTH: usize = 100;
/// JSON values (scalars, objects, arrays and array elements) one request may produce.
const MAX_VALUES: usize = 1_000_000;
const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// The HTTP answer for a body that cannot be transcoded.
#[derive(Debug, PartialEq, Eq)]
pub struct PbError {
    pub status: u16,
    pub message: &'static str,
}

const MALFORMED: PbError = PbError {
    status: 400,
    message: "malformed protobuf",
};
const BAD_UTF8: PbError = PbError {
    status: 400,
    message: "invalid UTF-8 in a protobuf string",
};
const TOO_DEEP: PbError = PbError {
    status: 400,
    message: "protobuf nested too deeply",
};
const TOO_MANY: PbError = PbError {
    status: 413,
    message: "too many records or attributes in one request",
};

type R<T> = Result<T, PbError>;

// ── schema ───────────────────────────────────────────────────────────────────────────────────

/// `I32` and `S64` are part of the vocabulary though no v1.5.0 table uses them.
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum Kind {
    Str,
    BytesHex,
    BytesB64,
    Bool,
    /// Varint read as a 32-bit unsigned number.
    U32,
    /// Varint read as a 32-bit signed number.
    I32,
    /// Zigzag varint, 32 bits.
    S32,
    /// Varint enum, shown as its number.
    Enum,
    /// Varint 64-bit, decimal string.
    I64,
    U64,
    S64,
    Fixed32,
    Fixed64,
    SFixed64,
    Double,
    Msg(&'static Msg),
}

struct Field {
    num: u32,
    name: &'static str,
    kind: Kind,
    repeated: bool,
    /// Non-zero: members of one oneof share the number.
    oneof: u8,
}

struct Msg {
    fields: &'static [Field],
}

const fn f(num: u32, name: &'static str, kind: Kind) -> Field {
    Field {
        num,
        name,
        kind,
        repeated: false,
        oneof: 0,
    }
}

const fn rep(num: u32, name: &'static str, kind: Kind) -> Field {
    Field {
        num,
        name,
        kind,
        repeated: true,
        oneof: 0,
    }
}

const fn of(oneof: u8, num: u32, name: &'static str, kind: Kind) -> Field {
    Field {
        num,
        name,
        kind,
        repeated: false,
        oneof,
    }
}

use Kind::{
    BytesB64, BytesHex, Double, Enum, Fixed32, Fixed64, I64, Msg as M, S32, SFixed64, Str, U32, U64,
};

// common.proto
static ANY_VALUE: Msg = Msg {
    fields: &[
        of(1, 1, "stringValue", Str),
        of(1, 2, "boolValue", Kind::Bool),
        of(1, 3, "intValue", I64),
        of(1, 4, "doubleValue", Double),
        of(1, 5, "arrayValue", M(&ARRAY_VALUE)),
        of(1, 6, "kvlistValue", M(&KEY_VALUE_LIST)),
        of(1, 7, "bytesValue", BytesB64),
    ],
};
static ARRAY_VALUE: Msg = Msg {
    fields: &[rep(1, "values", M(&ANY_VALUE))],
};
static KEY_VALUE_LIST: Msg = Msg {
    fields: &[rep(1, "values", M(&KEY_VALUE))],
};
static KEY_VALUE: Msg = Msg {
    fields: &[f(1, "key", Str), f(2, "value", M(&ANY_VALUE))],
};
static SCOPE: Msg = Msg {
    fields: &[
        f(1, "name", Str),
        f(2, "version", Str),
        rep(3, "attributes", M(&KEY_VALUE)),
        f(4, "droppedAttributesCount", U32),
    ],
};

// resource.proto
static ENTITY_REF: Msg = Msg {
    fields: &[
        f(1, "schemaUrl", Str),
        f(2, "type", Str),
        rep(3, "idKeys", Str),
        rep(4, "descriptionKeys", Str),
    ],
};
static RESOURCE: Msg = Msg {
    fields: &[
        rep(1, "attributes", M(&KEY_VALUE)),
        f(2, "droppedAttributesCount", U32),
        rep(3, "entityRefs", M(&ENTITY_REF)),
    ],
};

// logs.proto
static LOGS_REQUEST: Msg = Msg {
    fields: &[rep(1, "resourceLogs", M(&RESOURCE_LOGS))],
};
static RESOURCE_LOGS: Msg = Msg {
    fields: &[
        f(1, "resource", M(&RESOURCE)),
        rep(2, "scopeLogs", M(&SCOPE_LOGS)),
        f(3, "schemaUrl", Str),
    ],
};
static SCOPE_LOGS: Msg = Msg {
    fields: &[
        f(1, "scope", M(&SCOPE)),
        rep(2, "logRecords", M(&LOG_RECORD)),
        f(3, "schemaUrl", Str),
    ],
};
static LOG_RECORD: Msg = Msg {
    fields: &[
        f(1, "timeUnixNano", Fixed64),
        f(2, "severityNumber", Enum),
        f(3, "severityText", Str),
        f(5, "body", M(&ANY_VALUE)),
        rep(6, "attributes", M(&KEY_VALUE)),
        f(7, "droppedAttributesCount", U32),
        f(8, "flags", Fixed32),
        f(9, "traceId", BytesHex),
        f(10, "spanId", BytesHex),
        f(11, "observedTimeUnixNano", Fixed64),
        f(12, "eventName", Str),
    ],
};

// trace.proto
static TRACES_REQUEST: Msg = Msg {
    fields: &[rep(1, "resourceSpans", M(&RESOURCE_SPANS))],
};
static RESOURCE_SPANS: Msg = Msg {
    fields: &[
        f(1, "resource", M(&RESOURCE)),
        rep(2, "scopeSpans", M(&SCOPE_SPANS)),
        f(3, "schemaUrl", Str),
    ],
};
static SCOPE_SPANS: Msg = Msg {
    fields: &[
        f(1, "scope", M(&SCOPE)),
        rep(2, "spans", M(&SPAN)),
        f(3, "schemaUrl", Str),
    ],
};
static SPAN: Msg = Msg {
    fields: &[
        f(1, "traceId", BytesHex),
        f(2, "spanId", BytesHex),
        f(3, "traceState", Str),
        f(4, "parentSpanId", BytesHex),
        f(5, "name", Str),
        f(6, "kind", Enum),
        f(7, "startTimeUnixNano", Fixed64),
        f(8, "endTimeUnixNano", Fixed64),
        rep(9, "attributes", M(&KEY_VALUE)),
        f(10, "droppedAttributesCount", U32),
        rep(11, "events", M(&SPAN_EVENT)),
        f(12, "droppedEventsCount", U32),
        rep(13, "links", M(&SPAN_LINK)),
        f(14, "droppedLinksCount", U32),
        f(15, "status", M(&STATUS)),
        f(16, "flags", Fixed32),
    ],
};
static SPAN_EVENT: Msg = Msg {
    fields: &[
        f(1, "timeUnixNano", Fixed64),
        f(2, "name", Str),
        rep(3, "attributes", M(&KEY_VALUE)),
        f(4, "droppedAttributesCount", U32),
    ],
};
static SPAN_LINK: Msg = Msg {
    fields: &[
        f(1, "traceId", BytesHex),
        f(2, "spanId", BytesHex),
        f(3, "traceState", Str),
        rep(4, "attributes", M(&KEY_VALUE)),
        f(5, "droppedAttributesCount", U32),
        f(6, "flags", Fixed32),
    ],
};
static STATUS: Msg = Msg {
    fields: &[f(2, "message", Str), f(3, "code", Enum)],
};

// metrics.proto
static METRICS_REQUEST: Msg = Msg {
    fields: &[rep(1, "resourceMetrics", M(&RESOURCE_METRICS))],
};
static RESOURCE_METRICS: Msg = Msg {
    fields: &[
        f(1, "resource", M(&RESOURCE)),
        rep(2, "scopeMetrics", M(&SCOPE_METRICS)),
        f(3, "schemaUrl", Str),
    ],
};
static SCOPE_METRICS: Msg = Msg {
    fields: &[
        f(1, "scope", M(&SCOPE)),
        rep(2, "metrics", M(&METRIC)),
        f(3, "schemaUrl", Str),
    ],
};
static METRIC: Msg = Msg {
    fields: &[
        f(1, "name", Str),
        f(2, "description", Str),
        f(3, "unit", Str),
        of(1, 5, "gauge", M(&GAUGE)),
        of(1, 7, "sum", M(&SUM)),
        of(1, 9, "histogram", M(&HISTOGRAM)),
        of(1, 10, "exponentialHistogram", M(&EXP_HISTOGRAM)),
        of(1, 11, "summary", M(&SUMMARY)),
        rep(12, "metadata", M(&KEY_VALUE)),
    ],
};
static GAUGE: Msg = Msg {
    fields: &[rep(1, "dataPoints", M(&NUMBER_POINT))],
};
static SUM: Msg = Msg {
    fields: &[
        rep(1, "dataPoints", M(&NUMBER_POINT)),
        f(2, "aggregationTemporality", Enum),
        f(3, "isMonotonic", Kind::Bool),
    ],
};
static HISTOGRAM: Msg = Msg {
    fields: &[
        rep(1, "dataPoints", M(&HISTOGRAM_POINT)),
        f(2, "aggregationTemporality", Enum),
    ],
};
static EXP_HISTOGRAM: Msg = Msg {
    fields: &[
        rep(1, "dataPoints", M(&EXP_HISTOGRAM_POINT)),
        f(2, "aggregationTemporality", Enum),
    ],
};
static SUMMARY: Msg = Msg {
    fields: &[rep(1, "dataPoints", M(&SUMMARY_POINT))],
};
static NUMBER_POINT: Msg = Msg {
    fields: &[
        rep(7, "attributes", M(&KEY_VALUE)),
        f(2, "startTimeUnixNano", Fixed64),
        f(3, "timeUnixNano", Fixed64),
        of(1, 4, "asDouble", Double),
        of(1, 6, "asInt", SFixed64),
        rep(5, "exemplars", M(&EXEMPLAR)),
        f(8, "flags", U32),
    ],
};
static HISTOGRAM_POINT: Msg = Msg {
    fields: &[
        rep(9, "attributes", M(&KEY_VALUE)),
        f(2, "startTimeUnixNano", Fixed64),
        f(3, "timeUnixNano", Fixed64),
        f(4, "count", Fixed64),
        f(5, "sum", Double),
        rep(6, "bucketCounts", Fixed64),
        rep(7, "explicitBounds", Double),
        rep(8, "exemplars", M(&EXEMPLAR)),
        f(10, "flags", U32),
        f(11, "min", Double),
        f(12, "max", Double),
    ],
};
static EXP_HISTOGRAM_POINT: Msg = Msg {
    fields: &[
        rep(1, "attributes", M(&KEY_VALUE)),
        f(2, "startTimeUnixNano", Fixed64),
        f(3, "timeUnixNano", Fixed64),
        f(4, "count", Fixed64),
        f(5, "sum", Double),
        f(6, "scale", S32),
        f(7, "zeroCount", Fixed64),
        f(8, "positive", M(&BUCKETS)),
        f(9, "negative", M(&BUCKETS)),
        f(10, "flags", U32),
        rep(11, "exemplars", M(&EXEMPLAR)),
        f(12, "min", Double),
        f(13, "max", Double),
        f(14, "zeroThreshold", Double),
    ],
};
static BUCKETS: Msg = Msg {
    fields: &[f(1, "offset", S32), rep(2, "bucketCounts", U64)],
};
static SUMMARY_POINT: Msg = Msg {
    fields: &[
        rep(7, "attributes", M(&KEY_VALUE)),
        f(2, "startTimeUnixNano", Fixed64),
        f(3, "timeUnixNano", Fixed64),
        f(4, "count", Fixed64),
        f(5, "sum", Double),
        rep(6, "quantileValues", M(&QUANTILE)),
        f(8, "flags", U32),
    ],
};
static QUANTILE: Msg = Msg {
    fields: &[f(1, "quantile", Double), f(2, "value", Double)],
};
static EXEMPLAR: Msg = Msg {
    fields: &[
        rep(7, "filteredAttributes", M(&KEY_VALUE)),
        f(2, "timeUnixNano", Fixed64),
        of(1, 3, "asDouble", Double),
        of(1, 6, "asInt", SFixed64),
        f(4, "spanId", BytesHex),
        f(5, "traceId", BytesHex),
    ],
};

impl Kind {
    /// The wire type a value of this kind arrives in.
    fn wire(self) -> u8 {
        match self {
            Kind::Str | Kind::BytesHex | Kind::BytesB64 | Kind::Msg(_) => 2,
            Kind::Fixed64 | Kind::SFixed64 | Kind::Double => 1,
            Kind::Fixed32 => 5,
            _ => 0,
        }
    }
}

// ── wire reader ──────────────────────────────────────────────────────────────────────────────

fn varint(buf: &mut &[u8]) -> R<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let Some((&b, rest)) = buf.split_first() else {
            return Err(MALFORMED);
        };
        *buf = rest;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(MALFORMED)
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> R<&'a [u8]> {
    if n > buf.len() {
        return Err(MALFORMED);
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Ok(head)
}

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// One decoded wire value.
#[derive(Clone, Copy)]
enum Wire<'a> {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u64),
    Bytes(&'a [u8]),
}

// ── JSON values ──────────────────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn double(v: f64) -> Value {
    // protojson (Go, Java) writes a whole double without a fraction: 3.0 is `3`, -0.0 is `0`.
    if v.fract() == 0.0 && v.abs() < 9_007_199_254_740_992.0 {
        return Value::from(v as i64);
    }
    match Number::from_f64(v) {
        Some(n) => Value::Number(n),
        None if v.is_nan() => Value::String("NaN".into()),
        None if v > 0.0 => Value::String("Infinity".into()),
        None => Value::String("-Infinity".into()),
    }
}

/// The JSON of a numeric wire value; `raw` holds the varint or the little-endian fixed bytes.
fn number(kind: Kind, raw: u64) -> Value {
    match kind {
        Kind::Bool => Value::Bool(raw != 0),
        Kind::U32 | Kind::Fixed32 => Value::from(raw as u32),
        Kind::I32 | Kind::Enum => Value::from(raw as u32 as i32),
        Kind::S32 => {
            let n = raw as u32;
            Value::from(((n >> 1) as i32) ^ -((n & 1) as i32))
        }
        Kind::I64 | Kind::SFixed64 => Value::String((raw as i64).to_string()),
        Kind::U64 | Kind::Fixed64 => Value::String(raw.to_string()),
        Kind::S64 => Value::String((((raw >> 1) as i64) ^ -((raw & 1) as i64)).to_string()),
        Kind::Double => double(f64::from_bits(raw)),
        Kind::Str | Kind::BytesHex | Kind::BytesB64 | Kind::Msg(_) => Value::Null,
    }
}

// ── decoder ──────────────────────────────────────────────────────────────────────────────────

struct Decoder {
    values: usize,
}

impl Decoder {
    fn bump(&mut self) -> R<()> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(TOO_MANY);
        }
        Ok(())
    }

    fn message(
        &mut self,
        msg: &Msg,
        mut buf: &[u8],
        depth: usize,
        out: &mut Map<String, Value>,
    ) -> R<()> {
        if depth > MAX_DEPTH {
            return Err(TOO_DEEP);
        }
        while !buf.is_empty() {
            let tag = varint(&mut buf)?;
            let num = tag >> 3;
            if num == 0 || num > MAX_FIELD_NUMBER {
                return Err(MALFORMED);
            }
            let wire = match tag & 7 {
                0 => Wire::Varint(varint(&mut buf)?),
                1 => Wire::Fixed64(le(take(&mut buf, 8)?)),
                2 => {
                    let len = usize::try_from(varint(&mut buf)?).map_err(|_| MALFORMED)?;
                    Wire::Bytes(take(&mut buf, len)?)
                }
                5 => Wire::Fixed32(le(take(&mut buf, 4)?)),
                _ => return Err(MALFORMED),
            };
            if let Some(field) = msg.fields.iter().find(|fl| u64::from(fl.num) == num) {
                self.field(msg, field, wire, depth, out)?;
            }
        }
        Ok(())
    }

    fn field(
        &mut self,
        msg: &Msg,
        field: &Field,
        wire: Wire<'_>,
        depth: usize,
        out: &mut Map<String, Value>,
    ) -> R<()> {
        match (field.kind, wire) {
            (Kind::Msg(sub), Wire::Bytes(b)) => {
                if field.repeated {
                    let mut m = Map::new();
                    self.bump()?;
                    self.message(sub, b, depth + 1, &mut m)?;
                    self.push(out, field, Value::Object(m))
                } else {
                    clear_oneof(msg, field, out);
                    let mut m = match out.remove(field.name) {
                        Some(Value::Object(m)) => m,
                        _ => {
                            self.bump()?;
                            Map::new()
                        }
                    };
                    self.message(sub, b, depth + 1, &mut m)?;
                    out.insert(field.name.to_string(), Value::Object(m));
                    Ok(())
                }
            }
            (Kind::Str, Wire::Bytes(b)) => {
                let s = std::str::from_utf8(b).map_err(|_| BAD_UTF8)?;
                self.set(msg, field, Value::String(s.to_string()), out)
            }
            (Kind::BytesHex, Wire::Bytes(b)) => self.set(msg, field, Value::String(hex(b)), out),
            (Kind::BytesB64, Wire::Bytes(b)) => self.set(msg, field, Value::String(base64(b)), out),
            // A packed run of a repeated scalar.
            (kind, Wire::Bytes(mut b)) if field.repeated && kind.wire() != 2 => {
                while !b.is_empty() {
                    let raw = match kind.wire() {
                        0 => varint(&mut b)?,
                        1 => le(take(&mut b, 8)?),
                        _ => le(take(&mut b, 4)?),
                    };
                    self.push(out, field, number(kind, raw))?;
                }
                Ok(())
            }
            (kind, Wire::Varint(raw)) if kind.wire() == 0 => {
                self.set(msg, field, number(kind, raw), out)
            }
            (kind, Wire::Fixed64(raw)) if kind.wire() == 1 => {
                self.set(msg, field, number(kind, raw), out)
            }
            (kind, Wire::Fixed32(raw)) if kind.wire() == 5 => {
                self.set(msg, field, number(kind, raw), out)
            }
            // The wire type does not fit the declared type: unknown, skipped.
            _ => Ok(()),
        }
    }

    /// Stores one scalar: appended for a repeated field, replacing for a singular one.
    fn set(&mut self, msg: &Msg, field: &Field, v: Value, out: &mut Map<String, Value>) -> R<()> {
        if field.repeated {
            return self.push(out, field, v);
        }
        self.bump()?;
        clear_oneof(msg, field, out);
        out.insert(field.name.to_string(), v);
        Ok(())
    }

    fn push(&mut self, out: &mut Map<String, Value>, field: &Field, v: Value) -> R<()> {
        if !out.contains_key(field.name) {
            self.bump()?;
        }
        self.bump()?;
        match out
            .entry(field.name.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(a) => {
                a.push(v);
                Ok(())
            }
            _ => Err(MALFORMED),
        }
    }
}

/// Setting one member of a oneof removes the others.
fn clear_oneof(msg: &Msg, field: &Field, out: &mut Map<String, Value>) {
    if field.oneof == 0 {
        return;
    }
    for other in msg.fields {
        if other.oneof == field.oneof && other.num != field.num {
            out.remove(other.name);
        }
    }
}

/// Transcodes an `Export{Logs,Metrics,Trace}ServiceRequest` into its OTLP/JSON document.
pub fn to_json(signal: Signal, bytes: &[u8]) -> Result<Value, PbError> {
    let root = match signal {
        Signal::Logs => &LOGS_REQUEST,
        Signal::Metrics => &METRICS_REQUEST,
        Signal::Traces => &TRACES_REQUEST,
    };
    let mut out = Map::new();
    Decoder { values: 0 }.message(root, bytes, 0, &mut out)?;
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A tiny protobuf encoder for building inputs.
    fn varint_bytes(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }
    fn tag(n: u64, wt: u64) -> Vec<u8> {
        varint_bytes(n << 3 | wt)
    }
    fn vi(n: u64, v: u64) -> Vec<u8> {
        [tag(n, 0), varint_bytes(v)].concat()
    }
    fn ld(n: u64, body: &[u8]) -> Vec<u8> {
        [tag(n, 2), varint_bytes(body.len() as u64), body.to_vec()].concat()
    }
    fn fx64(n: u64, v: u64) -> Vec<u8> {
        [tag(n, 1), v.to_le_bytes().to_vec()].concat()
    }
    fn fx32(n: u64, v: u32) -> Vec<u8> {
        [tag(n, 5), v.to_le_bytes().to_vec()].concat()
    }
    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    /// `ExportLogsServiceRequest` holding one record built from `record` bytes.
    fn logs_with(record: &[u8]) -> Vec<u8> {
        ld(1, &ld(2, &ld(2, record)))
    }
    fn log_json(bytes: &[u8]) -> Value {
        let v = to_json(Signal::Logs, bytes).unwrap();
        v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].clone()
    }
    fn err(signal: Signal, bytes: &[u8]) -> (u16, &'static str) {
        let e = to_json(signal, bytes).unwrap_err();
        (e.status, e.message)
    }

    #[test]
    fn an_empty_body_is_an_empty_document() {
        assert_eq!(to_json(Signal::Logs, b"").unwrap(), json!({}));
    }

    #[test]
    fn malformed_inputs_are_400() {
        let m = (400, "malformed protobuf");
        // groups, field 0, bad wire types
        assert_eq!(err(Signal::Logs, &tag(1, 3)), m);
        assert_eq!(err(Signal::Logs, &tag(1, 4)), m);
        assert_eq!(err(Signal::Logs, &tag(1, 6)), m);
        assert_eq!(err(Signal::Logs, &vi(0, 1)), m);
        // a varint over 10 bytes
        let mut long = tag(9, 0);
        long.extend([0x80; 10]);
        long.push(0);
        assert_eq!(err(Signal::Logs, &long), m);
        // a length past the end, truncated tag / fixed / varint
        assert_eq!(err(Signal::Logs, &[0x0a, 0x05, 1, 2]), m);
        assert_eq!(err(Signal::Logs, &[0x80]), m);
        assert_eq!(err(Signal::Logs, &tag(9, 1)), m);
        assert_eq!(err(Signal::Logs, &[tag(9, 5), vec![1, 2]].concat()), m);
        assert_eq!(err(Signal::Logs, &tag(9, 0)), m);
        // unknown fields are still checked for truncation
        assert_eq!(err(Signal::Logs, &[tag(99, 2), vec![9, 1]].concat()), m);
        // a packed run that is not a whole number of elements
        let packed = |run: &[u8]| ld(1, &ld(2, &ld(2, &ld(9, &ld(1, &ld(6, run))))));
        assert!(to_json(Signal::Metrics, &packed(&[0; 8])).is_ok());
        assert_eq!(err(Signal::Metrics, &packed(&[0; 5])), m);
    }

    #[test]
    fn invalid_utf8_is_400() {
        let body = ld(5, &ld(1, &[0xff, 0xfe]));
        assert_eq!(
            err(Signal::Logs, &logs_with(&body)),
            (400, "invalid UTF-8 in a protobuf string")
        );
        // an unknown field's bytes are never decoded
        assert!(to_json(Signal::Logs, &logs_with(&ld(99, &[0xff]))).is_ok());
    }

    #[test]
    fn nesting_is_bounded() {
        let nest = |levels: usize| {
            let mut v = ld(1, b"x");
            for _ in 0..levels {
                v = ld(5, &ld(1, &v));
            }
            logs_with(&ld(5, &v))
        };
        assert!(to_json(Signal::Logs, &nest(10)).is_ok());
        assert_eq!(
            err(Signal::Logs, &nest(60)),
            (400, "protobuf nested too deeply")
        );
        // far deeper than any stack could take stays an error, not an overflow
        let mut v = Vec::new();
        for _ in 0..2_000 {
            v = ld(5, &ld(1, &v));
        }
        assert_eq!(
            err(Signal::Logs, &logs_with(&ld(5, &v))),
            (400, "protobuf nested too deeply")
        );
    }

    #[test]
    fn too_many_values_is_413() {
        let run = vec![1u8; MAX_VALUES + 100];
        let bucket = ld(8, &ld(2, &run));
        let bytes = ld(1, &ld(2, &ld(2, &ld(10, &ld(1, &bucket)))));
        assert_eq!(
            err(Signal::Metrics, &bytes),
            (413, "too many records or attributes in one request")
        );
        let ok = vec![1u8; 1000];
        let bytes = ld(1, &ld(2, &ld(2, &ld(10, &ld(1, &ld(8, &ld(2, &ok)))))));
        assert!(to_json(Signal::Metrics, &bytes).is_ok());
    }

    #[test]
    fn packed_and_unpacked_repeated_scalars_agree() {
        let point = |body: Vec<u8>| ld(1, &ld(2, &ld(2, &ld(9, &ld(1, &body)))));
        let unpacked = point(cat(&[
            fx64(6, 7),
            fx64(6, 9),
            fx64(7, 1.5f64.to_bits()),
            fx64(7, 2.5f64.to_bits()),
        ]));
        let packed = point(cat(&[
            ld(6, &[7u64.to_le_bytes(), 9u64.to_le_bytes()].concat()),
            ld(7, &[1.5f64.to_le_bytes(), 2.5f64.to_le_bytes()].concat()),
        ]));
        let a = to_json(Signal::Metrics, &packed).unwrap();
        let b = to_json(Signal::Metrics, &unpacked).unwrap();
        assert_eq!(a, b);
        let p =
            &a["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["histogram"]["dataPoints"][0];
        assert_eq!(p["bucketCounts"], json!(["7", "9"]));
        assert_eq!(p["explicitBounds"], json!([1.5, 2.5]));
        // varint-packed too
        let varints = ld(
            1,
            &ld(
                2,
                &ld(2, &ld(10, &ld(1, &ld(8, &ld(2, &[1, 2, 0xac, 0x02]))))),
            ),
        );
        let v = to_json(Signal::Metrics, &varints).unwrap();
        let counts = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["exponentialHistogram"]
            ["dataPoints"][0]["positive"]["bucketCounts"];
        assert_eq!(counts, &json!(["1", "2", "300"]));
    }

    #[test]
    fn duplicate_messages_merge() {
        // two `body` messages: the second adds nothing for stringValue, and `resource` merges
        // scalar overwrite and repeated append
        let kv = |k: &str| ld(1, &cat(&[ld(1, k.as_bytes())]));
        let r1 = ld(1, &cat(&[kv("a"), vi(2, 1)]));
        let r2 = ld(1, &cat(&[kv("b"), vi(2, 5)]));
        let bytes = ld(1, &cat(&[r1, r2]));
        let v = to_json(Signal::Logs, &bytes).unwrap();
        let res = &v["resourceLogs"][0]["resource"];
        assert_eq!(res["droppedAttributesCount"], 5);
        assert_eq!(res["attributes"], json!([{"key": "a"}, {"key": "b"}]));
        // repeated messages stay separate elements
        let two = cat(&[ld(1, &[]), ld(1, &[])]);
        let v = to_json(Signal::Logs, &two).unwrap();
        assert_eq!(v["resourceLogs"], json!([{}, {}]));
    }

    #[test]
    fn a_oneof_keeps_the_last_member() {
        let body = ld(5, &cat(&[ld(1, b"text"), vi(3, 7)]));
        assert_eq!(
            log_json(&logs_with(&body))["body"],
            json!({"intValue": "7"})
        );
        let body = ld(5, &cat(&[vi(3, 7), ld(1, b"text")]));
        assert_eq!(
            log_json(&logs_with(&body))["body"],
            json!({"stringValue": "text"})
        );
        // a repeated member of the same kind: last wins
        let body = ld(5, &cat(&[ld(1, b"a"), ld(1, b"b")]));
        assert_eq!(
            log_json(&logs_with(&body))["body"],
            json!({"stringValue": "b"})
        );
        // the same message member twice merges
        let arr = |s: &str| ld(5, &ld(1, &ld(1, s.as_bytes())));
        let body = ld(5, &cat(&[arr("a"), arr("b")]));
        assert_eq!(
            log_json(&logs_with(&body))["body"],
            json!({"arrayValue": {"values": [{"stringValue": "a"}, {"stringValue": "b"}]}})
        );
        // metric data oneof
        let m = cat(&[ld(5, &[]), ld(7, &vi(3, 1))]);
        let bytes = ld(1, &ld(2, &ld(2, &m)));
        let v = to_json(Signal::Metrics, &bytes).unwrap();
        assert_eq!(
            v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0],
            json!({"sum": {"isMonotonic": true}})
        );
    }

    #[test]
    fn unknown_fields_and_mismatched_wire_types_are_skipped() {
        let rec = cat(&[
            vi(99, 1),
            fx64(98, 1),
            fx32(97, 1),
            ld(96, b"zz"),
            ld(3, b"WARN"),
            // `severityNumber` declared a varint, sent length-delimited
            ld(2, b"zz"),
            // `body` declared a message, sent as a varint
            vi(5, 3),
        ]);
        assert_eq!(log_json(&logs_with(&rec)), json!({"severityText": "WARN"}));
    }

    #[test]
    fn bytes_and_integers_follow_the_json_encoding() {
        let rec = cat(&[
            fx64(1, 1_700_000_000_000_000_000),
            vi(2, 9),
            fx32(8, 1),
            ld(9, &[0xab, 0xcd, 0x01]),
            ld(10, &[0, 0xff]),
            ld(5, &ld(7, b"Many hands")),
            ld(6, &cat(&[ld(1, b"i"), ld(2, &vi(3, u64::MAX))])),
            ld(6, &cat(&[ld(1, b"b"), ld(2, &vi(2, 1))])),
            vi(7, 4),
        ]);
        let v = log_json(&logs_with(&rec));
        assert_eq!(v["timeUnixNano"], "1700000000000000000");
        assert_eq!(v["severityNumber"], 9);
        assert_eq!(v["flags"], 1);
        assert_eq!(v["traceId"], "abcd01");
        assert_eq!(v["spanId"], "00ff");
        assert_eq!(v["body"]["bytesValue"], "TWFueSBoYW5kcw==");
        assert_eq!(v["attributes"][0]["value"]["intValue"], "-1");
        assert_eq!(v["attributes"][1]["value"]["boolValue"], true);
        assert_eq!(v["droppedAttributesCount"], 4);
        assert!(v.get("observedTimeUnixNano").is_none());
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn signed_and_zigzag_numbers() {
        // sint32 scale -3 (zigzag 5), offset 2 (zigzag 4)
        let point = cat(&[vi(6, 5), ld(8, &vi(1, 4))]);
        let bytes = ld(1, &ld(2, &ld(2, &ld(10, &ld(1, &point)))));
        let v = to_json(Signal::Metrics, &bytes).unwrap();
        let p = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["exponentialHistogram"]["dataPoints"]
            [0];
        assert_eq!(p["scale"], -3);
        assert_eq!(p["positive"]["offset"], 2);
        // negative enum / sfixed64
        let dp = cat(&[fx64(6, (-5i64) as u64), fx64(4, f64::NAN.to_bits())]);
        let bytes = ld(1, &ld(2, &ld(2, &ld(5, &ld(1, &dp)))));
        let v = to_json(Signal::Metrics, &bytes).unwrap();
        let p = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0];
        assert_eq!(p, &json!({"asDouble": "NaN"}));
    }

    #[test]
    fn whole_doubles_are_integers_like_protojson() {
        let gauge = |vals: &[f64]| {
            let dps: Vec<Vec<u8>> = vals.iter().map(|v| ld(1, &fx64(4, v.to_bits()))).collect();
            let bytes = ld(1, &ld(2, &ld(2, &ld(5, &dps.concat()))));
            let v = to_json(Signal::Metrics, &bytes).unwrap();
            v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["asDouble"].clone())
                .collect::<Vec<_>>()
        };
        let big = 9_007_199_254_740_992.0_f64; // 2^53
        let got = gauge(&[
            0.0,
            -0.0,
            3.0,
            -3.0,
            1e15,
            big - 1.0,
            0.5,
            -2.5,
            big,
            -big,
            1e300,
        ]);
        assert_eq!(
            got,
            [
                json!(0),
                json!(0),
                json!(3),
                json!(-3),
                json!(1_000_000_000_000_000_i64),
                json!(9_007_199_254_740_991_i64),
                json!(0.5),
                json!(-2.5),
                json!(big),
                json!(-big),
                json!(1e300),
            ]
        );
        // Integers print without a fraction, the rest keep theirs.
        let text: Vec<String> = got.iter().map(Value::to_string).collect();
        assert_eq!(&text[..4], ["0", "0", "3", "-3"]);
        assert_eq!(&text[6..8], ["0.5", "-2.5"]);
        assert!(got[0].is_i64() || got[0].is_u64());
        assert!(got[8].is_f64() && got[9].is_f64());
    }

    #[test]
    fn doubles_nan_and_infinities_are_strings() {
        let summary = |vals: &[f64]| {
            let q: Vec<Vec<u8>> = vals.iter().map(|v| ld(6, &fx64(1, v.to_bits()))).collect();
            let bytes = ld(1, &ld(2, &ld(2, &ld(11, &ld(1, &q.concat())))));
            let v = to_json(Signal::Metrics, &bytes).unwrap();
            v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["summary"]["dataPoints"][0]
                ["quantileValues"]
                .clone()
        };
        assert_eq!(
            summary(&[f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.5]),
            json!([
                {"quantile": "NaN"},
                {"quantile": "Infinity"},
                {"quantile": "-Infinity"},
                {"quantile": 0.5}
            ])
        );
    }

    #[test]
    fn a_present_empty_sum_is_emitted() {
        let bytes = ld(1, &ld(2, &ld(2, &cat(&[ld(1, b"m"), ld(7, &[])]))));
        let v = to_json(Signal::Metrics, &bytes).unwrap();
        assert_eq!(
            v,
            json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "m", "sum": {}}]}]}]})
        );
    }

    #[test]
    fn spans_events_links_and_status() {
        let span = cat(&[
            ld(1, &[1; 16]),
            ld(2, &[2; 8]),
            ld(4, &[3; 8]),
            ld(5, b"op"),
            vi(6, 2),
            ld(11, &cat(&[fx64(1, 5), ld(2, b"ev")])),
            ld(13, &cat(&[ld(1, &[4; 16]), ld(2, &[5; 8])])),
            ld(15, &cat(&[ld(2, b"boom"), vi(3, 2)])),
        ]);
        let bytes = ld(1, &ld(2, &ld(2, &span)));
        let v = to_json(Signal::Traces, &bytes).unwrap();
        let s = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(s["traceId"], "01".repeat(16));
        assert_eq!(s["parentSpanId"], "03".repeat(8));
        assert_eq!(s["kind"], 2);
        assert_eq!(s["events"][0], json!({"timeUnixNano": "5", "name": "ev"}));
        assert_eq!(s["links"][0]["traceId"], "04".repeat(16));
        assert_eq!(s["status"], json!({"message": "boom", "code": 2}));
    }

    #[test]
    fn exemplars_and_points() {
        let ex = cat(&[ld(5, &[9; 16]), ld(4, &[8; 8]), fx64(6, 3)]);
        let dp = cat(&[
            ld(7, &cat(&[ld(1, b"k"), ld(2, &ld(1, b"v"))])),
            ld(5, &ex),
            fx64(4, 2.0f64.to_bits()),
        ]);
        let bytes = ld(1, &ld(2, &ld(2, &ld(7, &ld(1, &dp)))));
        let v = to_json(Signal::Metrics, &bytes).unwrap();
        let p = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0];
        assert_eq!(p["asDouble"], 2.0);
        assert_eq!(p["attributes"][0]["value"]["stringValue"], "v");
        assert_eq!(p["exemplars"][0]["traceId"], "09".repeat(16));
        assert_eq!(p["exemplars"][0]["spanId"], "08".repeat(8));
        assert_eq!(p["exemplars"][0]["asInt"], "3");
    }

    #[test]
    fn random_inputs_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u32
        };
        let signals = [Signal::Logs, Signal::Metrics, Signal::Traces];
        // Bytes that look like short tags and lengths reach deeper than uniform noise does.
        let alphabet = [
            0x08u8, 0x0a, 0x12, 0x1a, 0x22, 0x2a, 0x32, 0x3a, 0x4a, 0x52, 0x00, 0x01, 0x02, 0x05,
            0x10, 0x7f, 0xff, 0x80,
        ];
        for round in 0..20_000u32 {
            let len = (next() % 4097) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if round % 2 == 0 {
                        r as u8
                    } else {
                        alphabet[(r as usize) % alphabet.len()]
                    }
                })
                .collect();
            for s in signals {
                let _ = to_json(s, &bytes);
            }
        }
    }
}
