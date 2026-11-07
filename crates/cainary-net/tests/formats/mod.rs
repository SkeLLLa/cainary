//! The same OTLP export in every way a client may send it: JSON, protobuf, either one gzipped.
//! Shared by the plain and the takeover tests (design §8.2).
#![allow(dead_code)]

use flate2::{Compression, write::GzEncoder};
use serde_json::Value;
use std::io::Write;
use std::path::Path;

/// One export request, as plain OTLP/JSON, with the files that carry it in other forms.
pub struct Payload {
    pub name: &'static str,
    pub signal: &'static str,
    pub json: Vec<u8>,
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

pub fn payloads() -> Vec<Payload> {
    let core = "../cainary-core/tests/otel-payloads";
    [
        (
            "claude-code-2.1.316-logs",
            "logs",
            format!("{core}/claude-code-2.1.316/logs.json"),
        ),
        (
            "claude-code-2.1.316-metrics",
            "metrics",
            format!("{core}/claude-code-2.1.316/metrics.json"),
        ),
        (
            "codex-0.166.0-logs",
            "logs",
            format!("{core}/codex-0.166.0/logs.json"),
        ),
        (
            "synthetic-traces",
            "traces",
            "tests/fixtures/otlp/traces.json".to_string(),
        ),
    ]
    .into_iter()
    .map(|(name, signal, path)| Payload {
        name,
        signal,
        json: read(&path),
    })
    .collect()
}

/// One way of sending a payload.
pub struct Variant {
    pub label: String,
    pub content_type: &'static str,
    pub encoding: Option<&'static str>,
    pub body: Vec<u8>,
    /// What the batch line says: `format` and `encoding` keys, or `None` for the default.
    pub format: Option<&'static str>,
    pub gzip: bool,
}

impl Variant {
    /// The request headers that describe the body (no framing).
    pub fn headers(&self) -> String {
        let mut h = format!("Content-Type: {}\r\n", self.content_type);
        if let Some(e) = self.encoding {
            h.push_str(&format!("Content-Encoding: {e}\r\n"));
        }
        h
    }
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A valid gzip stream of `len` bytes that decodes to nothing, made of millions of empty
/// deflate blocks: tiny on the wire, but every block costs the decoder real time.
pub fn empty_block_bomb(len: usize) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    while v.len() < len {
        v.extend([0x02, 0x08, 0x20, 0x80, 0x00]);
    }
    v.extend([0x03, 0x00]);
    v.extend([0u8; 8]);
    v
}

pub fn variants(p: &Payload) -> Vec<Variant> {
    let fixture = |ext: &str| read(&format!("tests/fixtures/otlp/{}.{ext}", p.name));
    let v = |label: &str,
             content_type: &'static str,
             encoding: Option<&'static str>,
             body: Vec<u8>,
             format: Option<&'static str>| Variant {
        label: format!("{} {label}", p.name),
        content_type,
        encoding,
        body,
        format,
        gzip: encoding.is_some(),
    };
    let json = "application/json";
    let proto = "application/x-protobuf";
    let mut all = vec![
        v("json", json, None, p.json.clone(), None),
        v("json.gz", json, Some("gzip"), fixture("json.gz"), None),
        v("json x-gzip", json, Some("X-GZIP"), gzip(&p.json), None),
        v("binpb", proto, None, fixture("binpb"), Some("protobuf")),
        v(
            "binpb.gz",
            proto,
            Some("gzip"),
            fixture("binpb.gz"),
            Some("protobuf"),
        ),
        v(
            "binpb as application/protobuf",
            "application/protobuf; charset=utf-8",
            None,
            fixture("binpb"),
            Some("protobuf"),
        ),
    ];
    if p.name == "codex-0.166.0-logs" {
        all.push(v(
            "json two-member gzip",
            json,
            Some("gzip"),
            fixture("multi.json.gz"),
            None,
        ));
    }
    all
}

/// A batch or alert line without what legitimately differs between sends of one payload.
pub fn same(mut line: Value) -> Value {
    let o = line.as_object_mut().unwrap();
    for k in ["ts", "seq", "bytes", "format", "encoding"] {
        o.remove(k);
    }
    // The one real difference: a scope `version` of "" in JSON (codex sends it) reads as
    // `<empty>`, but protobuf can't tell an empty string from an absent one, so it reads null.
    let scopes = o
        .get_mut("resources")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get_mut("scopes")?.as_array_mut())
        .flatten();
    for scope in scopes {
        if scope["version"] == "<empty>" {
            scope["version"] = Value::Null;
        }
    }
    line
}

/// A `google.rpc.Status` body: (code, message).
pub fn status(body: &[u8]) -> (u64, String) {
    fn varint(b: &[u8], at: &mut usize) -> u64 {
        let mut v = 0u64;
        for shift in (0..).step_by(7) {
            let byte = b[*at];
            *at += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        v
    }
    let (mut at, mut code, mut message) = (0, None, None);
    while at < body.len() {
        match varint(body, &mut at) {
            0x08 => code = Some(varint(body, &mut at)),
            0x12 => {
                let n = varint(body, &mut at) as usize;
                message = Some(String::from_utf8(body[at..at + n].to_vec()).unwrap());
                at += n;
            }
            tag => panic!("unexpected tag {tag:#x} in {body:?}"),
        }
    }
    (code.expect("a code"), message.expect("a message"))
}

/// Where two values first differ, as a path with both sides, for readable failures.
pub fn first_diff(a: &Value, b: &Value) -> Option<String> {
    fn go(a: &Value, b: &Value, path: &mut String) -> bool {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for k in x.keys().chain(y.keys()) {
                    let at = path.len();
                    path.push_str(&format!(".{k}"));
                    match (x.get(k), y.get(k)) {
                        (Some(p), Some(q)) => {
                            if go(p, q, path) {
                                return true;
                            }
                        }
                        (p, q) => {
                            path.push_str(&format!(": {p:?} vs {q:?}"));
                            return true;
                        }
                    }
                    path.truncate(at);
                }
                false
            }
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
                for (i, (p, q)) in x.iter().zip(y).enumerate() {
                    let at = path.len();
                    path.push_str(&format!("[{i}]"));
                    if go(p, q, path) {
                        return true;
                    }
                    path.truncate(at);
                }
                false
            }
            _ if a == b => false,
            _ => {
                path.push_str(&format!(": {a} vs {b}"));
                true
            }
        }
    }
    let mut path = String::new();
    go(a, b, &mut path).then_some(path)
}
