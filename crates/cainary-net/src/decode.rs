//! What the body is and how to get the OTLP/JSON document out of it (design §8.2): the
//! `Content-Type` / `Content-Encoding` check, then gunzip and protobuf transcoding. Pure: reads
//! from a byte slice, no I/O.

use crate::http::Head;
use crate::otlp::{self, Signal};
use crate::otlp_pb;
use flate2::bufread::MultiGzDecoder;
use serde_json::Value;
use std::io::Read;

pub const PROTOBUF: &str = "application/protobuf";
pub const X_PROTOBUF: &str = "application/x-protobuf";

pub const TYPE_MESSAGE: &str = "cainary-otel-debug reads OTLP over HTTP as JSON or protobuf; gRPC isn't supported: set OTEL_EXPORTER_OTLP_PROTOCOL=http/json or http/protobuf (Claude Code) or protocol = \"json\" or \"binary\" in the otlp-http exporter (Codex)";
pub const ENCODING_MESSAGE: &str = "only gzip or uncompressed bodies are accepted; set OTEL_EXPORTER_OTLP_COMPRESSION to gzip or none";

/// The media type of the body. A protobuf body carries the spelling the request used, which its
/// response repeats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Json,
    Protobuf(&'static str),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    Identity,
    Gzip,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reject {
    pub status: u16,
    pub message: String,
}

fn reject<T>(status: u16, message: &str) -> Result<T, Reject> {
    Err(Reject {
        status,
        message: message.to_string(),
    })
}

/// The one value of a header that may appear once: `Ok(None)` when absent.
fn single<'a>(head: &'a Head, name: &str, what: &str) -> Result<Option<&'a str>, Reject> {
    let mut all = head.headers.iter().filter(|(k, _)| k == name);
    let first = all.next().map(|(_, v)| v.as_str());
    if all.next().is_some() {
        return reject(400, &format!("duplicate {what}"));
    }
    Ok(first)
}

/// `Content-Type` is `application/json` or `application/(x-)protobuf` (parameters ignored);
/// `Content-Encoding` is absent, `identity` or `gzip`/`x-gzip`.
pub fn content(head: &Head) -> Result<(Format, Encoding), Reject> {
    let ct = single(head, "content-type", "Content-Type")?.unwrap_or("");
    let media = ct.split(';').next().unwrap_or("").trim();
    let format = if media.eq_ignore_ascii_case("application/json") {
        Format::Json
    } else if media.eq_ignore_ascii_case(X_PROTOBUF) {
        Format::Protobuf(X_PROTOBUF)
    } else if media.eq_ignore_ascii_case(PROTOBUF) {
        Format::Protobuf(PROTOBUF)
    } else {
        return reject(415, TYPE_MESSAGE);
    };
    let enc = single(head, "content-encoding", "Content-Encoding")?
        .unwrap_or("identity")
        .trim();
    let encoding = if enc.eq_ignore_ascii_case("identity") {
        Encoding::Identity
    } else if enc.eq_ignore_ascii_case("gzip") || enc.eq_ignore_ascii_case("x-gzip") {
        Encoding::Gzip
    } else {
        return reject(415, ENCODING_MESSAGE);
    };
    Ok((format, encoding))
}

/// Every gzip member, at most `max` bytes out. Allocation stops at `max + 1`, so a bomb costs
/// what the cap does.
fn gunzip(body: &[u8], max: usize) -> Result<Vec<u8>, Reject> {
    let mut out = Vec::new();
    let mut dec = MultiGzDecoder::new(body).take(max as u64 + 1);
    if dec.read_to_end(&mut out).is_err() {
        return reject(400, "invalid gzip body");
    }
    if out.len() > max {
        return reject(413, "decompressed body too large");
    }
    Ok(out)
}

/// The OTLP/JSON document in `body`, whatever its format and encoding. `max` bounds the
/// decompressed size.
pub fn document(
    signal: Signal,
    format: Format,
    encoding: Encoding,
    body: &[u8],
    max: usize,
) -> Result<Value, Reject> {
    let unzipped;
    let body = match encoding {
        Encoding::Identity => body,
        Encoding::Gzip => {
            unzipped = gunzip(body, max)?;
            &unzipped
        }
    };
    match format {
        Format::Json => otlp::parse(body).or_else(|m| reject(400, &m)),
        Format::Protobuf(_) => {
            otlp_pb::to_json(signal, body).or_else(|e| reject(e.status, e.message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

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

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn err<T: std::fmt::Debug>(r: Result<T, Reject>) -> (u16, String) {
        let e = r.unwrap_err();
        (e.status, e.message)
    }

    #[test]
    fn content_types() {
        let ok = |h: &[(&str, &str)]| content(&head(h)).unwrap();
        assert_eq!(
            ok(&[("content-type", "application/json")]),
            (Format::Json, Encoding::Identity)
        );
        assert_eq!(
            ok(&[("content-type", "Application/JSON; charset=utf-8")]).0,
            Format::Json
        );
        assert_eq!(
            ok(&[("content-type", "application/x-protobuf")]).0,
            Format::Protobuf(X_PROTOBUF)
        );
        assert_eq!(
            ok(&[("content-type", "Application/Protobuf ; proto=x")]).0,
            Format::Protobuf(PROTOBUF)
        );
        for ct in ["", "text/plain", "application/grpc", "application/json2"] {
            assert_eq!(
                err(content(&head(&[("content-type", ct)]))),
                (415, TYPE_MESSAGE.to_string()),
                "{ct:?}"
            );
        }
        assert_eq!(
            err(content(&head(&[]))),
            (415, TYPE_MESSAGE.to_string()),
            "no Content-Type"
        );
        assert!(TYPE_MESSAGE.contains("JSON or protobuf") && TYPE_MESSAGE.contains("gRPC"));
    }

    #[test]
    fn content_encodings() {
        let enc = |v: &str| {
            content(&head(&[
                ("content-type", "application/json"),
                ("content-encoding", v),
            ]))
        };
        for v in ["identity", "Identity", " identity "] {
            assert_eq!(enc(v).unwrap().1, Encoding::Identity, "{v:?}");
        }
        for v in ["gzip", "GZIP", "x-gzip", "X-Gzip"] {
            assert_eq!(enc(v).unwrap().1, Encoding::Gzip, "{v:?}");
        }
        for v in [
            "deflate",
            "zstd",
            "br",
            "gzip, br",
            "gzip, gzip",
            "compress",
            "",
        ] {
            assert_eq!(err(enc(v)), (415, ENCODING_MESSAGE.to_string()), "{v:?}");
        }
        assert!(ENCODING_MESSAGE.contains("gzip"));
    }

    #[test]
    fn duplicate_headers_are_400() {
        assert_eq!(
            err(content(&head(&[
                ("content-type", "application/json"),
                ("content-type", "application/json"),
            ]))),
            (400, "duplicate Content-Type".to_string())
        );
        assert_eq!(
            err(content(&head(&[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
                ("content-encoding", "gzip"),
            ]))),
            (400, "duplicate Content-Encoding".to_string())
        );
    }

    const DOC: &[u8] = br#"{"resourceLogs":[]}"#;
    const MAX: usize = 16 * 1024 * 1024;

    fn doc(format: Format, encoding: Encoding, body: &[u8], max: usize) -> Result<Value, Reject> {
        document(Signal::Logs, format, encoding, body, max)
    }

    #[test]
    fn json_plain_and_gzip() {
        let want: Value = serde_json::from_slice(DOC).unwrap();
        assert_eq!(
            doc(Format::Json, Encoding::Identity, DOC, MAX).unwrap(),
            want
        );
        assert_eq!(
            doc(Format::Json, Encoding::Gzip, &gz(DOC), MAX).unwrap(),
            want
        );
        // Members are joined: the document may be split across them.
        let mut two = gz(&DOC[..7]);
        two.extend(gz(&DOC[7..]));
        assert_eq!(doc(Format::Json, Encoding::Gzip, &two, MAX).unwrap(), want);
        let (status, m) = err(doc(Format::Json, Encoding::Identity, b"{", MAX));
        assert_eq!(status, 400);
        assert!(m.starts_with("invalid JSON"), "{m}");
    }

    #[test]
    fn the_decompressed_cap_is_exact() {
        let zeros = vec![b' '; MAX];
        let mut at_cap = zeros.clone();
        at_cap[..2].copy_from_slice(b"{}");
        assert!(doc(Format::Json, Encoding::Gzip, &gz(&at_cap), MAX).is_ok());
        at_cap.push(b' ');
        assert_eq!(
            err(doc(Format::Json, Encoding::Gzip, &gz(&at_cap), MAX)),
            (413, "decompressed body too large".to_string())
        );
        // Over the cap in the second member.
        let mut two = gz(&zeros);
        two.extend(gz(b" "));
        assert_eq!(err(doc(Format::Json, Encoding::Gzip, &two, MAX)).0, 413);
    }

    #[test]
    fn bad_gzip_is_400() {
        let good = gz(DOC);
        let mut junk = good.clone();
        junk.extend(b"trailing junk");
        let mut zeros = good.clone();
        zeros.extend([0u8; 4]);
        let mut flipped = good.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0xff;
        let mut bad_crc = good.clone();
        let n = bad_crc.len();
        bad_crc[n - 5] ^= 0xff;
        let cases: [(&str, Vec<u8>); 7] = [
            ("not gzip", b"{}".to_vec()),
            ("empty", Vec::new()),
            ("header only", good[..10].to_vec()),
            ("truncated", good[..good.len() - 4].to_vec()),
            ("trailing junk", junk),
            ("trailing zeros", zeros),
            ("bit flip", flipped),
        ];
        for (what, body) in cases {
            assert_eq!(
                err(doc(Format::Json, Encoding::Gzip, &body, MAX)),
                (400, "invalid gzip body".to_string()),
                "{what}"
            );
        }
        assert_eq!(err(doc(Format::Json, Encoding::Gzip, &bad_crc, MAX)).0, 400);
        // Junk after a second member too.
        let mut two = gz(&DOC[..7]);
        two.extend(gz(&DOC[7..]));
        two.extend(b"x");
        assert_eq!(err(doc(Format::Json, Encoding::Gzip, &two, MAX)).0, 400);
    }

    #[test]
    fn protobuf_errors_keep_their_status_and_message() {
        // Field 1, length 5, only two bytes follow.
        let bad = [0x0a, 0x05, 0x01, 0x02];
        let e = otlp_pb::to_json(Signal::Logs, &bad).unwrap_err();
        assert_eq!(
            err(doc(
                Format::Protobuf(X_PROTOBUF),
                Encoding::Identity,
                &bad,
                MAX
            )),
            (e.status, e.message.to_string())
        );
        // An empty protobuf body is an empty request.
        assert!(doc(Format::Protobuf(PROTOBUF), Encoding::Gzip, &gz(b""), MAX).is_ok());
    }
}
