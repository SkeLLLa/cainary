//! Integration tests: a real listener on loopback port 0, driven with `std::net::TcpStream`.

mod formats;

use cainary_net::decode::{ENCODING_MESSAGE, TYPE_MESSAGE};
use cainary_net::logfile::LogFile;
use cainary_net::peer::Lookup;
use cainary_net::redflag::{Matcher, presets};
use cainary_net::server::{self, Config, PEER_REFUSED, PEER_UNCONFIRMED, PeerUid, Server};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn lines(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
            .collect()
    }
    fn wait_for(&self, ty: &str, n: usize) -> Vec<Value> {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let l: Vec<Value> = self
                .lines()
                .into_iter()
                .filter(|v| v["type"] == ty)
                .collect();
            if l.len() >= n || Instant::now() > end {
                return l;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn presets_matcher() -> Arc<Matcher> {
    let p = presets::PRESETS
        .iter()
        .filter(|p| p.default_on)
        .map(presets::Preset::pattern)
        .collect();
    Arc::new(Matcher::new(p).unwrap())
}

fn start_with(f: impl FnOnce(&mut Config)) -> (Server, Buf) {
    let buf = Buf::default();
    let mut cfg = Config::new(Box::new(buf.clone()));
    cfg.listen = vec!["127.0.0.1".into()];
    cfg.matcher = presets_matcher();
    cfg.tunables.read_timeout = Duration::from_millis(200);
    cfg.tunables.request_deadline = Duration::from_millis(800);
    cfg.tunables.idle_timeout = Duration::from_millis(800);
    f(&mut cfg);
    (server::run(cfg).expect("server starts"), buf)
}

fn start() -> (Server, Buf) {
    start_with(|_| {})
}

struct Reply {
    status: u16,
    headers: String,
    body: String,
    bytes: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        let prefix = format!("{}: ", name.to_ascii_lowercase());
        self.headers
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with(&prefix))
            .map(|l| &l[prefix.len()..])
    }
}

fn read_reply(s: &mut TcpStream) -> Option<Reply> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..i]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if data.len() >= i + 4 + len {
                let status = head.split(' ').nth(1)?.parse().ok()?;
                let bytes = data[i + 4..i + 4 + len].to_vec();
                return Some(Reply {
                    status,
                    headers: head,
                    body: String::from_utf8_lossy(&bytes).into_owned(),
                    bytes,
                });
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn raw(addr: SocketAddr, request: &[u8]) -> Option<Reply> {
    let mut s = connect(addr);
    s.write_all(request).unwrap();
    read_reply(&mut s)
}

fn post_with(addr: SocketAddr, path: &str, extra: &str, body: &[u8]) -> Option<Reply> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{extra}Content-Length: {}\r\n\r\n",
        addr.port(),
        body.len()
    );
    let mut req = head.into_bytes();
    req.extend_from_slice(body);
    raw(addr, &req)
}

fn post_json(addr: SocketAddr, path: &str, doc: &Value) -> Reply {
    post_with(
        addr,
        path,
        "Content-Type: application/json\r\n",
        doc.to_string().as_bytes(),
    )
    .expect("a reply")
}

fn sv(s: &str) -> Value {
    json!({"stringValue": s})
}

fn logs_doc(attrs: Vec<(&str, &str)>) -> Value {
    let attrs: Vec<Value> = attrs
        .into_iter()
        .map(|(k, v)| json!({"key": k, "value": sv(v)}))
        .collect();
    json!({"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": sv("claude-code")}]},
        "scopeLogs": [{"scope": {"name": "com.anthropic.claude_code.events"},
          "logRecords": [{"body": sv("claude_code.tool_result"), "attributes": attrs}]}]}]})
}

#[test]
fn a_post_is_acknowledged_and_streamed() {
    let (srv, out) = start();
    let r = post_json(
        srv.addrs[0],
        "/v1/logs",
        &logs_doc(vec![("event.name", "tool_result")]),
    );
    assert_eq!((r.status, r.body.as_str()), (200, "{}"));
    assert!(r.headers.contains("Content-Type: application/json"));
    let hello = &out.wait_for("hello", 1)[0];
    assert_eq!(hello["v"], 1);
    assert_eq!(hello["showValues"], false);
    assert!(
        hello["listen"][0]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    let batch = &out.wait_for("batch", 1)[0];
    assert_eq!(batch["seq"], 1);
    assert_eq!(batch["signal"], "logs");
    assert_eq!(batch["path"], "/v1/logs");
    assert_eq!(batch["vendor"], "claude-code");
    assert_eq!(batch["records"], 1);
    let keys: Vec<&str> = batch
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(&keys[..4], ["v", "type", "ts", "seq"]);
    srv.shutdown();
}

#[test]
fn secrets_are_masked_in_output_and_alerts_and_shown_on_request() {
    let doc = logs_doc(vec![
        ("event.name", "tool_result"),
        ("user.email", "alice@example-corp.com"),
        ("tool_input", "AKIAIOSFODNN7EXAMPLE"),
    ]);
    let (srv, out) = start();
    assert_eq!(post_json(srv.addrs[0], "/v1/logs", &doc).status, 200);
    let alerts = out.wait_for("alert", 2);
    let text = out.text();
    assert!(
        !text.contains("alice@example-corp.com") && !text.contains("AKIAIOSFODNN7EXAMPLE"),
        "{text}"
    );
    let m: Vec<&str> = alerts
        .iter()
        .map(|a| a["match"].as_str().unwrap())
        .collect();
    assert!(
        m.contains(&"ali…(22 chars)") && m.contains(&"AKI…(20 chars)"),
        "{m:?}"
    );
    srv.shutdown();

    let (srv, out) = start_with(|c| c.show_values = true);
    assert_eq!(post_json(srv.addrs[0], "/v1/logs", &doc).status, 200);
    out.wait_for("alert", 2);
    let text = out.text();
    assert!(text.contains("alice@example-corp.com") && text.contains("AKIAIOSFODNN7EXAMPLE"));
    srv.shutdown();
}

#[test]
fn a_secret_in_every_string_position_never_reaches_any_output() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let (srv, out) = start();
    let a = srv.addrs[0];
    let doc = json!({"resourceLogs": [{"resource": {"attributes": [
        {"key": secret, "value": sv(secret)}, {"key": "service.name", "value": sv(secret)}]},
        "scopeLogs": [{"scope": {"name": secret, "version": secret}, "logRecords": [
          {"body": sv(secret), "attributes": [{"key": secret, "value": sv(secret)}, {"key": "event.name", "value": sv(secret)}]}]}]}]});
    assert_eq!(post_json(a, "/v1/logs", &doc).status, 200);
    let spans = json!({"resourceSpans": [{"scopeSpans": [{"spans": [{"name": secret, "events": [{"name": secret}]}]}]}]});
    assert_eq!(post_json(a, "/v1/traces", &spans).status, 200);
    // Malformed input, an unknown path and a secret method or header value.
    let r = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/json\r\n",
        format!("{{\"k\": {secret}").as_bytes(),
    )
    .unwrap();
    assert_eq!(r.status, 400);
    assert!(!r.body.contains(secret));
    let r = post_with(
        a,
        &format!("/{secret}"),
        "Content-Type: application/json\r\n",
        b"{}",
    )
    .unwrap();
    assert_eq!(r.status, 404);
    assert!(!r.body.contains(secret));
    let r = raw(
        a,
        format!(
            "{secret} /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            a.port()
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(!r.body.contains(secret));
    let r = post_with(a, "/v1/logs", &format!("Content-Type: {secret}\r\n"), b"{}").unwrap();
    assert_eq!(r.status, 415);
    assert!(!r.body.contains(secret));
    out.wait_for("batch", 2);
    out.wait_for("error", 4);
    let text = out.text();
    assert!(!text.contains(secret), "{text}");
    srv.shutdown();
}

#[test]
fn terminal_escapes_in_text_mode() {
    let osc = "x\u{1b}]52;c;c2VjcmV0\u{7}y\r\u{202e}z";
    let (srv, out) = start_with(|c| {
        c.json = false;
        c.show_values = true;
    });
    let mut doc = logs_doc(vec![("event.name", "tool_result")]);
    doc["resourceLogs"][0]["resource"]["attributes"][0]["value"] = sv(osc);
    assert_eq!(post_json(srv.addrs[0], "/v1/logs", &doc).status, 200);
    let end = Instant::now() + Duration::from_secs(5);
    while !out.text().contains("claude_code.tool_result") && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    let text = out.text();
    assert!(text.contains("──"), "{text}");
    for bad in ['\u{1b}', '\u{7}', '\r', '\u{202e}'] {
        assert!(!text.contains(bad), "{bad:?} in {text:?}");
    }
    assert!(text.contains("\\u{1b}]52"));
    srv.shutdown();
}

#[test]
fn rejections_use_the_documented_statuses_and_messages() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    let grpc = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/grpc\r\n",
        b"\x00\x00\x00\x00\x00",
    )
    .unwrap();
    assert_eq!(grpc.status, 415);
    assert_eq!(
        grpc.body,
        json!({"code": 3, "message": TYPE_MESSAGE}).to_string()
    );
    assert!(grpc.body.contains("OTEL_EXPORTER_OTLP_PROTOCOL") && grpc.body.contains("gRPC"));
    let zstd = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/json\r\nContent-Encoding: zstd\r\n",
        b"\x28\xb5",
    )
    .unwrap();
    assert_eq!(zstd.status, 415);
    assert_eq!(
        zstd.body,
        r#"{"code":3,"message":"only gzip or uncompressed bodies are accepted; set OTEL_EXPORTER_OTLP_COMPRESSION to gzip or none"}"#
    );
    let bad = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/json\r\n",
        b"{not json",
    )
    .unwrap();
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("invalid JSON"));
    let wrong = post_json(a, "/v1/logs", &json!({"hello": 1}));
    assert_eq!(wrong.status, 400);
    assert!(wrong.body.contains("not an OTLP logs document"));
    let get = raw(
        a,
        format!(
            "GET /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            a.port()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(get.status, 405);
    assert!(get.headers.contains("Allow: POST") && get.headers.contains("Connection: close"));
    let opt = raw(
        a,
        format!(
            "OPTIONS /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            a.port()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(opt.status, 405);
    assert!(!opt.headers.to_lowercase().contains("access-control"));
    let nf = raw(
        a,
        format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", a.port()).as_bytes(),
    )
    .unwrap();
    assert_eq!(nf.status, 404);
    // The next request still works.
    assert_eq!(post_json(a, "/v1/logs", &logs_doc(vec![])).status, 200);
    let errs = out.wait_for("error", 7);
    assert_eq!(errs.len(), 7);
    assert_eq!(errs[0]["source"], "http");
    assert_eq!(errs[0]["status"], 415);
    assert_eq!(errs[0]["path"], "/v1/logs");
    srv.shutdown();
}

fn post_variant(addr: SocketAddr, path: &str, v: &formats::Variant) -> Reply {
    post_with(addr, path, &v.headers(), &v.body).expect("a reply")
}

#[test]
fn every_format_and_encoding_gives_the_same_batch() {
    // Raw values as well as masked ones: a transcoder that bent a value would show.
    for show in [false, true] {
        let (srv, out) = start_with(|c| c.show_values = show);
        let a = srv.addrs[0];
        let mut sent = Vec::new();
        for p in formats::payloads() {
            let path = format!("/v1/{}", p.signal);
            for v in formats::variants(&p) {
                let r = post_variant(a, &path, &v);
                assert_eq!(r.status, 200, "{}: {}", v.label, r.body);
                sent.push((p.name, v));
                // One at a time, so the lines come out in the order they were sent.
                out.wait_for("batch", sent.len());
            }
        }
        srv.shutdown();
        // Each batch and the alerts after it, up to the next batch.
        let mut groups: Vec<Vec<Value>> = Vec::new();
        for l in out.lines() {
            match l["type"].as_str().unwrap() {
                "batch" => groups.push(vec![l]),
                "alert" => groups.last_mut().unwrap().push(l),
                _ => {}
            }
        }
        assert_eq!(groups.len(), sent.len());
        let mut first: Option<(&str, Vec<Value>)> = None;
        for ((name, v), group) in sent.iter().zip(&groups) {
            let batch = &group[0];
            assert_eq!(
                batch["bytes"],
                v.body.len(),
                "{}: bytes is the wire size",
                v.label
            );
            assert_eq!(batch["format"].as_str(), v.format, "{}", v.label);
            assert_eq!(
                batch["encoding"].as_str(),
                v.gzip.then_some("gzip"),
                "{}",
                v.label
            );
            let got: Vec<Value> = group.iter().cloned().map(formats::same).collect();
            match &first {
                Some((n, want)) if n == name => {
                    let diff = formats::first_diff(&json!(got), &json!(want));
                    assert!(
                        diff.is_none(),
                        "{} differs from its JSON (show={show}): {diff:?}",
                        v.label
                    );
                }
                _ => {
                    assert!(batch["records"].as_u64().unwrap() > 0, "{}", v.label);
                    first = Some((name, got));
                }
            }
        }
        // The payloads exercise the red flags too.
        assert!(
            groups.iter().any(|g| g.len() > 1),
            "no alert in any payload"
        );
    }
}

#[test]
fn text_mode_says_protobuf_and_gzip() {
    let (srv, out) = start_with(|c| c.json = false);
    let a = srv.addrs[0];
    let p = formats::payloads().remove(2);
    for v in formats::variants(&p) {
        assert_eq!(post_variant(a, "/v1/logs", &v).status, 200, "{}", v.label);
    }
    srv.shutdown();
    let text = out.text();
    // The header ends with the time.
    let headers: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(" records"))
        .filter_map(|l| l.rsplit_once(" · ").map(|(h, _)| h))
        .collect();
    let has = |suffix: &str| headers.iter().any(|h| h.ends_with(suffix));
    assert!(has(" records"), "{text}");
    assert!(has(" records · gzip"), "{text}");
    assert!(has(" records · protobuf"), "{text}");
    assert!(has(" records · protobuf · gzip"), "{text}");
}

#[test]
fn protobuf_requests_get_protobuf_answers() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    let p = formats::payloads().remove(2);
    let binpb = formats::variants(&p)[3].body.clone();
    for (ct, media) in [
        ("application/x-protobuf", "application/x-protobuf"),
        (
            "Application/Protobuf; charset=utf-8",
            "application/protobuf",
        ),
    ] {
        let r = post_with(a, "/v1/logs", &format!("Content-Type: {ct}\r\n"), &binpb).unwrap();
        assert_eq!(r.status, 200);
        assert!(r.bytes.is_empty(), "an empty ExportLogsServiceResponse");
        assert_eq!(r.header("content-type"), Some(media));
        assert_eq!(r.header("content-length"), Some("0"));
    }

    // Once it's known to be protobuf, every error is a google.rpc.Status with the same HTTP status.
    let torn = [0x0a, 0x05, 0x01];
    let want = cainary_net::otlp_pb::to_json(cainary_net::otlp::Signal::Logs, &torn).unwrap_err();
    let proto = "Content-Type: application/x-protobuf\r\n";
    let bad = post_with(a, "/v1/logs", proto, &torn).unwrap();
    assert_eq!(bad.status, want.status);
    assert_eq!(bad.header("content-type"), Some("application/x-protobuf"));
    assert_eq!(formats::status(&bad.bytes), (3, want.message.to_string()));
    assert!(bad.headers.contains("Connection: close"));

    let bomb = formats::gzip(&vec![0u8; 17 << 20]);
    let big = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/protobuf\r\nContent-Encoding: gzip\r\n",
        &bomb,
    )
    .unwrap();
    assert_eq!(big.status, 413);
    assert_eq!(big.header("content-type"), Some("application/protobuf"));
    assert_eq!(
        formats::status(&big.bytes),
        (3, "decompressed body too large".to_string())
    );
    let junk = post_with(
        a,
        "/v1/logs",
        &format!("{proto}Content-Encoding: gzip\r\n"),
        b"not gzip",
    )
    .unwrap();
    assert_eq!(junk.status, 400);
    assert_eq!(
        formats::status(&junk.bytes),
        (3, "invalid gzip body".to_string())
    );

    // Before the request is known to be protobuf, the answer is JSON as ever.
    let get = raw(
        a,
        format!(
            "GET /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{proto}\r\n",
            a.port()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        (get.status, get.header("content-type")),
        (405, Some("application/json"))
    );
    let nf = post_with(a, "/nope", proto, b"").unwrap();
    assert_eq!(
        (nf.status, nf.header("content-type")),
        (404, Some("application/json"))
    );
    let dup = post_with(a, "/v1/logs", &format!("{proto}{proto}"), b"").unwrap();
    assert_eq!(dup.status, 400);
    assert!(dup.body.contains("duplicate Content-Type"), "{}", dup.body);
    let enc = post_with(
        a,
        "/v1/logs",
        &format!("{proto}Content-Encoding: br\r\n"),
        b"",
    )
    .unwrap();
    assert_eq!(
        (enc.status, enc.header("content-type")),
        (415, Some("application/json"))
    );

    let errs = out.wait_for("error", 7);
    assert_eq!(errs.len(), 7);
    assert_eq!(errs[0]["status"], i64::from(want.status));
    assert_eq!(errs[0]["message"], want.message);

    // The same connection keeps working after a good protobuf request.
    let mut s = connect(a);
    for _ in 0..2 {
        let head = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{proto}Content-Length: {}\r\n\r\n",
            a.port(),
            binpb.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(&binpb).unwrap();
        let r = read_reply(&mut s).unwrap();
        assert_eq!(r.status, 200);
        assert!(r.headers.contains("Connection: keep-alive"));
    }
    srv.shutdown();
}

#[test]
fn unsupported_encodings_and_types_are_415_and_duplicates_400() {
    let (srv, _out) = start();
    let a = srv.addrs[0];
    let json = "Content-Type: application/json\r\n";
    for enc in [
        "deflate",
        "zstd",
        "br",
        "compress",
        "gzip, br",
        "br, gzip",
        "gzip, gzip",
        "",
    ] {
        let extra = format!("{json}Content-Encoding: {enc}\r\n");
        let r = post_with(a, "/v1/logs", &extra, b"{}").unwrap();
        assert_eq!(r.status, 415, "{enc:?}");
        assert_eq!(
            r.body,
            json!({"code": 3, "message": ENCODING_MESSAGE}).to_string()
        );
    }
    for ct in [
        "application/grpc",
        "application/grpc+proto",
        "text/plain",
        "application/xml",
        "",
    ] {
        let r = post_with(a, "/v1/logs", &format!("Content-Type: {ct}\r\n"), b"{}").unwrap();
        assert_eq!(r.status, 415, "{ct:?}");
        assert_eq!(
            r.body,
            json!({"code": 3, "message": TYPE_MESSAGE}).to_string()
        );
    }
    assert_eq!(post_with(a, "/v1/logs", "", b"{}").unwrap().status, 415);
    for (extra, what) in [
        (format!("{json}{json}"), "duplicate Content-Type"),
        (
            format!("{json}Content-Type: application/x-protobuf\r\n"),
            "duplicate Content-Type",
        ),
        (
            format!("{json}Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n"),
            "duplicate Content-Encoding",
        ),
        (
            format!("{json}Content-Encoding: identity\r\nContent-Encoding: gzip\r\n"),
            "duplicate Content-Encoding",
        ),
    ] {
        let r = post_with(a, "/v1/logs", &extra, b"{}").unwrap();
        assert_eq!(r.status, 400, "{extra:?}");
        assert!(r.body.contains(what), "{}", r.body);
    }
    // `identity` is a plain body.
    let doc = logs_doc(vec![]).to_string();
    let extra = format!("{json}Content-Encoding: Identity\r\n");
    let ok = post_with(a, "/v1/logs", &extra, doc.as_bytes()).unwrap();
    assert_eq!(ok.status, 200);
    srv.shutdown();
}

#[test]
fn gzip_bodies_are_bounded_and_strict() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    let gz = "Content-Type: application/json\r\nContent-Encoding: gzip\r\n";
    let doc = logs_doc(vec![("event.name", "tool_result")]).to_string();
    let good = formats::gzip(doc.as_bytes());

    // 17 MiB of zeros is about 17 KiB on the wire: the wire budget lets it in, the decoded cap
    // doesn't.
    let bomb = formats::gzip(&vec![0u8; 17 << 20]);
    assert!(bomb.len() < 64 * 1024);
    let r = post_with(a, "/v1/logs", gz, &bomb).unwrap();
    assert_eq!(r.status, 413);
    assert_eq!(
        r.body,
        r#"{"code":3,"message":"decompressed body too large"}"#
    );

    let mut junk = good.clone();
    junk.extend(b"trailing junk");
    let mut zeros = good.clone();
    zeros.extend([0u8; 8]);
    for (what, body) in [
        ("not gzip", b"{\"resourceLogs\":[]}".to_vec()),
        ("empty", Vec::new()),
        ("truncated", good[..good.len() - 6].to_vec()),
        ("trailing junk", junk),
        ("trailing zeros", zeros),
    ] {
        let r = post_with(a, "/v1/logs", gz, &body).unwrap();
        assert_eq!(r.status, 400, "{what}");
        assert_eq!(
            r.body, r#"{"code":3,"message":"invalid gzip body"}"#,
            "{what}"
        );
    }

    // A good one still works afterwards, and counts as its wire size.
    let r = post_with(a, "/v1/logs", gz, &good).unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "{}"));
    let b = out.wait_for("batch", 1);
    assert_eq!(b[0]["bytes"], good.len());
    assert_eq!(b[0]["encoding"], "gzip");
    assert!(b[0].get("format").is_none());
    assert_eq!(out.wait_for("error", 6).len(), 6);
    srv.shutdown();
}

#[test]
fn browsers_and_rebinding_are_refused_before_any_body() {
    let (srv, _out) = start();
    let a = srv.addrs[0];
    let p = a.port();
    let req = |headers: &str| {
        format!(
            "POST /v1/logs HTTP/1.1\r\n{headers}Content-Type: application/json\r\nContent-Length: 19\r\n\r\n{{\"resourceLogs\":[]}}"
        )
    };
    let ok = raw(a, req(&format!("Host: localhost:{p}\r\n")).as_bytes()).unwrap();
    assert_eq!(ok.status, 200);
    let ok = raw(a, req(&format!("Host: LOCALHOST:{p}\r\n")).as_bytes()).unwrap();
    assert_eq!(ok.status, 200);
    for host in [
        "evil.example.com",
        &format!("evil.example.com:{p}"),
        &format!("localhost.evil.com:{p}"),
        "127.0.0.1:1",
        &format!("127.0.0.1.nip.io:{p}"),
        "localhost",
    ] {
        let r = raw(a, req(&format!("Host: {host}\r\n")).as_bytes()).unwrap();
        assert_eq!(r.status, 421, "{host}");
    }
    assert_eq!(raw(a, req("").as_bytes()).unwrap().status, 400);
    assert_eq!(
        raw(
            a,
            req(&format!("Host: localhost:{p}\r\nHost: localhost:{p}\r\n")).as_bytes()
        )
        .unwrap()
        .status,
        400
    );
    for h in [
        "Origin: https://evil.example.com\r\n",
        "Origin: null\r\n",
        "Sec-Fetch-Site: cross-site\r\n",
        "Sec-Fetch-Mode: cors\r\n",
    ] {
        let r = raw(a, req(&format!("Host: localhost:{p}\r\n{h}")).as_bytes()).unwrap();
        assert_eq!(r.status, 403, "{h}");
    }
    srv.shutdown();
}

#[test]
fn framing_is_strict() {
    let (srv, _out) = start();
    let a = srv.addrs[0];
    let p = a.port();
    let doc = r#"{"resourceLogs":[]}"#;
    let head = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Type: application/json\r\n"
    );
    let st = |extra: &str, body: &str| {
        raw(a, format!("{head}{extra}\r\n{body}").as_bytes()).map(|r| r.status)
    };
    let n = doc.len();
    assert_eq!(st(&format!("Content-Length: {n}\r\n"), doc), Some(200));
    assert_eq!(
        st(
            &format!("Content-Length: {n}\r\nContent-Length: {n}\r\n"),
            doc
        ),
        Some(400)
    );
    assert_eq!(
        st(
            &format!("Content-Length: {n}\r\nTransfer-Encoding: chunked\r\n"),
            doc
        ),
        Some(400)
    );
    assert_eq!(st("", doc), Some(400), "POST needs explicit framing");
    assert_eq!(st("Transfer-Encoding: gzip, chunked\r\n", ""), Some(400));
    assert_eq!(st("Content-Length: +5\r\n", "12345"), Some(400));
    let chunked = format!("{:x}\r\n{doc}\r\n0\r\n\r\n", n);
    assert_eq!(st("Transfer-Encoding: chunked\r\n", &chunked), Some(200));
    let ext = format!("{:x};x=1\r\n{doc}\r\n0\r\n\r\n", n);
    assert_eq!(
        st("Transfer-Encoding: chunked\r\n", &ext),
        Some(400),
        "chunk extensions are rejected"
    );
    // Bare LF line endings, whitespace before the colon, obs-fold.
    let lf = format!("POST /v1/logs HTTP/1.1\nHost: 127.0.0.1:{p}\nContent-Length: 2\n\n{{}}");
    assert_eq!(raw(a, lf.as_bytes()).map(|r| r.status), Some(400));
    assert_eq!(st("Content-Length : 2\r\n", "{}"), Some(400));
    assert_eq!(st("X: a\r\n b\r\nContent-Length: 2\r\n", "{}"), Some(400));
    // The gRPC preface is HTTP/2.
    assert_eq!(
        raw(a, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").map(|r| r.status),
        Some(400)
    );
    srv.shutdown();
}

#[test]
fn expect_100_continue_is_honoured() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    let mut s = connect(a);
    let body = logs_doc(vec![]).to_string();
    let head = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        a.port(),
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(body.as_bytes()).unwrap();
    assert_eq!(read_reply(&mut s).unwrap().status, 200);
    out.wait_for("batch", 1);
    srv.shutdown();
}

#[test]
fn keep_alive_serves_several_requests() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    let mut s = connect(a);
    let body = logs_doc(vec![]).to_string();
    for _ in 0..3 {
        let req = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            a.port(),
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let r = read_reply(&mut s).unwrap();
        assert_eq!(r.status, 200);
        assert!(r.headers.contains("keep-alive"));
    }
    assert_eq!(out.wait_for("batch", 3).len(), 3);
    // HTTP/1.0 closes.
    let r = raw(a, format!("POST /v1/logs HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}", a.port()).as_bytes());
    // `{}` isn't an OTLP document, but the connection handling is what's under test.
    assert!(r.unwrap().headers.contains("Connection: close"));
    srv.shutdown();
}

#[test]
fn an_oversized_content_length_gets_413_before_the_body() {
    let (srv, _out) = start();
    let a = srv.addrs[0];
    let mut s = connect(a);
    let head = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        a.port(),
        17 * 1024 * 1024
    );
    s.write_all(head.as_bytes()).unwrap();
    let r = read_reply(&mut s).unwrap();
    assert_eq!(r.status, 413);
    srv.shutdown();
}

#[test]
fn a_stalled_client_is_dropped_and_the_next_is_served() {
    let (srv, _out) = start();
    let a = srv.addrs[0];
    let mut slow = connect(a);
    slow.write_all(b"POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1")
        .unwrap();
    let t0 = Instant::now();
    // Dribble a byte at a time: each read succeeds, only the request deadline can end this.
    let mut closed = false;
    while t0.elapsed() < Duration::from_secs(4) {
        if slow.write_all(b"x").is_err() {
            closed = true;
            break;
        }
        slow.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut b = [0u8; 1];
        if matches!(slow.read(&mut b), Ok(0)) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        closed,
        "the request deadline should close a dribbling client"
    );
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert_eq!(post_json(a, "/v1/logs", &logs_doc(vec![])).status, 200);
    srv.shutdown();
}

#[test]
fn the_seventeenth_connection_gets_503() {
    let (srv, _out) = start_with(|c| {
        c.tunables.read_timeout = Duration::from_secs(30);
        c.tunables.idle_timeout = Duration::from_secs(30);
        c.tunables.request_deadline = Duration::from_secs(30);
    });
    let a = srv.addrs[0];
    let held: Vec<TcpStream> = (0..16).map(|_| connect(a)).collect();
    let end = Instant::now() + Duration::from_secs(10);
    while srv.connections() < 16 {
        assert!(
            Instant::now() < end,
            "only {} connections counted",
            srv.connections()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut s = connect(a);
    let r = read_reply(&mut s).expect("a 503");
    assert_eq!(r.status, 503);
    assert!(r.headers.contains("Connection: close"));
    drop(held);
    srv.shutdown();
}

#[test]
fn rejection_lines_are_rate_limited() {
    // A window that outlasts the test, so the count can't straddle two windows.
    let (srv, out) = start_with(|c| c.tunables.error_window = Duration::from_secs(3600));
    let a = srv.addrs[0];
    for _ in 0..40 {
        let _ = raw(
            a,
            format!("GET /nope HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", a.port()).as_bytes(),
        );
    }
    out.wait_for("error", 10);
    std::thread::sleep(Duration::from_millis(200));
    let errs = out.wait_for("error", 0);
    assert_eq!(errs.len(), 10, "{errs:?}");
    srv.shutdown();
}

// ── own-user check (design D3) ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn euid() -> u32 {
    cainary_net::peer_proc::euid().expect("this process's uid")
}

fn get_logs(addr: SocketAddr) -> Option<Reply> {
    raw(
        addr,
        format!(
            "GET /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        )
        .as_bytes(),
    )
}

/// The `/proc/net/tcp` parsing end to end: this process is the client, and it is us.
#[cfg(target_os = "linux")]
#[test]
fn the_system_check_serves_a_client_of_the_same_user() {
    let (srv, out) = start_with(|c| c.tunables.peer_uid = PeerUid::System);
    let a = srv.addrs[0];
    let r = post_json(
        a,
        "/v1/logs",
        &logs_doc(vec![("event.name", "tool_result")]),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    // Several in a row: each connection is looked up once, at accept.
    for _ in 0..3 {
        let doc = logs_doc(vec![("event.name", "tool_result")]);
        assert_eq!(post_json(a, "/v1/logs", &doc).status, 200);
    }
    out.wait_for("batch", 4);
    srv.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn a_fake_lookup_of_our_own_uid_is_served() {
    let (srv, _out) = start_with(|c| c.tunables.peer_uid = PeerUid::Fake(Lookup::Uid(euid())));
    assert_eq!(get_logs(srv.addrs[0]).expect("a reply").status, 405);
    srv.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn another_users_client_gets_a_403_and_one_error_line() {
    let (srv, out) =
        start_with(|c| c.tunables.peer_uid = PeerUid::Fake(Lookup::Uid(euid().wrapping_add(1))));
    let a = srv.addrs[0];
    // The request is never read: a valid POST is refused the same way and nothing is streamed.
    let mut s = connect(a);
    let body = logs_doc(vec![("event.name", "tool_result")]).to_string();
    let _ = s.write_all(
        format!(
            "POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            a.port(),
            body.len()
        )
        .as_bytes(),
    );
    let r = read_reply(&mut s).expect("a 403");
    assert_eq!(r.status, 403);
    assert!(r.headers.contains("Connection: close"), "{}", r.headers);
    let doc: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(doc["message"], PEER_REFUSED);
    assert_eq!(PEER_REFUSED, "connection from another local user refused");
    assert_eq!(
        PEER_UNCONFIRMED,
        "connection refused: couldn't confirm it comes from this user"
    );

    let errs = out.wait_for("error", 1);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0]["status"], 403);
    assert_eq!(errs[0]["message"], PEER_REFUSED);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        out.lines()
            .iter()
            .all(|v| v["type"] != "batch" && v["type"] != "alert")
    );
    srv.shutdown();
}

/// No match, two matches and an unreadable table are refused too, without blaming another user.
#[cfg(target_os = "linux")]
#[test]
fn an_unknown_or_ambiguous_client_is_refused() {
    for fake in [
        PeerUid::Fake(Lookup::NotFound),
        PeerUid::Fake(Lookup::Ambiguous),
        PeerUid::FakeUnreadable,
    ] {
        let (srv, out) = start_with(|c| c.tunables.peer_uid = fake);
        let r = get_logs(srv.addrs[0]).unwrap_or_else(|| panic!("{fake:?}: a 403"));
        assert_eq!(r.status, 403, "{fake:?}");
        assert!(r.body.contains(PEER_UNCONFIRMED), "{fake:?}: {}", r.body);
        let errs = out.wait_for("error", 1);
        assert_eq!(errs.len(), 1, "{fake:?}");
        assert_eq!(errs[0]["message"], PEER_UNCONFIRMED, "{fake:?}");
        srv.shutdown();
    }
}

#[test]
fn the_check_can_be_off_for_the_tests() {
    let (srv, _out) = start_with(|c| c.tunables.peer_uid = PeerUid::Off);
    assert_eq!(get_logs(srv.addrs[0]).expect("a reply").status, 405);
    srv.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn refusals_share_the_rate_limit() {
    let (srv, out) = start_with(|c| {
        c.tunables.peer_uid = PeerUid::Fake(Lookup::Uid(euid().wrapping_add(1)));
        c.tunables.error_window = Duration::from_secs(3600);
    });
    let a = srv.addrs[0];
    for _ in 0..40 {
        let _ = get_logs(a);
    }
    out.wait_for("error", 10);
    std::thread::sleep(Duration::from_millis(200));
    let errs = out.wait_for("error", 0);
    assert_eq!(errs.len(), 10, "{errs:?}");
    assert!(errs.iter().all(|e| e["message"] == PEER_REFUSED));
    srv.shutdown();
}

#[test]
fn the_log_file_equals_the_stream() {
    let dir = std::env::temp_dir().join(format!("cainary-net-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("logs/out.jsonl");
    let log = LogFile::open(&path, 10 << 20, 3).unwrap();
    let (srv, out) = start_with(|c| c.log = Some(log));
    let a = srv.addrs[0];
    post_json(
        a,
        "/v1/logs",
        &logs_doc(vec![
            ("event.name", "tool_result"),
            ("m", "bob@example-corp.com"),
        ]),
    );
    let _ = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/x-protobuf\r\n",
        b"x",
    );
    out.wait_for("alert", 1);
    out.wait_for("error", 1);
    srv.shutdown();
    let file = std::fs::read_to_string(&path).unwrap();
    assert_eq!(file, out.text());
    assert!(!file.contains("bob@example-corp.com"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(dir.join("logs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn text_mode_still_writes_json_to_the_log_file() {
    let dir = std::env::temp_dir().join(format!("cainary-net-it-text-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("out.jsonl");
    let log = LogFile::open(&path, 10 << 20, 3).unwrap();
    let (srv, out) = start_with(|c| {
        c.json = false;
        c.log = Some(log);
    });
    post_json(
        srv.addrs[0],
        "/v1/logs",
        &logs_doc(vec![("event.name", "tool_result")]),
    );
    let end = Instant::now() + Duration::from_secs(5);
    while !out.text().contains("──") && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    srv.shutdown();
    let file = std::fs::read_to_string(&path).unwrap();
    let types: Vec<String> = file
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(types, ["hello", "batch"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ── the binary ─────────────────────────────────────────────────────────────────────────────

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"))
}

#[test]
fn non_loopback_listen_is_refused_with_exit_2() {
    for ip in ["0.0.0.0", "::", "192.168.1.1", "::ffff:127.0.0.1"] {
        let out = bin()
            .args(["--listen", ip])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{ip}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains(&format!(
                "refusing to listen on {ip}: only loopback addresses (127.0.0.0/8, ::1)"
            )),
            "{err}"
        );
    }
}

fn hello_port(lines: &mut impl std::io::BufRead) -> u16 {
    let mut l = String::new();
    lines.read_line(&mut l).unwrap();
    let v: Value = serde_json::from_str(&l).unwrap();
    assert_eq!(v["type"], "hello");
    v["listen"][0]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn once_exits_zero_after_the_first_batch() {
    let mut child = bin()
        .args(["--json", "--once", "--port", "0", "--listen", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let port = hello_port(&mut out);
    let a: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let r = post_json(
        a,
        "/v1/logs",
        &logs_doc(vec![("event.name", "tool_result")]),
    );
    assert_eq!(
        r.status, 200,
        "the response is written before the process can exit"
    );
    let mut rest = String::new();
    out.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("\"type\":\"batch\""));
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn closing_stdin_exits_within_a_second() {
    let mut child = bin()
        .args([
            "--json",
            "--exit-on-stdin-eof",
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let _ = hello_port(&mut out);
    drop(child.stdin.take());
    let t0 = Instant::now();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(t0.elapsed() < Duration::from_secs(1));
}

#[test]
fn config_stdin_takes_patterns_and_stays_open_as_the_lifeline() {
    let mut child = bin()
        .args([
            "--json",
            "--config-stdin",
            "--no-default-red-flags",
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"{\"v\":1,\"redFlags\":[{\"name\":\"customer\",\"kind\":\"text\",\"pattern\":\"acme-internal\",\"caseSensitive\":false}]}\n").unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut l = String::new();
    out.read_line(&mut l).unwrap();
    let hello: Value = serde_json::from_str(&l).unwrap();
    assert_eq!(hello["redFlags"][0]["name"], "customer");
    assert_eq!(hello["redFlags"].as_array().unwrap().len(), 1);
    let port: u16 = hello["listen"][0]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let a: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert_eq!(
        post_json(
            a,
            "/v1/logs",
            &logs_doc(vec![("event.name", "x"), ("k", "the ACME-Internal plan")])
        )
        .status,
        200
    );
    let mut seen = String::new();
    for _ in 0..2 {
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        seen.push_str(&l);
    }
    assert!(seen.contains("\"pattern\":\"customer\""), "{seen}");
    assert!(!seen.contains("ACME-Internal"));
    drop(stdin);
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn a_bad_stdin_config_exits_2_without_echoing_it() {
    let mut child = bin()
        .args(["--config-stdin", "--port", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"{\"v\":1,\"redFlags\":[{\"name\":\"a\",\"pattern\":\"SECRET-TEXT\",\"bogus\":1}]}\n",
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("SECRET-TEXT"));
}

#[test]
fn show_values_warns_on_stderr() {
    let child = bin()
        .args([
            "--show-values",
            "--once",
            "--json",
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
            "--log-file",
        ])
        .arg(std::env::temp_dir().join(format!("cainary-net-warn-{}.jsonl", std::process::id())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let mut child = child;
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("warning: --show-values prints attribute values unmasked (emails, commands and any secrets in them); they are also written to "), "{err}");
    let _ = std::fs::remove_file(
        std::env::temp_dir().join(format!("cainary-net-warn-{}.jsonl", std::process::id())),
    );
}

#[test]
fn port_in_use_is_exit_1() {
    let (srv, _out) = start();
    let port = srv.port;
    let out = bin()
        .args(["--port", &port.to_string(), "--listen", "127.0.0.1"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "port {port} is in use (another collector?); try --port {}",
            port + 1
        )),
        "{err}"
    );
    srv.shutdown();
}

#[test]
fn version_help_and_presets() {
    let out = bin().arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("cainary-otel-debug "));
    let out = bin().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("Point an agent at it."));
    let out = bin().arg("--list-presets").output().unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(t.contains("email") && t.contains("ipv4") && t.contains("off"));
    assert_eq!(bin().arg("--nope").output().unwrap().status.code(), Some(2));
}

#[test]
fn the_default_binds_v4_then_v6_on_the_same_port() {
    let (srv, out) = start_with(|c| c.listen.clear());
    assert_eq!(srv.addrs[0].ip().to_string(), "127.0.0.1");
    let hello = &out.wait_for("hello", 1)[0];
    let listen = hello["listen"].as_array().unwrap();
    assert!(listen.len() >= 2, "{listen:?}");
    if srv.addrs.len() == 2 {
        assert_eq!(srv.addrs[1].to_string(), format!("[::1]:{}", srv.port));
        // Node resolves localhost to ::1 first, and Claude Code's default endpoint is localhost.
        let r = raw(
            srv.addrs[1],
            format!(
                "POST /v1/logs HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{{\"resourceLogs\":[]}}",
                srv.port
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(r.status, 200);
    } else {
        assert!(
            listen[1].as_str().unwrap().contains("not available"),
            "{listen:?}"
        );
    }
    srv.shutdown();
}

// ── goldens ────────────────────────────────────────────────────────────────────────────────

fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../cainary-core/tests/otel-payloads")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The stream for one fixture: hello, batch, alerts. `ts`, `generator` and the port are masked.
fn golden_text(out: &Buf, port: u16) -> String {
    let mut s = String::new();
    for mut v in out.lines() {
        v["ts"] = json!("<ts>");
        if v["type"] == "hello" {
            v["generator"] = json!("<generator>");
        }
        s.push_str(&v.to_string().replace(&port.to_string(), "<port>"));
        s.push('\n');
    }
    s
}

fn check_golden(name: &str, fixture_rel: &str, path: &str, batches: usize) {
    let (srv, out) = start();
    let r = post_with(
        srv.addrs[0],
        path,
        "Content-Type: application/json\r\n",
        &fixture(fixture_rel),
    )
    .expect("a reply");
    assert_eq!((r.status, r.body.as_str()), (200, "{}"), "{name}");
    out.wait_for("batch", batches);
    let got = golden_text(&out, srv.port);
    srv.shutdown();
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.jsonl"));
    if std::env::var_os("CAINARY_BLESS").is_some() {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("{}: {e} (run with CAINARY_BLESS=1)", file.display()));
    assert!(
        got == want,
        "{name} differs from {}; re-bless with CAINARY_BLESS=1",
        file.display()
    );
}

#[test]
fn golden_claude_code_logs() {
    check_golden(
        "claude-code-2.1.316.logs",
        "claude-code-2.1.316/logs.json",
        "/v1/logs",
        1,
    );
}

#[test]
fn golden_claude_code_metrics() {
    check_golden(
        "claude-code-2.1.316.metrics",
        "claude-code-2.1.316/metrics.json",
        "/v1/metrics",
        1,
    );
}

#[test]
fn golden_codex_logs() {
    check_golden(
        "codex-0.166.0.logs",
        "codex-0.166.0/logs.json",
        "/v1/logs",
        1,
    );
}

#[test]
fn fixtures_classify_against_their_catalogs_and_stream_masked() {
    let (srv, out) = start();
    let a = srv.addrs[0];
    for (rel, path) in [
        ("claude-code-2.1.316/logs.json", "/v1/logs"),
        ("claude-code-2.1.316/metrics.json", "/v1/metrics"),
        ("codex-0.166.0/logs.json", "/v1/logs"),
    ] {
        let r = post_with(a, path, "Content-Type: application/json\r\n", &fixture(rel)).unwrap();
        assert_eq!(r.status, 200, "{rel}");
    }
    let batches = out.wait_for("batch", 3);
    assert_eq!(batches.len(), 3);
    let by = |catalog: &str, signal: &str| {
        batches
            .iter()
            .find(|b| b["catalog"] == catalog && b["signal"] == signal)
            .unwrap_or_else(|| panic!("no {catalog} {signal} batch"))
            .clone()
    };
    let cl = by("claude-code 2.1.316", "logs");
    assert_eq!(cl["vendor"], "claude-code");
    assert_eq!(
        cl["notInCatalog"], 0,
        "the drift test keeps the fixtures inside the catalog"
    );
    assert!(
        cl["summary"]["identity"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "user.email")
    );
    let tool_result = cl["summary"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "claude_code.tool_result")
        .unwrap();
    assert_eq!(tool_result["known"], true);
    assert!(tool_result["what"].is_string());
    let content = tool_result["attrs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == "tool_parameters")
        .unwrap();
    assert_eq!(content["group"], "content");
    assert_eq!(content["flag"], "OTEL_LOG_TOOL_DETAILS");
    let m = by("claude-code 2.1.316", "metrics");
    let rec = &m["resources"][0]["scopes"][0]["records"][0];
    assert_eq!(rec["kind"], "metric");
    assert!(rec["metricType"].is_string());
    let cx = by("codex 0.166.0", "logs");
    assert_eq!(cx["vendor"], "codex");
    assert_eq!(cx["notInCatalog"], 0);
    // Sanitized fixtures hold placeholders: nothing may alert.
    assert!(out.lines().iter().all(|l| l["type"] != "alert"));
    srv.shutdown();
}

/// Port `n` is privileged for anyone but root; skip where it isn't (root, or a lowered sysctl).
fn port_is_privileged(n: u32) -> bool {
    let start: u32 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1024);
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    cfg!(target_os = "linux") && !root && start > n
}

#[test]
fn a_refused_privileged_port_is_a_short_error_and_a_note_on_stderr() {
    if !port_is_privileged(1) {
        return;
    }
    let out = bin()
        .args(["--port", "1", "--listen", "127.0.0.1", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    // --json: the error is a line on stdout, with the contract's envelope.
    let line = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        (v["v"].clone(), v["type"].clone(), v["source"].clone()),
        (json!(1), json!("error"), json!("listen"))
    );
    assert_eq!(
        v["message"],
        "can't listen on 127.0.0.1:1: permission denied"
    );
    assert_eq!(
        (v["code"].clone(), v["port"].clone()),
        (json!("port-privileged"), json!(1))
    );
    assert_eq!(line.lines().count(), 1);
    // The note is on stderr and offers the ways, concrete for this run.
    let err = String::from_utf8_lossy(&out.stderr);
    for needle in [
        "Port 1 is privileged on Linux",
        "1. Listen on an unprivileged port",
        "--port 8001",
        "2. In the cAInary tray, use \"Open port 1\"",
        "cainary-bind-helper",
        "3. Administrators only: redirect 1",
        "sudo nft delete table inet cainary_port_redirect",
        "4. Administrators only, system-wide",
        "sudo sysctl net.ipv4.ip_unprivileged_port_start=1024",
    ] {
        assert!(err.contains(needle), "{needle}\n{err}");
    }
    assert!(!err.contains("$(") && !err.contains("setcap"));
    // Without --json the error is text on stderr and nothing is on stdout.
    let out = bin()
        .args(["--port", "1", "--listen", "127.0.0.1"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("cainary-otel-debug: can't listen on 127.0.0.1:1: permission denied")
    );
}

/// The one `error` line a failed `--json` start prints on stdout: parsed, with nothing else there.
fn only_error_line(out: &std::process::Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 1, "{text}");
    let v: Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(
        (v["v"].clone(), v["type"].clone()),
        (json!(1), json!("error"))
    );
    v
}

#[test]
fn port_80_refused_is_port_privileged_with_the_port() {
    if !port_is_privileged(80) {
        return;
    }
    let out = bin()
        .args(["--port", "80", "--listen", "127.0.0.1", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = only_error_line(&out);
    assert_eq!(v["source"], "listen");
    assert_eq!(v["code"], "port-privileged");
    assert_eq!(v["port"], 80);
}

#[test]
fn a_busy_port_is_port_in_use_with_the_port() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let out = bin()
        .args([
            "--port",
            &port.to_string(),
            "--listen",
            "127.0.0.1",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = only_error_line(&out);
    assert_eq!(v["source"], "listen");
    assert_eq!(v["code"], "port-in-use");
    assert_eq!(v["port"], port);
    assert!(v.get("port").is_some());
    // Text mode is unchanged: stderr only.
    let out = bin()
        .args(["--port", &port.to_string(), "--listen", "127.0.0.1"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is in use"));
}

#[test]
fn every_fatal_startup_path_prints_one_coded_error_line_under_json() {
    let cases: [(&[&str], i32, &str); 5] = [
        (&["--tls", "--json"], 2, "tls-no-host"),
        (&["--bogus-flag", "--json"], 2, "usage"),
        (&["--json", "--port", "70000"], 2, "usage"),
        (&["--json", "--listen", "0.0.0.0"], 2, "usage"),
        (
            &[
                "--json",
                "--red-flags",
                "/nonexistent/cainary-red-flags.toml",
            ],
            1,
            "config",
        ),
    ];
    for (args, exit, code) in cases {
        let out = bin().args(args).stdin(Stdio::null()).output().unwrap();
        assert_eq!(out.status.code(), Some(exit), "{args:?}");
        let v = only_error_line(&out);
        assert_eq!(v["source"], "startup", "{args:?}");
        assert_eq!(v["code"], code, "{args:?}");
        assert!(v.get("port").is_none());
        assert!(!out.stderr.is_empty(), "the text stays on stderr: {args:?}");
    }
    // Without --json nothing is on stdout.
    let out = bin().args(["--tls"]).stdin(Stdio::null()).output().unwrap();
    assert!(out.stdout.is_empty());
}

#[cfg(not(feature = "tls"))]
#[test]
fn tls_in_a_build_without_it_is_tls_unsupported() {
    let out = bin()
        .args(["--tls", "--tls-host", "example.com", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(only_error_line(&out)["code"], "tls-unsupported");
}

#[cfg(target_os = "linux")]
#[test]
fn capabilities_are_dropped_after_bind_in_every_build() {
    let (srv, _out) = start();
    assert!(srv.caps_dropped);
    srv.shutdown();
}

/// Every thread of a running collector has no_new_privs set and no capabilities: the drop ran in
/// the thread that bound and in the stdin thread, and the rest inherited it.
#[cfg(target_os = "linux")]
#[test]
fn every_thread_of_the_running_collector_is_dropped() {
    let mut child = bin()
        .args([
            "--json",
            "--exit-on-stdin-eof",
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let _ = hello_port(&mut out);
    let mut seen = 0;
    for task in std::fs::read_dir(format!("/proc/{}/task", child.id())).unwrap() {
        let st = std::fs::read_to_string(task.unwrap().path().join("status")).unwrap();
        for key in ["CapInh:", "CapPrm:", "CapEff:"] {
            let l = st.lines().find(|l| l.starts_with(key)).unwrap();
            assert!(l[key.len()..].trim().chars().all(|c| c == '0'), "{l}");
        }
        assert!(st.lines().any(|l| l.trim_end() == "NoNewPrivs:\t1"), "{st}");
        seen += 1;
    }
    assert!(seen >= 3, "main, stdin and output threads at least: {seen}");
    drop(child.stdin.take());
    let _ = child.wait();
}

#[test]
fn commands_that_never_bind_still_work() {
    for args in [
        &["--version"][..],
        &["--list-presets"],
        &["--trust-status", "--json"],
    ] {
        let out = bin().args(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            out.status.code().is_some_and(|c| c <= 2)
                && !out.stderr.starts_with(b"cainary-otel-debug: can't drop"),
            "{args:?}"
        );
    }
}

// ---- --listen-fd: sockets inherited from the parent (design §12.1) ----

mod listen_fd {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Output};

    /// A raw TCP/UDP socket, optionally listening, bound to `ip:port` (port 0 picks one).
    /// `v6only` is set before the bind when given; `None` leaves the system default.
    fn sock(
        v6: bool,
        ty: libc::c_int,
        ip: &str,
        port: u16,
        listen: bool,
        v6only: Option<bool>,
    ) -> Option<(OwnedFd, u16)> {
        let af = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        // SAFETY: plain socket calls on a descriptor owned right here; structs are zeroed
        // and live for each call.
        unsafe {
            let fd = libc::socket(af, ty | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0, "socket");
            let owned = OwnedFd::from_raw_fd(fd);
            // Only so a test can hold two listeners of one family on one port.
            let one: libc::c_int = 1;
            let r = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                4,
            );
            assert_eq!(r, 0);
            if let (true, Some(on)) = (v6, v6only) {
                let v = on as libc::c_int;
                let r = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &v as *const _ as *const libc::c_void,
                    4,
                );
                assert_eq!(r, 0);
            }
            let r = if v6 {
                let mut a: libc::sockaddr_in6 = std::mem::zeroed();
                a.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                a.sin6_port = port.to_be();
                a.sin6_addr.s6_addr = ip.parse::<std::net::Ipv6Addr>().unwrap().octets();
                libc::bind(
                    fd,
                    &a as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&a) as u32,
                )
            } else {
                let mut a: libc::sockaddr_in = std::mem::zeroed();
                a.sin_family = libc::AF_INET as libc::sa_family_t;
                a.sin_port = port.to_be();
                a.sin_addr.s_addr =
                    u32::from_ne_bytes(ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
                libc::bind(
                    fd,
                    &a as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&a) as u32,
                )
            };
            if r != 0 {
                return None;
            }
            if listen && ty == libc::SOCK_STREAM {
                assert_eq!(libc::listen(fd, 16), 0);
            }
            let mut ss: libc::sockaddr_storage = std::mem::zeroed();
            let mut len = std::mem::size_of_val(&ss) as u32;
            assert_eq!(
                libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len),
                0
            );
            let port = if v6 {
                u16::from_be((*(&ss as *const _ as *const libc::sockaddr_in6)).sin6_port)
            } else {
                u16::from_be((*(&ss as *const _ as *const libc::sockaddr_in)).sin_port)
            };
            Some((owned, port))
        }
    }

    fn tcp4() -> (OwnedFd, u16) {
        sock(false, libc::SOCK_STREAM, "127.0.0.1", 0, true, None).unwrap()
    }

    /// Spawns the collector with `fds[i]` placed at descriptor `3 + i` (and nothing else extra).
    fn spawn(args: &[&str], fds: &[&OwnedFd]) -> Child {
        // Temporaries above 100 so no source can be clobbered by a target slot.
        let temps: Vec<RawFd> = fds
            .iter()
            .map(|f| {
                // SAFETY: F_DUPFD_CLOEXEC on a descriptor we hold.
                let t = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100) };
                assert!(t >= 100);
                t
            })
            .collect();
        let mut c = bin();
        c.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let moved = temps.clone();
        // SAFETY: only async-signal-safe dup2 calls, no allocation.
        unsafe {
            c.pre_exec(move || {
                for (i, t) in moved.iter().enumerate() {
                    if libc::dup2(*t, 3 + i as RawFd) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = c.spawn().unwrap();
        for t in temps {
            // SAFETY: closing the temporaries this function made.
            unsafe { libc::close(t) };
        }
        child
    }

    fn serve_hello(args: &[&str], fds: &[&OwnedFd]) -> (Child, Value) {
        let mut child = spawn(args, fds);
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        let hello: Value = serde_json::from_str(&l).unwrap_or_else(|e| panic!("hello {l:?}: {e}"));
        assert_eq!(hello["type"], "hello", "{l}");
        // Keep stdout open so the child isn't killed by a broken pipe.
        std::mem::forget(out);
        (child, hello)
    }

    /// A start that must fail with exit 2 and one `error` line; returns that line.
    fn rejected(args: &[&str], fds: &[&OwnedFd], code: &str) -> Value {
        let out: Output = spawn(args, fds).wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v = only_error_line(&out);
        assert_eq!(v["code"], code, "{v}");
        assert_eq!(v["source"], "startup");
        v
    }

    fn get_ok(addr: &str) {
        let r = post_json(
            addr.parse().unwrap(),
            "/v1/logs",
            &logs_doc(vec![("event.name", "tool_result")]),
        );
        assert_eq!(r.status, 200, "{addr}");
    }

    #[test]
    fn listen_fd_serves() {
        let (fd, port) = tcp4();
        let p = port.to_string();
        let (mut child, hello) = serve_hello(&["--json", "--port", &p, "--listen-fd", "3"], &[&fd]);
        assert_eq!(hello["listen"], json!([format!("127.0.0.1:{port}")]));
        get_ok(&format!("127.0.0.1:{port}"));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn listen_fd_serves_v4_and_v6() {
        let (fd4, port) = tcp4();
        let Some((fd6, _)) = sock(true, libc::SOCK_STREAM, "::1", port, true, Some(true)) else {
            eprintln!("no IPv6 loopback here; skipped");
            return;
        };
        let p = port.to_string();
        let (mut child, hello) = serve_hello(
            &[
                "--json",
                "--port",
                &p,
                "--listen-fd",
                "3",
                "--listen-fd",
                "4",
            ],
            &[&fd4, &fd6],
        );
        assert_eq!(
            hello["listen"],
            json!([format!("127.0.0.1:{port}"), format!("[::1]:{port}")])
        );
        get_ok(&format!("127.0.0.1:{port}"));
        get_ok(&format!("[::1]:{port}"));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn listen_fd_udp() {
        let (fd, port) = sock(false, libc::SOCK_DGRAM, "127.0.0.1", 0, false, None).unwrap();
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_wildcard() {
        let (fd, port) = sock(false, libc::SOCK_STREAM, "0.0.0.0", 0, true, None).unwrap();
        // The wildcard socket owns the port on every address: a fallback bind would fail with
        // port-in-use (exit 1), so exit 2 `listen-fd` shows nothing tried to bind.
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_not_listening() {
        let (fd, port) = sock(false, libc::SOCK_STREAM, "127.0.0.1", 0, false, None).unwrap();
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_port_mismatch() {
        let (fd, port) = tcp4();
        let other = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert_ne!(other, port);
        rejected(
            &["--json", "--port", &other.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
        // Nothing bound the requested port on its own account.
        std::net::TcpListener::bind(("127.0.0.1", other)).expect("the port stayed free");
    }

    #[test]
    fn listen_fd_not_a_socket() {
        // Descriptor 3 is closed in the child: not an open descriptor.
        rejected(
            &["--json", "--port", "40123", "--listen-fd", "3"],
            &[],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_below_3() {
        let (fd, port) = tcp4();
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "2"],
            &[&fd],
            "usage",
        );
    }

    #[test]
    fn listen_fd_two_same_family() {
        let (a, port) = tcp4();
        // Two IPv4 listeners on one port (the test sockets use SO_REUSEPORT; the collector never does).
        let (b, _) = sock(false, libc::SOCK_STREAM, "127.0.0.1", port, true, None).unwrap();
        rejected(
            &[
                "--json",
                "--port",
                &port.to_string(),
                "--listen-fd",
                "3",
                "--listen-fd",
                "4",
            ],
            &[&a, &b],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_with_listen_conflict() {
        let (fd, port) = tcp4();
        rejected(
            &[
                "--json",
                "--port",
                &port.to_string(),
                "--listen-fd",
                "3",
                "--listen",
                "127.0.0.1",
            ],
            &[&fd],
            "usage",
        );
    }

    #[test]
    fn listen_fd_duplicate_number() {
        let (fd, port) = tcp4();
        rejected(
            &[
                "--json",
                "--port",
                &port.to_string(),
                "--listen-fd",
                "3",
                "--listen-fd",
                "3",
            ],
            &[&fd],
            "usage",
        );
    }

    #[test]
    fn listen_fd_v6_without_v6only() {
        let Some((fd, port)) = sock(true, libc::SOCK_STREAM, "::1", 0, true, Some(false)) else {
            eprintln!("no IPv6 loopback here; skipped");
            return;
        };
        // Linux turns IPV6_V6ONLY on for any bind to a non-wildcard address, so the flag can't
        // be left off on `::1` there; the check stays as defence in depth for kernels that can.
        let mut v: libc::c_int = 0;
        let mut len = 4u32;
        // SAFETY: `v` and `len` are live and sized for the call.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut v as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(r, 0);
        if v != 0 {
            eprintln!("the kernel forces IPV6_V6ONLY on a ::1 bind; skipped");
            return;
        }
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_non_tcp_stream() {
        // SCTP one-to-one style: SOCK_STREAM, but not TCP.
        // SAFETY: plain socket calls on a descriptor owned right here.
        let (fd, port) = unsafe {
            let fd = libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_SCTP,
            );
            if fd < 0 {
                eprintln!("no SCTP in this kernel; skipped");
                return;
            }
            let owned = OwnedFd::from_raw_fd(fd);
            let mut a: libc::sockaddr_in = std::mem::zeroed();
            a.sin_family = libc::AF_INET as libc::sa_family_t;
            a.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let ok = libc::bind(
                fd,
                &a as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&a) as u32,
            ) == 0
                && libc::listen(fd, 4) == 0;
            if !ok {
                eprintln!("SCTP can't listen here; skipped");
                return;
            }
            let mut len = std::mem::size_of_val(&a) as u32;
            libc::getsockname(fd, &mut a as *mut _ as *mut libc::sockaddr, &mut len);
            (owned, u16::from_be(a.sin_port))
        };
        rejected(
            &["--json", "--port", &port.to_string(), "--listen-fd", "3"],
            &[&fd],
            "listen-fd",
        );
    }

    #[test]
    fn listen_fd_needs_port() {
        let (fd, _) = tcp4();
        rejected(&["--json", "--listen-fd", "3"], &[&fd], "usage");
    }
}
