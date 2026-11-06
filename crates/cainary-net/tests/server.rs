//! Integration tests: a real listener on loopback port 0, driven with `std::net::TcpStream`.

use cainary_net::logfile::LogFile;
use cainary_net::redflag::{Matcher, presets};
use cainary_net::server::{self, Config, Server};
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
                let body = String::from_utf8_lossy(&data[i + 4..i + 4 + len]).into_owned();
                return Some(Reply {
                    status,
                    headers: head,
                    body,
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
    let proto = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/x-protobuf\r\n",
        b"\x0a\x00",
    )
    .unwrap();
    assert_eq!(proto.status, 415);
    assert!(
        proto.body.contains("OTEL_EXPORTER_OTLP_PROTOCOL") && proto.body.contains("\"code\":3")
    );
    let gz = post_with(
        a,
        "/v1/logs",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        b"\x1f\x8b",
    )
    .unwrap();
    assert_eq!(gz.status, 415);
    assert_eq!(
        gz.body,
        r#"{"code":3,"message":"compressed bodies aren't supported; unset OTEL_EXPORTER_OTLP_COMPRESSION or set it to none"}"#
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
