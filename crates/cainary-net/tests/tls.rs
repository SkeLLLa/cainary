//! The endpoint takeover end to end (design §16.6, §16.7): a rustls client that trusts only the
//! certificate file the collector wrote. Everything uses `--port 0`-style ephemeral ports; 443 is
//! never bound.
#![cfg(feature = "tls")]

mod formats;

use cainary_net::decode::TYPE_MESSAGE;
use cainary_net::peer::Lookup;
use cainary_net::redflag::{Matcher, presets};
use cainary_net::server::{self, Config, PEER_REFUSED, PEER_UNCONFIRMED, PeerUid, Server, TlsRun};
use cainary_net::tls::Tls;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HOST: &str = "otel.example-corp.test";
const OTHER: &str = "logs.example-corp.test";

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
    fn lines(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
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

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cainary-tls-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Run {
    srv: Server,
    out: Buf,
    ca_pem: String,
    dir: PathBuf,
}

fn start_with(tag: &str, f: impl FnOnce(&mut Config)) -> Run {
    let dir = tmp(tag);
    let hosts = vec![HOST.to_string(), OTHER.to_string()];
    let tls = Tls::start(&hosts, &dir).expect("the CA publishes");
    let out = Buf::default();
    let mut cfg = Config::new(Box::new(out.clone()));
    cfg.listen = vec!["127.0.0.1".into()];
    cfg.matcher = Arc::new(
        Matcher::new(
            presets::PRESETS
                .iter()
                .filter(|p| p.default_on)
                .map(presets::Preset::pattern)
                .collect(),
        )
        .unwrap(),
    );
    cfg.tunables.read_timeout = Duration::from_millis(300);
    cfg.tunables.first_request_deadline = Duration::from_secs(2);
    cfg.tunables.idle_timeout = Duration::from_secs(3);
    cfg.tls = Some(TlsRun {
        tls,
        public_port: 443,
    });
    f(&mut cfg);
    let ca_pem = std::fs::read_to_string(dir.join("otel-debug-ca.pem")).unwrap();
    let srv = server::run(cfg).expect("server starts");
    Run {
        srv,
        out,
        ca_pem,
        dir,
    }
}

fn start(tag: &str) -> Run {
    start_with(tag, |_| {})
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(ca_pem: &str, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

type Tls_ = StreamOwned<ClientConnection, TcpStream>;

fn connect(addr: SocketAddr, cfg: &Arc<ClientConfig>, sni: &str) -> Result<Tls_, String> {
    let tcp = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(Arc::clone(cfg), name).map_err(|e| e.to_string())?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(|e| e.to_string())?;
    }
    Ok(s)
}

struct Reply {
    status: u16,
    body: String,
    bytes: Vec<u8>,
}

fn read_reply(s: &mut Tls_) -> Option<Reply> {
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
                let body = String::from_utf8_lossy(&bytes).into_owned();
                return Some(Reply {
                    status,
                    body,
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

fn request(path: &str, host_header: Option<&str>, extra: &str, body: &[u8]) -> Vec<u8> {
    request_as(
        path,
        host_header,
        &format!("Content-Type: application/json\r\n{extra}"),
        body,
    )
}

/// `request` with the content headers spelled out.
fn request_as(path: &str, host_header: Option<&str>, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("POST {path} HTTP/1.1\r\n");
    if let Some(h) = host_header {
        r.push_str(&format!("Host: {h}\r\n"));
    }
    r.push_str(&format!("{headers}Content-Length: {}\r\n\r\n", body.len()));
    let mut v = r.into_bytes();
    v.extend_from_slice(body);
    v
}

fn post(run: &Run, sni: &str, host: Option<&str>, path: &str, body: &[u8]) -> Option<Reply> {
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let mut s = connect(run.srv.addrs[0], &cfg, sni).ok()?;
    s.write_all(&request(path, host, "", body)).ok()?;
    read_reply(&mut s)
}

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cainary-core/tests/otel-payloads")
            .join(rel),
    )
    .unwrap()
}

fn host_port(run: &Run, host: &str) -> String {
    format!("{host}:{}", run.srv.port)
}

#[test]
fn fixtures_over_tls_to_organization_style_paths() {
    let run = start("e2e");
    let cases = [
        (
            "claude-code-2.1.316/logs.json",
            "/_x/claude_code/logs",
            "claude-code 2.1.316",
            "logs",
        ),
        (
            "claude-code-2.1.316/metrics.json",
            "/_x/claude_code/v1/metrics",
            "claude-code 2.1.316",
            "metrics",
        ),
        // No signal in the path: the JSON root key decides.
        (
            "codex-0.166.0/logs.json",
            "/anything/else?x=1",
            "codex 0.166.0",
            "logs",
        ),
    ];
    for (rel, path, _, _) in cases {
        let r = post(
            &run,
            HOST,
            Some(&host_port(&run, HOST)),
            path,
            &fixture(rel),
        )
        .expect("a reply");
        assert_eq!((r.status, r.body.as_str()), (200, "{}"), "{path}");
    }
    let batches = run.out.wait_for("batch", 3);
    assert_eq!(batches.len(), 3);
    for (i, (_, path, catalog, signal)) in cases.iter().enumerate() {
        let b = &batches[i];
        assert_eq!(b["catalog"], *catalog);
        assert_eq!(b["signal"], *signal);
        assert_eq!(b["host"], HOST);
        // Paths are never printed: the canonical one or a marker.
        assert_eq!(b["path"], "<custom path>", "{path}");
        assert_eq!(b["notInCatalog"], 0);
    }
    let text = run.out.text();
    for secret in ["_x/claude_code", "anything/else", "x=1"] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
    // A canonical path keeps its name.
    let r = post(
        &run,
        HOST,
        Some(&host_port(&run, HOST)),
        "/v1/logs",
        &fixture("codex-0.166.0/logs.json"),
    )
    .unwrap();
    assert_eq!(r.status, 200);
    let b = run.out.wait_for("batch", 4);
    assert_eq!(b[3]["path"], "/v1/logs");
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn the_hello_describes_the_takeover() {
    let run = start("hello");
    let h = &run.out.wait_for("hello", 1)[0];
    assert_eq!(h["mode"], "tls-receiver");
    assert_eq!(h["tls"]["hosts"], json!([HOST, OTHER]));
    let path = h["tls"]["ca"]["path"].as_str().unwrap();
    assert!(path.ends_with("otel-debug-ca.pem"));
    assert_eq!(h["tls"]["ca"]["sha256"].as_str().unwrap().len(), 64);
    let takeover = h["setup"]["takeover"].as_array().unwrap();
    let all: Vec<&str> = takeover.iter().map(|l| l.as_str().unwrap()).collect();
    let all = all.join("\n");
    assert!(all.contains(&format!("127.0.0.1 {HOST}")));
    assert!(all.contains("NODE_EXTRA_CA_CERTS="));
    assert!(all.contains("Nothing is forwarded"));
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn only_configured_names_complete_a_handshake() {
    let run = start("sni");
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let a = run.srv.addrs[0];
    // Unlisted name: refused (the client sees a failed handshake).
    assert!(connect(a, &cfg, "evil.example.test").is_err());
    // No SNI at all (an IP address as the server name sends none).
    assert!(connect(a, &cfg, "127.0.0.1").is_err());
    // A configured name works, in any case.
    assert!(connect(a, &cfg, "OTEL.example-corp.test").is_ok());
    let errs = run.out.wait_for("error", 2);
    assert!(errs.len() >= 2);
    for e in &errs {
        assert_eq!(e["source"], "tls");
        let m = e["message"].as_str().unwrap();
        assert!(m.starts_with("tls handshake refused"), "{m}");
        assert!(!m.contains("evil") && !run.out.text().contains("evil.example.test"));
    }
    let msgs: Vec<&str> = errs
        .iter()
        .map(|e| e["message"].as_str().unwrap())
        .collect();
    assert!(
        msgs.iter().any(|m| m.contains("SNI not in --tls-host")),
        "{msgs:?}"
    );
    assert!(msgs.iter().any(|m| m.contains("no SNI")), "{msgs:?}");
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn alpn_is_http11_only() {
    let run = start("alpn");
    let a = run.srv.addrs[0];
    assert!(connect(a, &client_config(&run.ca_pem, &[b"h2"]), HOST).is_err());
    assert!(connect(a, &client_config(&run.ca_pem, &[b"h2", b"http/1.1"]), HOST).is_ok());
    let s = connect(a, &client_config(&run.ca_pem, &[]), HOST).expect("no ALPN is allowed");
    drop(s);
    let mut ok = connect(a, &client_config(&run.ca_pem, &[b"h2", b"http/1.1"]), HOST).unwrap();
    assert_eq!(ok.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    drop(ok.flush());
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn plain_http_to_the_tls_port_fails_cleanly() {
    let run = start("plain");
    let mut s = TcpStream::connect(run.srv.addrs[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: otel.example-corp.test\r\n\r\n")
        .unwrap();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    // Closed (possibly after a TLS alert); never an HTTP answer.
    assert!(!String::from_utf8_lossy(&got).contains("HTTP/1.1"));
    let errs = run.out.wait_for("error", 1);
    assert_eq!(errs[0]["source"], "tls");
    assert!(
        errs[0]["message"]
            .as_str()
            .unwrap()
            .contains("not TLS (plain HTTP to the TLS port?)")
    );
    // The server still serves.
    assert_eq!(
        post(
            &run,
            HOST,
            Some(&host_port(&run, HOST)),
            "/v1/logs",
            &fixture("codex-0.166.0/logs.json")
        )
        .unwrap()
        .status,
        200
    );
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn host_must_equal_the_sni_and_a_reachable_port() {
    let run = start("host");
    let body = fixture("codex-0.166.0/logs.json");
    let st =
        |sni: &str, host: Option<&str>| post(&run, sni, host, "/v1/logs", &body).map(|r| r.status);
    let p = run.srv.port;
    assert_eq!(st(HOST, Some(&format!("{HOST}:{p}"))), Some(200));
    assert_eq!(
        st(HOST, Some(HOST)),
        Some(200),
        "no port means 443, which the redirect serves"
    );
    assert_eq!(st(HOST, Some(&format!("{HOST}:443"))), Some(200));
    assert_eq!(
        st(HOST, Some(&format!("{}:{p}", HOST.to_uppercase()))),
        Some(200)
    );
    // Another configured host, a loopback alias, another port, junk.
    assert_eq!(st(HOST, Some(&format!("{OTHER}:{p}"))), Some(421));
    assert_eq!(
        st(HOST, Some(&format!("127.0.0.1:{p}"))),
        Some(400),
        "an IP isn't a DNS name here"
    );
    assert_eq!(st(HOST, Some(&format!("localhost:{p}"))), Some(400));
    assert_eq!(st(HOST, Some(&format!("{HOST}:1234"))), Some(421));
    assert_eq!(st(HOST, Some(&format!("{HOST}:0443"))), Some(400));
    assert_eq!(st(HOST, Some(&format!("{HOST}:x"))), Some(400));
    assert_eq!(st(HOST, Some("[::1]:1")), Some(400));
    assert_eq!(st(HOST, None), Some(400));
    // Two Host headers.
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let mut s = connect(run.srv.addrs[0], &cfg, HOST).unwrap();
    s.write_all(&request(
        "/v1/logs",
        Some(HOST),
        &format!("Host: {HOST}\r\n"),
        &body,
    ))
    .unwrap();
    assert_eq!(read_reply(&mut s).unwrap().status, 400);
    // Browsers are refused here too.
    let mut s = connect(run.srv.addrs[0], &cfg, HOST).unwrap();
    s.write_all(&request(
        "/v1/logs",
        Some(&host_port(&run, HOST)),
        "Origin: https://evil.example.test\r\n",
        &body,
    ))
    .unwrap();
    assert_eq!(read_reply(&mut s).unwrap().status, 403);
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn takeover_routing_is_post_only_and_needs_one_signal() {
    let run = start("route");
    let a = run.srv.addrs[0];
    let h = host_port(&run, HOST);
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let logs = fixture("codex-0.166.0/logs.json");
    let send = |raw: Vec<u8>| {
        let mut s = connect(a, &cfg, HOST).unwrap();
        s.write_all(&raw).unwrap();
        read_reply(&mut s).map(|r| (r.status, r.body))
    };
    let get = format!("GET /v1/logs HTTP/1.1\r\nHost: {h}\r\n\r\n");
    assert_eq!(send(get.into_bytes()).unwrap().0, 405);
    let opt = format!("OPTIONS /x HTTP/1.1\r\nHost: {h}\r\n\r\n");
    assert_eq!(send(opt.into_bytes()).unwrap().0, 405);
    // A path that says metrics over a logs body, and a body with no signal in a neutral path.
    assert_eq!(
        send(request("/x/metrics", Some(&h), "", &logs)).unwrap().0,
        400
    );
    assert_eq!(
        send(request("/x/y", Some(&h), "", b"{\"a\":1}")).unwrap().0,
        400
    );
    let both = br#"{"resourceLogs":[],"resourceSpans":[]}"#;
    assert_eq!(send(request("/x/y", Some(&h), "", both)).unwrap().0, 400);
    // CONNECT and absolute-form targets are never honoured.
    let connect_req = format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {h}\r\n\r\n");
    assert_ne!(send(connect_req.into_bytes()).map(|r| r.0), Some(200));
    let abs = format!(
        "POST https://{HOST}/v1/logs HTTP/1.1\r\nHost: {h}\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    assert_eq!(send(abs.into_bytes()).unwrap().0, 400);
    // The query is ignored; the strict §14 limits still apply (br is refused, gzip is read).
    assert_eq!(
        send(request("/v1/logs?token=abc", Some(&h), "", &logs))
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        send(request(
            "/v1/logs",
            Some(&h),
            "Content-Encoding: br\r\n",
            &logs
        ))
        .unwrap()
        .0,
        415
    );
    assert_eq!(
        send(request(
            "/v1/logs",
            Some(&h),
            "Content-Encoding: gzip\r\n",
            &logs
        ))
        .unwrap()
        .0,
        400,
        "a body that isn't gzip says so"
    );
    assert!(!run.out.text().contains("token=abc"));
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn every_format_and_encoding_works_in_takeover_too() {
    let run = start("formats");
    let a = run.srv.addrs[0];
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let h = host_port(&run, HOST);
    let send = |raw: Vec<u8>| {
        let mut s = connect(a, &cfg, HOST).unwrap();
        s.write_all(&raw).unwrap();
        read_reply(&mut s).expect("a reply")
    };
    let mut sent = Vec::new();
    for p in formats::payloads() {
        // The signal comes from the path for protobuf, and from the path or the body for JSON.
        let paths = [format!("/v1/{}", p.signal), format!("/_x/org/{}", p.signal)];
        for v in formats::variants(&p) {
            for path in &paths {
                let r = send(request_as(path, Some(&h), &v.headers(), &v.body));
                assert_eq!(r.status, 200, "{} {path}: {}", v.label, r.body);
                match v.format {
                    Some(_) => assert!(r.bytes.is_empty(), "{}", v.label),
                    None => assert_eq!(r.body, "{}", "{}", v.label),
                }
                let shown = if path.starts_with("/v1/") {
                    path.as_str()
                } else {
                    "<custom path>"
                };
                sent.push((
                    p.name,
                    v.label.clone(),
                    v.body.len(),
                    v.format,
                    v.gzip,
                    shown.to_string(),
                ));
                run.out.wait_for("batch", sent.len());
            }
        }
    }
    // JSON bodies find their signal in the body, on a path that has none.
    let json = formats::payloads().remove(2);
    let r = send(request_as(
        "/anything/else",
        Some(&h),
        &formats::variants(&json)[1].headers(),
        &formats::variants(&json)[1].body,
    ));
    assert_eq!(r.status, 200);
    let batches = run.out.wait_for("batch", sent.len() + 1);
    assert_eq!(batches.len(), sent.len() + 1);
    let mut first: Option<(&str, Value)> = None;
    for ((name, label, bytes, format, gzip, path), b) in sent.iter().zip(&batches) {
        assert_eq!(b["bytes"], *bytes, "{label}");
        assert_eq!(b["format"].as_str(), *format, "{label}");
        assert_eq!(b["encoding"].as_str(), gzip.then_some("gzip"), "{label}");
        assert_eq!(b["path"], *path, "{label}");
        let mut got = formats::same(b.clone());
        got.as_object_mut().unwrap().remove("path");
        match &first {
            Some((n, want)) if n == name => {
                let diff = formats::first_diff(&got, want);
                assert!(diff.is_none(), "{label} differs: {diff:?}");
            }
            _ => first = Some((name, got)),
        }
    }
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn protobuf_in_takeover_needs_a_path_that_names_the_signal() {
    let run = start("pb-path");
    let a = run.srv.addrs[0];
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let h = host_port(&run, HOST);
    let send = |raw: Vec<u8>| {
        let mut s = connect(a, &cfg, HOST).unwrap();
        s.write_all(&raw).unwrap();
        read_reply(&mut s).expect("a reply")
    };
    let p = formats::payloads().remove(3);
    let v = &formats::variants(&p)[3];
    let r = send(request_as("/x/y", Some(&h), &v.headers(), &v.body));
    assert_eq!(r.status, 400);
    assert_eq!(
        formats::status(&r.bytes),
        (
            3,
            "can't tell which signal this is (protobuf needs a /v1/<signal> path)".to_string()
        )
    );
    // Said before the body is read or allocated, and the same with no body at all.
    let r = send(request_as("/", Some(&h), &v.headers(), b""));
    assert_eq!(r.status, 400);
    assert!(
        formats::status(&r.bytes)
            .1
            .starts_with("can't tell which signal")
    );
    // A path that names a signal works, a JSON body on the neutral path still gets a JSON answer.
    let r = send(request_as("/v1/traces", Some(&h), &v.headers(), &v.body));
    assert_eq!((r.status, r.bytes.len()), (200, 0));
    let r = send(request_as(
        "/x/y",
        Some(&h),
        "Content-Type: application/grpc\r\n",
        b"x",
    ));
    assert_eq!(r.status, 415);
    assert_eq!(
        r.body,
        json!({"code": 3, "message": TYPE_MESSAGE}).to_string()
    );
    // The error line never carries the path.
    let errs = run.out.wait_for("error", 3);
    assert_eq!(errs.len(), 3);
    assert!(!run.out.text().contains("/x/y"));
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn the_certificate_file_is_public_and_the_key_is_nowhere_on_disk() {
    let run = start("files");
    let ca = run.dir.join("otel-debug-ca.pem");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&ca), 0o644);
    assert_eq!(mode(&run.dir), 0o700);
    assert!(run.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    for e in std::fs::read_dir(&run.dir).unwrap() {
        let p = e.unwrap().path();
        let text = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
        assert!(!text.contains("PRIVATE KEY"), "{}", p.display());
    }
    // Nor in any output.
    assert!(!run.out.text().contains("PRIVATE"));
    // Name constraints are in the file (OID 2.5.29.30, critical) and name exactly the hosts.
    let der: Vec<u8> = CertificateDer::pem_slice_iter(run.ca_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let nc = [0x06, 0x03, 0x55, 0x1d, 0x1e, 0x01, 0x01, 0xff];
    assert!(der.windows(nc.len()).any(|w| w == nc));
    for h in [HOST, OTHER] {
        assert!(der.windows(h.len()).any(|w| w == h.as_bytes()));
    }
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

// ── transport limits ───────────────────────────────────────────────────────────────────────

#[test]
fn a_trickled_handshake_is_cut_off_at_the_absolute_deadline() {
    let run = start_with("trickle", |c| {
        c.tunables.first_request_deadline = Duration::from_millis(700);
        c.tunables.read_timeout = Duration::from_millis(300);
    });
    let a = run.srv.addrs[0];
    let mut s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let t0 = Instant::now();
    // A TLS record header, then one byte at a time: each read succeeds, only the absolute
    // deadline from accept can end this.
    let mut closed = false;
    s.write_all(&[0x16, 0x03, 0x01, 0x00, 0xff]).unwrap();
    while t0.elapsed() < Duration::from_secs(5) {
        if s.write_all(&[0x01]).is_err() {
            closed = true;
            break;
        }
        let mut b = [0u8; 16];
        if matches!(s.read(&mut b), Ok(0)) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(60));
    }
    assert!(closed, "the connection should be closed");
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    // The next client is served.
    assert_eq!(
        post(
            &run,
            HOST,
            Some(&host_port(&run, HOST)),
            "/v1/logs",
            &fixture("codex-0.166.0/logs.json")
        )
        .unwrap()
        .status,
        200
    );
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn a_silent_client_after_the_handshake_is_cut_off_at_the_first_request_deadline() {
    let run = start_with("silent", |c| {
        c.tunables.first_request_deadline = Duration::from_millis(800);
        c.tunables.idle_timeout = Duration::from_secs(30);
        c.tunables.request_deadline = Duration::from_secs(30);
        c.tunables.read_timeout = Duration::from_secs(30);
    });
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let mut s = connect(run.srv.addrs[0], &cfg, HOST).unwrap();
    let t0 = Instant::now();
    s.sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut b = [0u8; 8];
    // Nothing is sent. The server's 30 s idle timeout would be far later than the 0.8 s the
    // absolute deadline allows for handshake plus first request.
    let r = s.read(&mut b);
    assert!(matches!(r, Ok(0) | Err(_)));
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn over_the_limit_connections_close_without_a_handshake_or_a_plaintext_reply() {
    let run = start_with("full", |c| {
        c.tunables.max_connections = 2;
        c.tunables.first_request_deadline = Duration::from_secs(20);
        c.tunables.read_timeout = Duration::from_secs(20);
        c.tunables.idle_timeout = Duration::from_secs(20);
    });
    let a = run.srv.addrs[0];
    let held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(a).unwrap()).collect();
    let end = Instant::now() + Duration::from_secs(5);
    while run.srv.connections() < 2 {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut third = TcpStream::connect(a).unwrap();
    third
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut got = Vec::new();
    let _ = third.read_to_end(&mut got);
    assert!(got.is_empty(), "no bytes, plaintext or TLS: {got:?}");
    drop(held);
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

// ── the binary ─────────────────────────────────────────────────────────────────────────────

fn bin(state: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"));
    c.env("XDG_STATE_HOME", state).env("HOME", state);
    c
}

#[test]
fn the_binary_prints_the_takeover_and_a_second_run_is_refused() {
    let state = tmp("bin");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut first = bin(&state)
        .args([
            "--tls",
            "--tls-host",
            HOST,
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
            "--json",
            "--exit-on-stdin-eof",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(first.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let hello: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(hello["mode"], "tls-receiver");
    let port: u16 = hello["listen"][0]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(port, 443);
    let ca = PathBuf::from(hello["tls"]["ca"]["path"].as_str().unwrap());
    assert_eq!(ca, state.join("cainary/otel-debug-ca.pem"));

    // A real client against the real process, trusting only the file.
    let pem = std::fs::read_to_string(&ca).unwrap();
    let cfg = client_config(&pem, &[b"http/1.1"]);
    let a: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut s = connect(a, &cfg, HOST).unwrap();
    s.write_all(&request(
        "/_x/logs",
        Some(&format!("{HOST}:{port}")),
        "",
        &fixture("codex-0.166.0/logs.json"),
    ))
    .unwrap();
    assert_eq!(read_reply(&mut s).unwrap().status, 200);

    // A second --tls run for the same state directory exits 1.
    let second = bin(&state)
        .args([
            "--tls",
            "--tls-host",
            HOST,
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(
        err.contains("another cainary-otel-debug --tls run owns"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(&ca).unwrap(),
        pem,
        "the first run's file is untouched"
    );

    // --delete-ca refuses while it runs, then works.
    let del = bin(&state).arg("--delete-ca").output().unwrap();
    assert_eq!(del.status.code(), Some(1));
    drop(first.stdin.take());
    assert_eq!(first.wait().unwrap().code(), Some(0));
    let del = bin(&state).arg("--delete-ca").output().unwrap();
    assert_eq!(del.status.code(), Some(0));
    assert!(!ca.exists());
    let again = bin(&state).arg("--delete-ca").output().unwrap();
    assert_eq!(again.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn tls_flags_are_validated_before_anything_is_bound() {
    let state = tmp("flags");
    for args in [
        vec!["--tls"],
        vec!["--tls", "--tls-host", "localhost"],
        vec!["--tls", "--tls-host", "*.example.com"],
        vec!["--tls", "--tls-host", "1.2.3.4"],
        vec!["--tls-host", "a.example.test"],
    ] {
        let out = bin(&state)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    assert!(!state.exists(), "nothing was created");
}

#[test]
fn the_hello_line_golden() {
    let state = tmp("golden");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = bin(&state)
        .args([
            "--tls",
            "--tls-host",
            HOST,
            "--tls-host",
            OTHER,
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
            "--json",
            "--exit-on-stdin-eof",
            "--no-default-red-flags",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    drop(child.stdin.take());
    let _ = child.wait();
    let mut v: Value = serde_json::from_str(&line).unwrap();
    let port = v["listen"][0]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .to_string();
    v["ts"] = json!("<ts>");
    v["generator"] = json!("<generator>");
    let sha = v["tls"]["ca"]["sha256"].as_str().unwrap().to_string();
    let masked = v
        .to_string()
        .replace(&sha, "<sha256>")
        .replace(&state.display().to_string(), "<state>")
        .replace(&port, "<port>");
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/tls-hello.jsonl");
    let got = format!("{masked}\n");
    if std::env::var_os("CAINARY_BLESS").is_some() {
        std::fs::write(&file, &got).unwrap();
    } else {
        let want =
            std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{e} (CAINARY_BLESS=1)"));
        assert!(
            got == want,
            "tls hello differs; re-bless with CAINARY_BLESS=1\n{got}"
        );
    }
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_symlinked_state_directory_is_refused_with_exit_1() {
    let base = tmp("symlinked-state");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.join("state");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"))
        .env("XDG_STATE_HOME", &link)
        .env("HOME", &base)
        .args([
            "--tls",
            "--tls-host",
            HOST,
            "--port",
            "0",
            "--listen",
            "127.0.0.1",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
    assert!(!real.join("cainary").exists());
    let del = Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"))
        .env("XDG_STATE_HOME", &link)
        .env("HOME", &base)
        .arg("--delete-ca")
        .output()
        .unwrap();
    assert_eq!(del.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&base);
}

/// The encrypted bytes of one request, as the client would put them on the wire.
fn wire_bytes(s: &mut Tls_, req: &[u8]) -> Vec<u8> {
    s.conn.writer().write_all(req).unwrap();
    let mut out = Vec::new();
    s.conn.write_tls(&mut out).unwrap();
    out
}

#[test]
fn a_record_trickled_after_a_good_first_request_is_cut_off_at_the_idle_deadline() {
    let run = start_with("trickle2", |c| {
        c.tunables.idle_timeout = Duration::from_millis(1200);
        c.tunables.request_deadline = Duration::from_secs(30);
        c.tunables.read_timeout = Duration::from_millis(500);
        c.tunables.first_request_deadline = Duration::from_secs(30);
    });
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    let mut s = connect(run.srv.addrs[0], &cfg, HOST).unwrap();
    let h = host_port(&run, HOST);
    let body = fixture("codex-0.166.0/logs.json");
    s.write_all(&request("/v1/logs", Some(&h), "", &body))
        .unwrap();
    assert_eq!(
        read_reply(&mut s).unwrap().status,
        200,
        "the first request succeeds"
    );
    // The second request's encrypted record, one byte every 150 ms: every socket read succeeds
    // within the 500 ms read timeout, so only an absolute deadline can end it.
    let bytes = wire_bytes(&mut s, &request("/v1/logs", Some(&h), "", &body));
    assert!(bytes.len() > 40, "{}", bytes.len());
    let t0 = Instant::now();
    let mut closed = false;
    for b in &bytes {
        if s.sock.write_all(&[*b]).is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
        s.sock
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        let mut one = [0u8; 1];
        if matches!((&s.sock).read(&mut one), Ok(0)) {
            closed = true;
            break;
        }
        if t0.elapsed() > Duration::from_secs(8) {
            break;
        }
    }
    assert!(
        closed,
        "the idle deadline should have closed the connection"
    );
    assert!(t0.elapsed() < Duration::from_secs(4), "{:?}", t0.elapsed());
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn capabilities_are_dropped_after_bind_in_plain_mode_too() {
    // A tls-enabled executable may hold the bind capability however it is started.
    let out = Buf::default();
    let mut cfg = Config::new(Box::new(out.clone()));
    cfg.listen = vec!["127.0.0.1".into()];
    let plain = server::run(cfg).unwrap();
    assert!(plain.caps_dropped, "plain mode must drop too");
    plain.shutdown();
    let run = start("caps");
    assert!(run.srv.caps_dropped);
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

// ── handshake error categories (design §16.7, fixed messages, aggregated) ───────────────────

fn wait_tls(run: &Run, needle: &str) -> String {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let all: Vec<String> = run
            .out
            .lines()
            .into_iter()
            .filter(|e| e["type"] == "error" && e["source"] == "tls")
            .map(|e| e["message"].as_str().unwrap().to_string())
            .collect();
        if let Some(m) = all.iter().find(|m| m.contains(needle)) {
            return m.clone();
        }
        assert!(
            Instant::now() < end,
            "no tls error containing {needle:?}: {all:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_client_that_does_not_trust_the_ca_gets_a_message_that_says_how_to_fix_it() {
    let run = start("unknown-ca");
    // A client with some other root store: it sends an unknown_ca / bad_certificate alert.
    let other = Tls::start(&["x.example.test".to_string()], &tmp("unknown-ca-other")).unwrap();
    let other_pem = std::fs::read_to_string(&other.ca_path).unwrap();
    let cfg = client_config(&other_pem, &[b"http/1.1"]);
    assert!(connect(run.srv.addrs[0], &cfg, HOST).is_err());
    let m = wait_tls(&run, "rejected the certificate");
    assert!(m.contains("doesn't trust the CA"), "{m}");
    assert!(
        m.contains(&format!(
            "NODE_EXTRA_CA_CERTS={}",
            run.dir.join("otel-debug-ca.pem").display()
        )),
        "{m}"
    );
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
    let _ = std::fs::remove_dir_all(tmp("unknown-ca-other"));
}

#[test]
fn every_handshake_failure_category_has_its_own_fixed_message() {
    // Off: "a client that connects and leaves" is gone before the own-user lookup, which would
    // refuse it before the handshake ever starts.
    let run = start_with("categories", |c| c.tunables.peer_uid = PeerUid::Off);
    let a = run.srv.addrs[0];
    let ok_cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    // SNI not configured (the name is omitted), and no SNI.
    assert!(connect(a, &ok_cfg, "evil.example.test").is_err());
    assert!(connect(a, &ok_cfg, "127.0.0.1").is_err());
    // No common ALPN.
    assert!(connect(a, &client_config(&run.ca_pem, &[b"h2"]), HOST).is_err());
    // Plain HTTP to the TLS port.
    let mut s = TcpStream::connect(a).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    // A TLS record header followed by nonsense: a protocol error, not "not TLS".
    let mut s = TcpStream::connect(a).unwrap();
    s.write_all(&[
        0x16, 0x03, 0x03, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff,
    ])
    .unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    // A client that connects and leaves.
    drop(TcpStream::connect(a).unwrap());
    let sni = wait_tls(&run, "SNI not in --tls-host");
    let no_sni = wait_tls(&run, "no SNI");
    let alpn = wait_tls(&run, "no common ALPN");
    let not_tls = wait_tls(&run, "not TLS (plain HTTP to the TLS port?)");
    let proto = wait_tls(&run, "protocol error");
    let closed = wait_tls(&run, "closed the connection or stalled");
    for m in [&sni, &no_sni, &alpn, &not_tls, &proto, &closed] {
        assert!(m.starts_with("tls handshake "), "{m}");
        assert!(!m.contains("evil") && !m.contains("127.0.0.1"), "{m}");
    }
    let all = run.out.text();
    assert!(!all.contains("evil.example.test"));
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

// ── own-user check (design D3) ─────────────────────────────────────────────────────────────

/// The `/proc/net/tcp` parsing end to end, over TLS: this process is the client, and it is us.
#[cfg(target_os = "linux")]
#[test]
fn the_system_check_serves_a_tls_client_of_the_same_user() {
    let run = start_with("peer-system", |c| c.tunables.peer_uid = PeerUid::System);
    let r = post(
        &run,
        HOST,
        Some(&host_port(&run, HOST)),
        "/v1/logs",
        &fixture("codex-0.166.0/logs.json"),
    )
    .expect("a reply");
    assert_eq!(r.status, 200, "{}", r.body);
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

/// Another user, no match, two matches, an unreadable table: the connection is closed before the
/// handshake, with no reply, and one `error` line says so.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_peer_is_closed_before_the_handshake() {
    let uid = cainary_net::peer_proc::euid().unwrap();
    for fake in [
        PeerUid::Fake(Lookup::Uid(uid.wrapping_add(1))),
        PeerUid::Fake(Lookup::NotFound),
        PeerUid::Fake(Lookup::Ambiguous),
        PeerUid::FakeUnreadable,
    ] {
        let run = start_with("peer-refused", |c| c.tunables.peer_uid = fake);
        let a = run.srv.addrs[0];
        // The client speaks first and the server never answers: no ServerHello, no plaintext.
        let mut tcp = TcpStream::connect(a).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = tcp.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);
        let mut got = Vec::new();
        let _ = tcp.read_to_end(&mut got);
        assert!(got.is_empty(), "{fake:?}: the server said {got:?}");
        let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
        assert!(connect(a, &cfg, HOST).is_err(), "{fake:?}");
        let errs: Vec<Value> = run.out.wait_for("error", 2);
        assert_eq!(errs.len(), 2, "{fake:?}: {errs:?}");
        let want = match fake {
            PeerUid::Fake(Lookup::Uid(_)) => PEER_REFUSED,
            _ => PEER_UNCONFIRMED,
        };
        assert!(
            errs.iter().all(|e| e["message"] == want),
            "{fake:?}: {errs:?}"
        );
        assert!(
            errs.iter()
                .all(|e| e["source"] == "http" && e["status"] == 403)
        );
        run.srv.shutdown();
        let _ = std::fs::remove_dir_all(&run.dir);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn tls_refusals_share_the_rate_limit() {
    let uid = cainary_net::peer_proc::euid().unwrap();
    let run = start_with("peer-limit", |c| {
        c.tunables.peer_uid = PeerUid::Fake(Lookup::Uid(uid.wrapping_add(1)));
        c.tunables.error_window = Duration::from_secs(3600);
    });
    let a = run.srv.addrs[0];
    for _ in 0..30 {
        let _ = TcpStream::connect(a).and_then(|mut t| {
            t.set_read_timeout(Some(Duration::from_secs(5)))?;
            t.read(&mut [0u8; 1])
        });
    }
    run.out.wait_for("error", 10);
    std::thread::sleep(Duration::from_millis(200));
    let errs = run.out.wait_for("error", 0);
    assert_eq!(errs.len(), 10, "{errs:?}");
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn a_retry_storm_is_one_line_per_category_with_a_count() {
    let run = start_with("storm", |c| {
        c.tunables.tls_error_window = Duration::from_millis(700)
    });
    let a = run.srv.addrs[0];
    let cfg = client_config(&run.ca_pem, &[b"http/1.1"]);
    for _ in 0..30 {
        let _ = connect(a, &cfg, "evil.example.test");
    }
    std::thread::sleep(Duration::from_millis(200));
    let lines: Vec<Value> = run
        .out
        .lines()
        .into_iter()
        .filter(|e| e["type"] == "error" && e["source"] == "tls")
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    // After the window the next one reports how many were skipped.
    std::thread::sleep(Duration::from_millis(800));
    let _ = connect(a, &cfg, "evil.example.test");
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let lines: Vec<Value> = run
            .out
            .lines()
            .into_iter()
            .filter(|e| e["type"] == "error" && e["source"] == "tls")
            .collect();
        if lines.len() == 2 {
            assert_eq!(lines[1]["count"], 30, "29 skipped plus this one: {lines:?}");
            break;
        }
        assert!(Instant::now() < end, "{lines:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn the_endpoint_says_https_and_both_families_are_listed_by_default() {
    let run = start_with("scheme", |c| c.listen.clear());
    let h = &run.out.wait_for("hello", 1)[0];
    assert!(
        h["endpoint"]
            .as_str()
            .unwrap()
            .starts_with("https://127.0.0.1:"),
        "{h}"
    );
    let listen = h["listen"].as_array().unwrap();
    assert!(listen.len() >= 2, "{listen:?}");
    if run.srv.addrs.len() == 2 {
        assert!(listen[1].as_str().unwrap().starts_with("[::1]:"));
    } else {
        assert!(listen[1].as_str().unwrap().contains("not available"));
    }
    run.srv.shutdown();
    let _ = std::fs::remove_dir_all(&run.dir);
}

#[test]
fn a_state_path_with_dotdot_or_a_relative_one_is_refused_with_exit_1() {
    let base = tmp("dotdot-bin");
    std::fs::create_dir_all(base.join("a")).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(base.join("a"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = |xdg: &str| {
        Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"))
            .env("XDG_STATE_HOME", xdg)
            .env("HOME", &base)
            .args([
                "--tls",
                "--tls-host",
                HOST,
                "--port",
                "0",
                "--listen",
                "127.0.0.1",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = run(&format!("{}/a/../state", base.display()));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("'..'"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!base.join("a/state").exists() && !base.join("state").exists());
    let out = run("relative/state");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("XDG_STATE_HOME is not an absolute path")
    );
    let _ = std::fs::remove_dir_all(&base);
}

// ── --trust ────────────────────────────────────────────────────────────────────────────────

fn trust_bin(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cainary-otel-debug"));
    c.env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("NODE_EXTRA_CA_CERTS");
    c
}

fn json_line(out: &std::process::Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 1, "{text}");
    serde_json::from_str(text.trim()).unwrap()
}

#[test]
fn trust_through_the_binary_applies_reports_and_undoes() {
    let home = tmp("trust-bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let settings = home.join(".claude/settings.json");
    let ca = home.join("state/cainary/otel-debug-ca.pem");
    let bundle = home.join("state/cainary/otel-debug-claude-bundle.pem");

    let st = json_line(
        &trust_bin(&home)
            .args(["--trust-status", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(st["type"], "trust-status");
    assert_eq!(st["claudeCode"]["state"], "absent");
    assert_eq!(st["codex"]["state"], "absent");
    assert_eq!(st["caPath"], ca.display().to_string());
    assert_eq!(st["owned"], json!([]));

    // Preview: exit 0, nothing written.
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v = json_line(&out);
    assert_eq!(
        (v["type"].clone(), v["target"].clone(), v["action"].clone()),
        (json!("trust"), json!("claude-code"), json!("preview"))
    );
    assert_eq!(v["key"], "NODE_EXTRA_CA_CERTS");
    assert_eq!(v["to"], bundle.display().to_string());
    assert!(!settings.exists());

    // The bundle needs the collector certificate, as a run of the collector leaves it.
    let ca_dir = ca.parent().unwrap();
    std::fs::create_dir_all(ca_dir).unwrap();
    std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&ca, rcgen_cert("collector")).unwrap();
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).unwrap();
    // Apply, then again (already), then the status, then undo.
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(json_line(&out)["action"], "applied");
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(
        written["env"]["NODE_EXTRA_CA_CERTS"],
        bundle.display().to_string()
    );
    assert_eq!(
        json_line(
            &trust_bin(&home)
                .args(["--trust", "claude-code", "--json"])
                .output()
                .unwrap()
        )["action"],
        "already"
    );
    assert_eq!(
        json_line(
            &trust_bin(&home)
                .args(["--trust-status", "--json"])
                .output()
                .unwrap()
        )["claudeCode"]["state"],
        "applied"
    );
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--undo", "--json"])
        .output()
        .unwrap();
    assert_eq!(json_line(&out)["action"], "undone");
    assert!(!settings.exists(), "the file cAInary created is removed");
    assert_eq!(
        json_line(
            &trust_bin(&home)
                .args(["--trust", "claude-code", "--undo", "--json"])
                .output()
                .unwrap()
        )["action"],
        "nothing-to-undo"
    );

    // A refusal exits 1 and still prints one line.
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(&settings, "{ not json").unwrap();
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_line(&out)["action"], "refused");

    // Without --json it is text, and a bad target is a usage error.
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--dry-run"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("refused:"));
    assert_eq!(
        trust_bin(&home)
            .args(["--trust", "vim"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn each_tls_start_regenerates_the_combined_bundle_at_the_same_path() {
    let home = tmp("trust-refresh");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cert = |pem: &str| -> Vec<Vec<u8>> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .map(|c| c.unwrap().to_vec())
            .collect()
    };
    let start = |home: &Path| {
        let mut child = trust_bin(home)
            .args([
                "--tls",
                "--tls-host",
                HOST,
                "--port",
                "0",
                "--listen",
                "127.0.0.1",
                "--json",
                "--exit-on-stdin-eof",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        drop(child.stdin.take());
        child.wait().unwrap();
    };
    // The user's own bundle: another path already in the settings.
    let mine = home.join("corp.pem");
    let corp = rcgen_cert("corp root");
    std::fs::write(&mine, &corp).unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(
        home.join(".claude/settings.json"),
        format!(
            "{{\"env\":{{\"NODE_EXTRA_CA_CERTS\":\"{}\"}}}}\n",
            mine.display()
        ),
    )
    .unwrap();
    start(&home); // publishes the first CA
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--json"])
        .output()
        .unwrap();
    let v = json_line(&out);
    assert_eq!(v["action"], "applied", "{v}");
    let bundle = PathBuf::from(v["bundlePath"].as_str().unwrap());
    let ca_file = home.join("state/cainary/otel-debug-ca.pem");
    let first_ca = cert(&std::fs::read_to_string(&ca_file).unwrap());
    let b1 = cert(&std::fs::read_to_string(&bundle).unwrap());
    assert_eq!(b1.len(), 2);
    assert_eq!(
        b1[1], first_ca[0],
        "the collector certificate is last, and once"
    );
    // A second run makes a new CA; the bundle at the same path now has the new one.
    start(&home);
    let second_ca = cert(&std::fs::read_to_string(&ca_file).unwrap());
    assert_ne!(first_ca, second_ca);
    let b2 = cert(&std::fs::read_to_string(&bundle).unwrap());
    assert_eq!(b2.len(), 2);
    assert_eq!(b2[1], second_ca[0]);
    assert_eq!(b2[0], b1[0], "the user's certificate is kept");
    let settings: Value =
        serde_json::from_str(&std::fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(
        settings["env"]["NODE_EXTRA_CA_CERTS"],
        bundle.display().to_string()
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A throwaway certificate in PEM, for a user's pre-existing bundle.
fn rcgen_cert(name: &str) -> String {
    // A directory per call: tests run in parallel and each removes its own.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = tmp(&format!(
        "rcgen-cert-{}",
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let t = Tls::start(&[format!("{}.example.test", name.replace(' ', "-"))], &dir).unwrap();
    let pem = std::fs::read_to_string(&t.ca_path).unwrap();
    drop(t);
    let _ = std::fs::remove_dir_all(&dir);
    pem
}

/// A home with the collector CA published and `--trust claude-code` applied over the user's bundle.
fn trusted_home(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = tmp(tag);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = home.join("state/cainary");
    drop(Tls::start(&[HOST.to_string()], &state).unwrap());
    let mine = home.join("corp.pem");
    std::fs::write(&mine, rcgen_cert("corp root")).unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    let settings = home.join(".claude/settings.json");
    std::fs::write(
        &settings,
        format!(
            "{{\"env\":{{\"NODE_EXTRA_CA_CERTS\":\"{}\"}}}}\n",
            mine.display()
        ),
    )
    .unwrap();
    let out = trust_bin(&home)
        .args(["--trust", "claude-code", "--json"])
        .output()
        .unwrap();
    assert_eq!(json_line(&out)["action"], "applied");
    (home, settings, state)
}

#[test]
fn delete_ca_undoes_first() {
    let (home, settings, state) = trusted_home("delete-undoes");
    let corp = format!("{}", home.join("corp.pem").display());
    let del = trust_bin(&home).arg("--delete-ca").output().unwrap();
    assert_eq!(del.status.code(), Some(0), "{del:?}");
    let text = String::from_utf8_lossy(&del.stdout);
    assert!(text.contains("undone:"), "{text}");
    assert!(text.contains("removed "), "{text}");
    assert!(!state.join("otel-debug-ca.pem").exists());
    assert!(!state.join("otel-debug-claude-bundle.pem").exists());
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(v["env"]["NODE_EXTRA_CA_CERTS"], corp, "restored");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn delete_ca_refused_if_undo_refused() {
    let (home, settings, state) = trusted_home("delete-refused");
    let bundle = state.join("otel-debug-claude-bundle.pem");
    std::fs::write(&bundle, "someone else's bundle").unwrap();
    let before = std::fs::read(&settings).unwrap();
    let del = trust_bin(&home).arg("--delete-ca").output().unwrap();
    assert_eq!(del.status.code(), Some(1), "{del:?}");
    assert!(String::from_utf8_lossy(&del.stdout).contains("refused:"));
    assert!(state.join("otel-debug-ca.pem").exists(), "the CA stays");
    assert_eq!(std::fs::read(&settings).unwrap(), before);
    assert_eq!(std::fs::read(&bundle).unwrap(), b"someone else's bundle");
    let _ = std::fs::remove_dir_all(&home);
}
