//! The output thread and the line formats (design §8.6, §14.2). Everything that reaches a
//! terminal, the log file or a GUI passes through here, so this is where escaping lives.

use crate::logfile::LogFile;
use crate::queue::Queue;
use serde_json::{Map, Value, json};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::SystemTime;

pub const MAX_LINE_BYTES: usize = 1 << 20;

/// Renders a payload-derived string for a terminal: C0/C1 controls, ESC, CR/LF, DEL and bidi
/// format controls become `\u{…}`, so a payload can't move the cursor, set the clipboard (OSC
/// 52) or reorder what the user reads.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        let bad = cp < 0x20
            || (0x7f..=0x9f).contains(&cp)
            || (0x202a..=0x202e).contains(&cp)
            || (0x2066..=0x2069).contains(&cp)
            || matches!(cp, 0x200e | 0x200f | 0x061c);
        if bad {
            out.push_str(&format!("\\u{{{cp:x}}}"));
        } else {
            out.push(c);
        }
    }
    out
}

/// A `{…}` JSON object with at least one key, serialized once by the producer. The output
/// thread splices `v`, `type`, `ts` (and `seq`) in front, so the queue holds plain strings
/// whose size is exact.
fn tail(map: Map<String, Value>) -> String {
    debug_assert!(!map.is_empty());
    Value::Object(map).to_string()
}

fn line(ty: &str, ts: &str, seq: Option<u64>, tail: &str) -> String {
    let mut s = format!("{{\"v\":1,\"type\":\"{ty}\",\"ts\":\"{ts}\"");
    if let Some(n) = seq {
        s.push_str(&format!(",\"seq\":{n}"));
    }
    match tail.strip_prefix('{') {
        Some("}") | None => s.push('}'),
        Some(rest) => {
            s.push(',');
            s.push_str(rest);
        }
    }
    s.push('\n');
    s
}

#[derive(Debug)]
pub struct AlertEvent {
    pub tail: String,
    pub text: String,
}

#[derive(Debug)]
pub struct BatchEvent {
    pub tail: String,
    /// `logs · claude-code 2.1.316 · 12 records`; the time is appended when printed.
    pub text_header: String,
    pub text_body: String,
    pub alerts: Vec<AlertEvent>,
}

#[derive(Debug)]
pub struct ErrorEvent {
    pub tail: String,
    pub text: String,
}

#[derive(Debug)]
pub enum Event {
    Batch(BatchEvent),
    Error(ErrorEvent),
}

/// Standard methods are echoed; anything else is `<other>`, so a method can't carry data.
fn method_label(m: &str) -> &str {
    match m {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE" => m,
        _ => "<other>",
    }
}

impl ErrorEvent {
    /// `path` must already be a known route (`/v1/logs`) or `None`.
    pub fn http(
        status: u16,
        method: Option<&str>,
        path: Option<&str>,
        message: &str,
    ) -> ErrorEvent {
        let method = method.map(method_label);
        let mut m = Map::new();
        m.insert("source".into(), json!("http"));
        m.insert("status".into(), json!(status));
        m.insert("method".into(), json!(method));
        m.insert("path".into(), json!(path));
        m.insert("message".into(), json!(message));
        ErrorEvent {
            tail: tail(m),
            text: format!(
                "error http {status} {} {}: {message}",
                method.unwrap_or("-"),
                path.unwrap_or("-")
            ),
        }
    }

    pub fn dropped(n: u64) -> ErrorEvent {
        let message = format!("{n} more rejections in the last second were not shown");
        let mut m = Map::new();
        m.insert("source".into(), json!("http"));
        m.insert("dropped".into(), json!(n));
        m.insert("message".into(), json!(message));
        ErrorEvent {
            tail: tail(m),
            text: format!("error http: {message}"),
        }
    }

    /// A TLS handshake category, with how many there were since the last line for it.
    pub fn tls(message: &str, count: u64) -> ErrorEvent {
        let mut m = Map::new();
        m.insert("source".into(), json!("tls"));
        m.insert("message".into(), json!(message));
        if count > 1 {
            m.insert("count".into(), json!(count));
        }
        ErrorEvent {
            tail: tail(m),
            text: if count > 1 {
                format!("error tls: {message} (×{count})")
            } else {
                format!("error tls: {message}")
            },
        }
    }

    pub fn other(source: &str, message: &str) -> ErrorEvent {
        let mut m = Map::new();
        m.insert("source".into(), json!(source));
        m.insert("message".into(), json!(message));
        ErrorEvent {
            tail: tail(m),
            text: format!("error {source}: {message}"),
        }
    }
}

impl Event {
    pub fn size(&self) -> usize {
        match self {
            Event::Batch(b) => {
                b.tail.len()
                    + b.text_header.len()
                    + b.text_body.len()
                    + b.alerts
                        .iter()
                        .map(|a| a.tail.len() + a.text.len())
                        .sum::<usize>()
            }
            Event::Error(e) => e.tail.len() + e.text.len(),
        }
    }

    #[cfg(test)]
    pub fn sized_for_test(n: usize) -> Event {
        Event::Error(ErrorEvent {
            tail: "x".repeat(n),
            text: String::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FlagInfo {
    pub name: String,
    pub kind: &'static str,
    pub preset: bool,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone)]
pub struct TlsHello {
    pub hosts: Vec<String>,
    pub ca_path: String,
    pub ca_sha256: String,
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub generator: String,
    /// `receiver`, or `tls-receiver` in takeover mode.
    pub mode: &'static str,
    pub tls: Option<TlsHello>,
    /// Bound addresses, plus a note for any that couldn't be bound.
    pub listen: Vec<String>,
    pub endpoint: String,
    pub show_values: bool,
    pub log_file: Option<String>,
    pub red_flags: Vec<FlagInfo>,
    pub setup: crate::setup::Setup,
}

impl Hello {
    fn tail(&self) -> String {
        let flags: Vec<Value> = self
            .red_flags
            .iter()
            .map(|f| {
                json!({"name": f.name, "kind": f.kind, "preset": f.preset, "caseSensitive": f.case_sensitive})
            })
            .collect();
        let mut m = Map::new();
        m.insert("generator".into(), json!(self.generator));
        m.insert("mode".into(), json!(self.mode));
        m.insert("listen".into(), json!(self.listen));
        m.insert("endpoint".into(), json!(self.endpoint));
        m.insert("showValues".into(), json!(self.show_values));
        m.insert("logFile".into(), json!(self.log_file));
        m.insert("redFlags".into(), Value::Array(flags));
        if let Some(t) = &self.tls {
            // The names are what the user configured, not a sender identity.
            m.insert(
                "tls".into(),
                json!({"hosts": t.hosts, "ca": {"path": t.ca_path, "sha256": t.ca_sha256}}),
            );
        }
        let mut setup = json!({"claudeCode": self.setup.claude_code, "codex": self.setup.codex, "notes": self.setup.notes});
        if let Some(t) = &self.setup.takeover {
            setup["takeover"] = json!(t);
        }
        m.insert("setup".into(), setup);
        tail(m)
    }
}

/// A standalone `error` line (`source`, `message`) with the contract's envelope, for failures
/// before the output thread exists (a refused listen).
pub fn error_line(source: &str, message: &str) -> String {
    let m = ErrorEvent::other(source, message);
    line("error", &now(), None, &m.tail)
}

pub struct Config {
    pub json: bool,
    pub once: bool,
    pub hello: Hello,
    pub log: Option<LogFile>,
    /// stdout.
    pub sink: Box<dyn Write + Send>,
    /// stderr: the text-mode startup lines.
    pub status: Box<dyn Write + Send>,
}

#[derive(Debug)]
pub enum End {
    /// `--once` after its first batch.
    Once,
    /// The queue closed.
    Closed,
    /// The sink failed: `BrokenPipe` means the reader went away.
    SinkFailed(io::Error),
}

fn now() -> String {
    cainary_core::value::rfc3339(SystemTime::now())
}

struct Out {
    json: bool,
    sink: Box<dyn Write + Send>,
    log: Option<LogFile>,
    seq: u64,
}

impl Out {
    /// A JSON line goes to the log file always and to the sink in `--json` mode.
    fn emit(
        &mut self,
        ty: &str,
        ts: &str,
        seq: Option<u64>,
        tail: &str,
        text: &str,
    ) -> io::Result<()> {
        let l = line(ty, ts, seq, tail);
        if self.log.is_some() {
            self.log_line(&l, ts)?;
        }
        if self.json {
            self.sink.write_all(l.as_bytes())?;
        } else {
            self.sink.write_all(text.as_bytes())?;
        }
        Ok(())
    }

    fn log_line(&mut self, l: &str, ts: &str) -> io::Result<()> {
        let Some(log) = self.log.as_mut() else {
            return Ok(());
        };
        if let Err(e) = log.write_line(l) {
            // One error line, then file logging stops and streaming continues.
            self.log = None;
            let msg = format!("log file write failed ({}); file logging stopped", e.kind());
            let m = ErrorEvent::other("log-file", &msg);
            let el = line("error", ts, None, &m.tail);
            if self.json {
                self.sink.write_all(el.as_bytes())?;
            } else {
                writeln!(self.sink, "{}", m.text)?;
            }
        }
        Ok(())
    }

    fn batch(&mut self, b: BatchEvent) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let ts = now();
        let text = format!(
            "── {} · {}\n{}",
            b.text_header,
            ts.get(11..).unwrap_or(&ts),
            b.text_body
        );
        self.emit("batch", &ts, Some(seq), &b.tail, &text)?;
        for a in &b.alerts {
            self.emit("alert", &ts, Some(seq), &a.tail, &format!("{}\n", a.text))?;
        }
        self.sink.flush()
    }

    fn error(&mut self, e: ErrorEvent) -> io::Result<()> {
        let ts = now();
        self.emit("error", &ts, None, &e.tail, &format!("{}\n", e.text))?;
        self.sink.flush()
    }
}

pub fn run(queue: Arc<Queue>, cfg: Config) -> End {
    let Config {
        json,
        once,
        hello,
        log,
        sink,
        mut status,
    } = cfg;
    let mut out = Out {
        json,
        sink,
        log,
        seq: 0,
    };
    let ts = now();
    let first = (|| -> io::Result<()> {
        if json {
            out.emit("hello", &ts, None, &hello.tail(), "")?;
            out.sink.flush()
        } else {
            out.log_line(&line("hello", &ts, None, &hello.tail()), &ts)?;
            // Text mode keeps stdout for the stream; the setup lines go to stderr.
            let scheme = hello.endpoint.split("://").next().unwrap_or("http");
            let bound: Vec<String> = hello
                .listen
                .iter()
                .filter(|l| !l.contains(" ("))
                .map(|l| format!("{scheme}://{l}"))
                .collect();
            writeln!(status, "listening on {}", bound.join(" and "))?;
            for note in hello.listen.iter().filter(|l| l.contains(" (")) {
                writeln!(status, "not listening on {note}")?;
            }
            write!(status, "{}", crate::setup::text(&hello.setup))?;
            status.flush()
        }
    })();
    if let Err(e) = first {
        return End::SinkFailed(e);
    }
    while let Some(ev) = queue.pop() {
        let r = match ev {
            Event::Batch(b) => out.batch(b),
            Event::Error(e) => out.error(e),
        };
        if let Err(e) = r {
            return End::SinkFailed(e);
        }
        if once && out.seq > 0 {
            return End::Once;
        }
    }
    End::Closed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralises_terminal_controls() {
        let osc52 = "a\u{1b}]52;c;c2VjcmV0\u{7}b";
        let e = escape(osc52);
        assert!(!e.contains('\u{1b}') && !e.contains('\u{7}'));
        assert_eq!(e, "a\\u{1b}]52;c;c2VjcmV0\\u{7}b");
        assert_eq!(escape("ok\rspoof\nline"), "ok\\u{d}spoof\\u{a}line");
        assert_eq!(escape("\u{85}\u{9b}\u{7f}"), "\\u{85}\\u{9b}\\u{7f}");
        assert_eq!(escape("\u{202e}evil\u{2066}"), "\\u{202e}evil\\u{2066}");
        assert_eq!(
            escape("\u{200e}\u{200f}\u{061c}"),
            "\\u{200e}\\u{200f}\\u{61c}"
        );
        assert_eq!(escape("plain ünïcode ✓"), "plain ünïcode ✓");
    }

    #[test]
    fn a_standalone_error_line_has_the_contract_shape() {
        let l = error_line("listen", "can't listen on 127.0.0.1:443: permission denied");
        assert!(l.ends_with('\n') && l.matches('\n').count() == 1);
        let v: Value = serde_json::from_str(&l).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["v", "type", "ts", "source", "message"]);
        assert_eq!(
            (v["v"].clone(), v["type"].clone()),
            (json!(1), json!("error"))
        );
        assert_eq!(v["source"], "listen");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn lines_are_spliced_in_order() {
        let l = line("batch", "T", Some(3), "{\"a\":1}");
        assert_eq!(
            l,
            "{\"v\":1,\"type\":\"batch\",\"ts\":\"T\",\"seq\":3,\"a\":1}\n"
        );
        assert_eq!(
            line("x", "T", None, "{}"),
            "{\"v\":1,\"type\":\"x\",\"ts\":\"T\"}\n"
        );
    }

    #[test]
    fn error_events_do_not_echo_methods_or_paths() {
        let e = ErrorEvent::http(404, Some("XSECRET-METHOD"), None, "not found");
        assert!(!e.tail.contains("SECRET") && !e.text.contains("SECRET"));
        assert!(e.tail.contains("\"method\":\"<other>\""));
        assert!(
            ErrorEvent::http(415, Some("POST"), Some("/v1/logs"), "m")
                .tail
                .contains("/v1/logs")
        );
        assert!(ErrorEvent::dropped(7).tail.contains("\"dropped\":7"));
    }
}
