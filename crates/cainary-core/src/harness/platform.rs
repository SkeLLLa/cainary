//! Operating system, environment kind, MDM paths and the system proxy (architecture.md §6.4).

use crate::value::Value;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Macos,
    Linux,
}

impl Os {
    /// The host OS (`cfg!(target_os)`). Path decisions use the runtime value, not this.
    pub fn host() -> Os {
        if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }

    pub fn parse(s: &str) -> Option<Os> {
        match s {
            "macos" => Some(Os::Macos),
            "linux" => Some(Os::Linux),
            _ => None,
        }
    }
}

/// Who started the scanner: a shell (env is visible) or launchd (shell exports are not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvKind {
    Shell,
    Launchd,
}

impl EnvKind {
    pub fn parse(s: &str) -> Option<EnvKind> {
        match s {
            "shell" => Some(EnvKind::Shell),
            "launchd" => Some(EnvKind::Launchd),
            _ => None,
        }
    }
}

/// macOS: `R/Library/Managed Preferences/<user>/<domain>.plist`, then
/// `R/Library/Managed Preferences/<domain>.plist`. Linux: empty.
pub fn mdm_paths(os: Os, root: &Path, user: &str, domain: &str) -> Vec<PathBuf> {
    if os != Os::Macos {
        return Vec::new();
    }
    let dir = root.join("Library").join("Managed Preferences");
    let file = format!("{domain}.plist");
    vec![dir.join(user).join(&file), dir.join(file)]
}

/// Why running the helper failed (each becomes an `error` source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdError {
    Spawn(String),
    Exit(i32),
    TimedOut,
    TooLarge,
}

/// Counts calls to [`scutil_proxy`], so a test can show fixture mode never runs it.
#[cfg(test)]
pub static SCUTIL_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const SCUTIL_CAP: usize = 64 * 1024;
const SCUTIL_DEADLINE: Duration = Duration::from_secs(3);

/// `/usr/sbin/scutil --proxy` (macOS only; fixed arguments, cleared env, 3 s timeout, 64 KiB cap).
pub fn scutil_proxy() -> Result<String, CmdError> {
    #[cfg(test)]
    SCUTIL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut cmd = Command::new("/usr/sbin/scutil");
    cmd.arg("--proxy").env_clear();
    run_bounded(cmd, SCUTIL_CAP, SCUTIL_DEADLINE)
}

/// Run `cmd` with stdin/stderr on `/dev/null` and stdout drained by a reader thread that keeps
/// at most `cap + 1` bytes. Over `cap` is `TooLarge`; past `deadline` the child is killed and
/// reaped (`TimedOut`). A non-zero exit is `Exit`.
fn run_bounded(mut cmd: Command, cap: usize, deadline: Duration) -> Result<String, CmdError> {
    cmd.stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| CmdError::Spawn(e.to_string()))?;
    let Some(out) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CmdError::Spawn("no stdout pipe".to_string()));
    };
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = Some(std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.take(limit).read_to_end(&mut buf);
        buf
    }));
    let mut captured: Option<Vec<u8>> = None;
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                // A grandchild may still hold the pipe; the output is discarded, so do not wait for it.
                drop(reader.take());
                return Err(CmdError::Spawn(e.to_string()));
            }
        }
        if reader.as_ref().is_some_and(|r| r.is_finished()) {
            join_reader(&mut reader, &mut captured);
            if captured.as_ref().is_some_and(|b| b.len() > cap) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CmdError::TooLarge);
            }
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // A grandchild may still hold the pipe; the output is discarded, so do not wait for it.
            drop(reader.take());
            return Err(CmdError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    join_reader(&mut reader, &mut captured);
    let buf = captured.unwrap_or_default();
    if buf.len() > cap {
        return Err(CmdError::TooLarge);
    }
    if !status.success() {
        return Err(CmdError::Exit(status.code().unwrap_or(-1)));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn join_reader(reader: &mut Option<JoinHandle<Vec<u8>>>, captured: &mut Option<Vec<u8>>) {
    if let Some(handle) = reader.take() {
        *captured = Some(handle.join().unwrap_or_default());
    }
}

enum Frame {
    Dict(Map<String, Value>),
    Array(Vec<Value>),
}

impl Frame {
    fn insert(&mut self, key: &str, v: Value) {
        match self {
            Frame::Dict(m) => {
                m.insert(key.to_string(), v);
            }
            Frame::Array(a) => a.push(v),
        }
    }

    fn into_value(self) -> Value {
        match self {
            Frame::Dict(m) => Value::Object(m),
            Frame::Array(a) => Value::Array(a),
        }
    }
}

fn scalar(s: &str) -> Value {
    match s.parse::<i64>() {
        Ok(n) if n.to_string() == s => Value::from(n),
        _ => Value::String(s.to_string()),
    }
}

/// Parse `scutil --proxy` text (nested `<dictionary>`/`<array>`, `key : value`) into a Value.
/// Integers become numbers, everything else strings; array entries keep their order. Unbalanced
/// or unknown lines are skipped, so the result is always an object.
pub fn parse_scutil(text: &str) -> Value {
    // Each frame carries the key it will be stored under in its parent.
    let mut stack: Vec<(String, Frame)> = vec![(String::new(), Frame::Dict(Map::new()))];
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line == "}" {
            if stack.len() > 1
                && let Some((key, frame)) = stack.pop()
                && let Some((_, parent)) = stack.last_mut()
            {
                parent.insert(&key, frame.into_value());
            }
            continue;
        }
        let (key, value) = match line.split_once(" : ") {
            Some((k, v)) => (k.trim(), v.trim()),
            None => ("", line),
        };
        let frame = match value {
            "<dictionary> {" => Some(Frame::Dict(Map::new())),
            "<array> {" => Some(Frame::Array(Vec::new())),
            _ => None,
        };
        match frame {
            // The outermost `<dictionary> {` is the root we already have.
            Some(_) if key.is_empty() && stack.len() == 1 => {}
            Some(f) => stack.push((key.to_string(), f)),
            None if !key.is_empty() => {
                if let Some((_, top)) = stack.last_mut() {
                    top.insert(key, scalar(value));
                }
            }
            None => {}
        }
    }
    while stack.len() > 1 {
        if let Some((key, frame)) = stack.pop()
            && let Some((_, parent)) = stack.last_mut()
        {
            parent.insert(&key, frame.into_value());
        }
    }
    stack
        .pop()
        .map_or_else(|| Value::Object(Map::new()), |(_, f)| f.into_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mdm_paths_macos_user_then_global() {
        let p = mdm_paths(Os::Macos, Path::new("/r"), "alice", "com.example.app");
        assert_eq!(
            p,
            vec![
                PathBuf::from("/r/Library/Managed Preferences/alice/com.example.app.plist"),
                PathBuf::from("/r/Library/Managed Preferences/com.example.app.plist"),
            ]
        );
    }

    #[test]
    fn mdm_paths_linux_empty() {
        assert!(mdm_paths(Os::Linux, Path::new("/r"), "alice", "d").is_empty());
    }

    #[test]
    fn os_and_env_kind_parse() {
        assert_eq!(Os::parse("macos"), Some(Os::Macos));
        assert_eq!(Os::parse("windows"), None);
        assert_eq!(EnvKind::parse("launchd"), Some(EnvKind::Launchd));
        assert_eq!(EnvKind::parse("x"), None);
    }

    #[test]
    fn parse_http_https_socks() {
        let v = parse_scutil(
            "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : proxy.example-corp.com\n  \
             HTTPSEnable : 1\n  HTTPSProxy : proxy.example-corp.com\n  HTTPSPort : 8443\n  \
             SOCKSEnable : 0\n  SOCKSProxy : socks.example-corp.com\n}\n",
        );
        assert_eq!(v["HTTPEnable"], json!(1));
        assert_eq!(v["HTTPPort"], json!(8080));
        assert_eq!(v["HTTPProxy"], json!("proxy.example-corp.com"));
        assert_eq!(v["HTTPSPort"], json!(8443));
        assert_eq!(v["SOCKSEnable"], json!(0));
        assert_eq!(v["SOCKSProxy"], json!("socks.example-corp.com"));
    }

    #[test]
    fn parse_pac_and_wpad() {
        let v = parse_scutil(
            "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  \
             ProxyAutoConfigURLString : http://pac.example-corp.com/proxy.pac\n  \
             ProxyAutoDiscoveryEnable : 1\n}\n",
        );
        assert_eq!(
            v["ProxyAutoConfigURLString"],
            json!("http://pac.example-corp.com/proxy.pac")
        );
        assert_eq!(v["ProxyAutoConfigEnable"], json!(1));
        assert_eq!(v["ProxyAutoDiscoveryEnable"], json!(1));
    }

    #[test]
    fn parse_exceptions_array() {
        let v = parse_scutil(
            "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n    \
             2 : *.example-corp.com\n  }\n  FTPPassive : 1\n}\n",
        );
        assert_eq!(
            v["ExceptionsList"],
            json!(["*.local", "169.254/16", "*.example-corp.com"])
        );
        assert_eq!(v["FTPPassive"], json!(1));
    }

    #[test]
    fn parse_scoped_dictionary() {
        let v = parse_scutil(
            "<dictionary> {\n  HTTPEnable : 0\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      \
             HTTPEnable : 1\n      HTTPProxy : proxy.example-corp.com\n      ExceptionsList : <array> {\n        \
             0 : *.local\n      }\n    }\n    utun3 : <dictionary> {\n      SOCKSEnable : 0\n    }\n  }\n}\n",
        );
        assert_eq!(v["HTTPEnable"], json!(0));
        assert_eq!(v["__SCOPED__"]["en0"]["HTTPEnable"], json!(1));
        assert_eq!(
            v["__SCOPED__"]["en0"]["HTTPProxy"],
            json!("proxy.example-corp.com")
        );
        assert_eq!(v["__SCOPED__"]["en0"]["ExceptionsList"], json!(["*.local"]));
        assert_eq!(v["__SCOPED__"]["utun3"]["SOCKSEnable"], json!(0));
    }

    #[test]
    fn parse_garbage_is_empty_object() {
        assert_eq!(parse_scutil(""), json!({}));
        assert_eq!(parse_scutil("}\n}\nnonsense\n"), json!({}));
        // truncated nesting still closes
        let v = parse_scutil("<dictionary> {\n  A : <dictionary> {\n    B : 1\n");
        assert_eq!(v["A"]["B"], json!(1));
    }

    #[test]
    fn run_bounded_too_large() {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("yes | head -c 200000");
        assert_eq!(
            run_bounded(c, SCUTIL_CAP, Duration::from_secs(5)),
            Err(CmdError::TooLarge)
        );
    }

    #[test]
    fn run_bounded_times_out_and_reaps() {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("sleep 10");
        let t = Instant::now();
        assert_eq!(
            run_bounded(c, SCUTIL_CAP, Duration::from_secs(1)),
            Err(CmdError::TimedOut)
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn run_bounded_ok_exit_and_spawn() {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("echo hi");
        assert_eq!(
            run_bounded(c, 100, Duration::from_secs(5)),
            Ok("hi\n".to_string())
        );
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("exit 3");
        assert_eq!(
            run_bounded(c, 100, Duration::from_secs(5)),
            Err(CmdError::Exit(3))
        );
        let c = Command::new("/nonexistent/example-bin");
        assert!(matches!(
            run_bounded(c, 100, Duration::from_secs(1)),
            Err(CmdError::Spawn(_))
        ));
    }

    #[test]
    #[ignore = "runs the real /usr/sbin/scutil (macOS)"]
    fn live_scutil_proxy() {
        let text = scutil_proxy().expect("scutil runs");
        assert!(parse_scutil(&text).is_object());
    }
}
