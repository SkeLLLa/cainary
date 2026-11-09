//! Protocol 1. The tray starts `pkexec <helper> set HOST [HOST…]` or `pkexec <helper> clear`. The
//! helper prints exactly one line on stdout: `cainary-hosts-helper/1 ok set|clear
//! changed|unchanged|changed-unsynced` or `cainary-hosts-helper/1 error <token>`. The rename of
//! `/etc/hosts` is the commit point: every `error` happens before it. Exit 0 on `ok`, 2 on a
//! refused precondition (bad arguments, not run by pkexec, too many or reserved names), 1 on any
//! other error. stderr stays empty. It reads no stdin, takes no path from the caller, runs
//! nothing and reads only the invoker uid (`PKEXEC_UID`, on macOS `CAINARY_HOSTS_UID`) from the
//! environment.

use std::io::Write;
use std::process::exit;

use crate::edit::Op;
use crate::file::{self, Done};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL: &str = "cainary-hosts-helper/1";
pub const MAX_EDIT_HOSTS: usize = 8;
pub const MAX_HOST_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fail {
    BadArgs,
    NotPkexec,
    ReservedName,
    TooMany,
    Symlink,
    NotRegular,
    Unprotected,
    MountPoint,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NoMountId,
    Hardlinked,
    TooLarge,
    DamagedBlock,
    BadLock,
    Busy,
    Changed,
    Label,
    ReadOnly,
    WriteFailed,
}

impl Fail {
    pub fn token(&self) -> &'static str {
        match self {
            Fail::BadArgs => "bad-args",
            Fail::NotPkexec => "not-pkexec",
            Fail::ReservedName => "reserved-name",
            Fail::TooMany => "too-many",
            Fail::Symlink => "symlink",
            Fail::NotRegular => "not-regular",
            Fail::Unprotected => "unprotected",
            Fail::MountPoint => "mount-point",
            Fail::NoMountId => "no-mount-id",
            Fail::Hardlinked => "hardlinked",
            Fail::TooLarge => "too-large",
            Fail::DamagedBlock => "damaged-block",
            Fail::BadLock => "bad-lock",
            Fail::Busy => "busy",
            Fail::Changed => "changed",
            Fail::Label => "label",
            Fail::ReadOnly => "read-only",
            Fail::WriteFailed => "write-failed",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Fail::BadArgs | Fail::NotPkexec | Fail::ReservedName | Fail::TooMany => 2,
            _ => 1,
        }
    }
}

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`, applied to the
/// already lowercased name: at least two labels, no wildcard, and not an IP-address shape.
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > MAX_HOST_BYTES {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    // An all-numeric last label would make `1.2.3.4` a "name".
    labels.iter().all(|l| label_ok(l))
        && !labels[labels.len() - 1].bytes().all(|c| c.is_ascii_digit())
}

/// `PKEXEC_UID`: canonical decimal that fits a uid (`(uid_t)-1` is not one).
pub fn parse_uid(s: Option<&str>) -> Option<u32> {
    let s = s?;
    let canonical = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    s.parse::<u32>()
        .ok()
        .filter(|&u| canonical && u != u32::MAX)
}

/// `set HOST…` (1 to 8 valid, distinct names) or `clear` (no names). Nothing else.
pub fn parse_args(args: &[String]) -> Result<Op, Fail> {
    match args.split_first() {
        Some((cmd, [])) if cmd == "clear" => Ok(Op::Clear),
        Some((cmd, hosts)) if cmd == "set" && !hosts.is_empty() => {
            if hosts.len() > MAX_EDIT_HOSTS {
                return Err(Fail::TooMany);
            }
            for (i, h) in hosts.iter().enumerate() {
                if !valid_host(h) || hosts[..i].contains(h) {
                    return Err(Fail::BadArgs);
                }
            }
            Ok(Op::Set(hosts.to_vec()))
        }
        _ => Err(Fail::BadArgs),
    }
}

/// Names of this machine and loopback aliases the helper never redirects. Local data only.
/// `node` is `uname().nodename`, lowercased.
pub fn reserved(host: &str, node: &str) -> bool {
    const FIXED: [&str; 3] = [
        "localhost.localdomain",
        "localhost4.localdomain4",
        "localhost6.localdomain6",
    ];
    let first = |n: &str| n.split('.').next().unwrap_or(n).to_string();
    host.ends_with(".localhost")
        || host.ends_with(".localdomain")
        || FIXED.contains(&host)
        || (!node.is_empty() && first(host) == first(node))
}

fn check_reserved(op: &Op, node: &str) -> Result<(), Fail> {
    match op {
        Op::Set(hosts) if hosts.iter().any(|h| reserved(h, node)) => Err(Fail::ReservedName),
        _ => Ok(()),
    }
}

pub fn reply_ok(op: &Op, done: &Done) -> String {
    format!("{PROTOCOL} ok {} {}", op.word(), done.word())
}

pub fn reply_error(fail: &Fail) -> String {
    format!("{PROTOCOL} error {}", fail.token())
}

/// `uname().nodename`, lowercased; empty when unavailable.
fn nodename() -> String {
    // SAFETY: an all-zero utsname is valid; uname fills it.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is valid for the call.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = uts
        .nodename
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_ascii_lowercase()
}

fn run_checked(args: &[String]) -> Result<(Op, Done), Fail> {
    let op = parse_args(args)?;
    // SAFETY: geteuid(2) cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let uid = parse_uid(crate::os::invoker_uid().as_deref()).filter(|_| root);
    uid.ok_or(Fail::NotPkexec)?;
    let node = nodename();
    check_reserved(&op, &node)?;
    let done = file::apply(&op, &node)?;
    Ok((op, done))
}

/// `--version` is an unprivileged convenience only; as root every invocation must be the protocol.
pub fn version_allowed(args: &[String], euid: u32) -> bool {
    euid != 0 && args == ["--version"]
}

/// One line to stdout; a closed pipe or any other error is ignored.
fn print_line(line: &str) {
    // SAFETY: ignoring SIGPIPE touches no memory.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let mut out = std::io::stdout();
    let _ = out.write_all(format!("{line}\n").as_bytes());
    let _ = out.flush();
}

pub fn run() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().unwrap_or_default())
        .collect();
    // SAFETY: geteuid(2) cannot fail.
    if version_allowed(&args, unsafe { libc::geteuid() }) {
        print_line(&format!("cainary-hosts-helper {VERSION} protocol 1"));
        exit(0);
    }
    // A panic must neither print to stderr nor claim a result: exit 3 with no reply is `uncertain`.
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(|| run_checked(&args)) {
        Ok(Ok((op, done))) => {
            print_line(&reply_ok(&op, &done));
            exit(0);
        }
        Ok(Err(fail)) => {
            print_line(&reply_error(&fail));
            exit(fail.exit_code());
        }
        Err(_) => exit(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(a: &[&str]) -> Vec<String> {
        a.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_args_accepts() {
        assert_eq!(parse_args(&s(&["clear"])), Ok(Op::Clear));
        assert_eq!(
            parse_args(&s(&["set", "a.example.com", "b.example.com"])),
            Ok(Op::Set(s(&["a.example.com", "b.example.com"])))
        );
        let eight: Vec<String> = (0..8).map(|i| format!("h{i}.example.com")).collect();
        let mut args = vec!["set".to_string()];
        args.extend(eight.clone());
        assert_eq!(parse_args(&args), Ok(Op::Set(eight)));
    }

    #[test]
    fn parse_args_rejects() {
        for bad in [
            &[][..],
            &["set"],
            &["clear", "a.example.com"],
            &["clear", ""],
            &["Set", "a.example.com"],
            &["--version"],
            &["a.example.com"],
            &["set", "A.example.com"],
            &["set", "a.example.com\n#x"],
            &["set", "a.b\n#x"],
            &["set", "localhost"],
            &["set", "*.example.com"],
            &["set", "1.2.3.4"],
            &["set", "a.example.com", "a.example.com"],
            &["set", ""],
            &["set", "a.example.com", ""],
            &["set", "a.example.com."],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(Fail::BadArgs), "{bad:?}");
        }
        let mut nine = vec!["set".to_string()];
        nine.extend((0..9).map(|i| format!("h{i}.example.com")));
        assert_eq!(parse_args(&nine), Err(Fail::TooMany));
        // Too many wins over an invalid name; a non-UTF-8 argument became "".
        nine.push("bad".into());
        assert_eq!(parse_args(&nine), Err(Fail::TooMany));
    }

    #[test]
    fn reserved_names() {
        for host in [
            "foo.localhost",
            "foo.localdomain",
            "localhost.localdomain",
            "localhost4.localdomain4",
            "localhost6.localdomain6",
            "myhost.corp.example",
            "myhost.example.com",
        ] {
            assert!(reserved(host, "myhost"), "{host}");
        }
        assert!(reserved("myhost.example.com", "myhost.lan"));
        assert!(!reserved("otel.example.com", "myhost"));
        assert!(!reserved("myhost2.example.com", "myhost"));
        // Without a node name only the static rules apply.
        assert!(!reserved("myhost.example.com", ""));
        assert!(reserved("a.localhost", ""));
        assert_eq!(
            check_reserved(&Op::Set(s(&["myhost.corp.example"])), "myhost"),
            Err(Fail::ReservedName)
        );
        assert_eq!(check_reserved(&Op::Clear, "myhost"), Ok(()));
    }

    #[test]
    fn valid_host_table() {
        for ok in [
            "otel.example-corp.test",
            "a.b",
            "x1.y2.z3.example",
            "a-b.c-d.io",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}example.com", "a.".repeat(130));
        for bad in [
            "",
            "localhost",
            "a..b",
            ".a.b",
            "a.b.",
            "a.b-",
            "-a.b",
            "A.b",
            "a_b.c",
            "a.b c",
            "1.2.3.4",
            "a.1",
            "*.a.b",
            "a.b\n",
            "ä.example.com",
            &long_label,
            &long_name,
        ] {
            assert!(!valid_host(bad), "{bad:?}");
        }
        assert!(valid_host(&format!("{}.com", "a".repeat(63))));
    }

    #[test]
    fn parse_uid_overflow() {
        assert_eq!(parse_uid(Some("0")), Some(0));
        assert_eq!(parse_uid(Some("1000")), Some(1000));
        assert_eq!(parse_uid(Some("4294967294")), Some(4294967294));
        for bad in [
            None,
            Some(""),
            Some("4294967295"),
            Some("4294967296"),
            Some("99999999999999999999"),
            Some("+1"),
            Some("-1"),
            Some("01"),
            Some("1 "),
            Some("0x10"),
        ] {
            assert_eq!(parse_uid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn version_refused_as_root() {
        assert!(version_allowed(&s(&["--version"]), 1000));
        assert!(!version_allowed(&s(&["--version"]), 0));
        assert!(!version_allowed(&s(&["--version", "x"]), 1000));
        assert!(!version_allowed(&s(&[]), 1000));
        assert_eq!(parse_args(&s(&["--version"])), Err(Fail::BadArgs));
    }

    #[test]
    fn reply_format_and_exit_codes() {
        let set = Op::Set(s(&["a.example.com"]));
        assert_eq!(
            reply_ok(&set, &Done::Changed),
            "cainary-hosts-helper/1 ok set changed"
        );
        assert_eq!(
            reply_ok(&Op::Clear, &Done::Unchanged),
            "cainary-hosts-helper/1 ok clear unchanged"
        );
        assert_eq!(
            reply_ok(&set, &Done::ChangedUnsynced),
            "cainary-hosts-helper/1 ok set changed-unsynced"
        );
        assert_eq!(
            reply_error(&Fail::DamagedBlock),
            "cainary-hosts-helper/1 error damaged-block"
        );
        for f in [
            Fail::BadArgs,
            Fail::NotPkexec,
            Fail::ReservedName,
            Fail::TooMany,
        ] {
            assert_eq!(f.exit_code(), 2, "{}", f.token());
        }
        for f in [
            Fail::Symlink,
            Fail::Busy,
            Fail::Changed,
            Fail::Label,
            Fail::ReadOnly,
            Fail::WriteFailed,
        ] {
            assert_eq!(f.exit_code(), 1, "{}", f.token());
        }
    }
}
