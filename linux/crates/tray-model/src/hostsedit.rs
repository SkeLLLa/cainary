//! Editing `/etc/hosts` through the root helper `cainary-hosts-helper`: where the helper and its
//! polkit policy must be, whether they can be trusted, what may be asked of it, and what its
//! one-line replies mean. Nothing here starts a process; `runner::edit_hosts` does that.
//!
//! The trust walk, the policy check and the reply framing are `privport`'s, with this helper's
//! identity (program name, protocol, install paths, policy files, action ids) as parameters. The
//! two fixed install paths are the only places looked at: there is no environment override, and
//! the test entry points exist only under `cfg(test)` / the `test-fakes` feature.
//!
//! The helper's contract (protocol 1): `set HOST [HOST…]` or `clear`, one reply line on stdout,
//! exit 0 on `ok`, 2 on a refused precondition, 1 on any other error, 3 on a panic (no reply).
//! The rename of `/etc/hosts` is its commit point: every `error` happens before it.

use std::path::Path;

use crate::privport::{self, Candidate, HelperSpec, ReplyError, Selection, TrustEnv};
use crate::settings::valid_tls_host;

/// Where the distribution package puts the helper.
pub const HELPER_PACKAGED: &str = "/usr/libexec/cainary/cainary-hosts-helper";
/// Where an administrator or a developer installs it by hand.
pub const HELPER_LOCAL: &str = "/usr/local/libexec/cainary/cainary-hosts-helper";
pub const POLICY_PACKAGED: &str = "/usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.policy";
pub const POLICY_LOCAL: &str = "/usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.hosts.local.policy";
pub const ACTION_PACKAGED: &str = "ua.SkeLLLa.cAInary.edit-hosts";
pub const ACTION_LOCAL: &str = "ua.SkeLLLa.cAInary.edit-hosts.local";

/// The protocol this tray speaks to the hosts helper.
pub const PROTOCOL: u32 = 1;
/// The most names one edit may carry (the helper refuses more).
pub const MAX_EDIT_HOSTS: usize = 8;

/// The hosts helper, in order of preference.
pub const SPEC: HelperSpec = HelperSpec {
    program: "cainary-hosts-helper",
    protocol_prefix: "cainary-hosts-helper/",
    protocol: PROTOCOL,
    noun: "the hosts helper",
    candidates: [
        Candidate {
            helper: HELPER_PACKAGED,
            policy: POLICY_PACKAGED,
            action: ACTION_PACKAGED,
        },
        Candidate {
            helper: HELPER_LOCAL,
            policy: POLICY_LOCAL,
            action: ACTION_LOCAL,
        },
    ],
};

// ---- the request ------------------------------------------------------------------------------

/// What to ask the helper. Can only be built from names the helper would accept, so the pkexec
/// command line never carries anything it would have to refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostsOp {
    /// Replace the managed block with exactly these names (1 to 8, valid, distinct, lowercase).
    Set(Vec<String>),
    /// Remove the managed block.
    Clear,
}

impl HostsOp {
    pub fn set(hosts: &[String]) -> Result<Self, String> {
        if hosts.is_empty() {
            return Err("no host names".into());
        }
        if hosts.len() > MAX_EDIT_HOSTS {
            return Err(format!("more than {MAX_EDIT_HOSTS} host names"));
        }
        for (index, host) in hosts.iter().enumerate() {
            if !valid_tls_host(host) {
                return Err(format!("{host:?} is not a valid host name"));
            }
            if hosts[..index].contains(host) {
                return Err(format!("{host:?} appears twice"));
            }
        }
        Ok(Self::Set(hosts.to_vec()))
    }

    /// The command word, as it appears on the command line and in the reply.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Set(_) => "set",
            Self::Clear => "clear",
        }
    }
}

// ---- trust ------------------------------------------------------------------------------------

/// A hosts helper and policy that passed the trust walk. Only this module can make one, and
/// `runner::edit_hosts` accepts nothing else; it walks again right before it runs pkexec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHostsHelper(privport::VerifiedHelper);

impl VerifiedHostsHelper {
    pub fn helper_path(&self) -> &Path {
        self.0.helper_path()
    }

    pub fn policy_path(&self) -> &Path {
        self.0.policy_path()
    }

    /// Runs the whole trust walk again (helper, its chain, the policy and its content).
    pub fn recheck(&self) -> Result<(), String> {
        self.0.recheck()
    }
}

/// What the tray knows about editing `/etc/hosts` through the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostsHelperState {
    /// A trusted helper and policy are installed; asking would show the authentication prompt.
    Ready { helper: VerifiedHostsHelper },
    /// A trusted helper of another build: still used, but the user is told.
    Mismatch {
        helper: VerifiedHostsHelper,
        warn: String,
    },
    /// No usable helper; the text says why, for the step's hint.
    NoHelper(String),
    /// Running inside a sandbox: the button is hidden and the manual lines stay.
    Sandboxed,
}

/// Whether `/.flatpak-info` exists or `$container` is set.
fn sandboxed_with(flatpak_info: bool, container: Option<&std::ffi::OsStr>) -> bool {
    flatpak_info || container.is_some()
}

fn sandboxed() -> bool {
    sandboxed_with(
        Path::new("/.flatpak-info").exists(),
        std::env::var_os("container").as_deref(),
    )
}

/// The state against the real system. `version` runs `<helper> --version` (unprivileged,
/// directly).
pub fn assess(version: impl Fn(&Path) -> Result<String, String>) -> HostsHelperState {
    assess_with(sandboxed(), &TrustEnv::system(), version)
}

/// [`assess`] against a fake tree and an injected sandbox flag, for tests.
#[cfg(any(test, feature = "test-fakes"))]
pub fn assess_hosts_in(
    sandboxed: bool,
    env: &TrustEnv,
    version: impl Fn(&Path) -> Result<String, String>,
) -> HostsHelperState {
    assess_with(sandboxed, env, version)
}

fn assess_with(
    sandboxed: bool,
    env: &TrustEnv,
    version: impl Fn(&Path) -> Result<String, String>,
) -> HostsHelperState {
    if sandboxed {
        return HostsHelperState::Sandboxed;
    }
    match privport::select(env, &SPEC, version) {
        Selection::Ready(helper) => HostsHelperState::Ready {
            helper: VerifiedHostsHelper(helper),
        },
        Selection::Mismatch(helper, warn) => HostsHelperState::Mismatch {
            helper: VerifiedHostsHelper(helper),
            warn,
        },
        Selection::Unavailable(problem) => HostsHelperState::NoHelper(
            problem.unwrap_or_else(|| "the hosts helper isn't installed".into()),
        ),
    }
}

/// The trust walk for one hosts-helper candidate against a fake tree, for tests.
#[cfg(any(test, feature = "test-fakes"))]
pub fn verify_hosts_in(
    env: &TrustEnv,
    candidate: Candidate,
) -> Result<VerifiedHostsHelper, privport::TrustError> {
    privport::verify_candidate(env, candidate).map(VerifiedHostsHelper)
}

// ---- the helper's reply -----------------------------------------------------------------------

/// Why the helper refused (its `error <token>` replies), and the exit code that goes with each.
/// The one table: a token the helper may print is listed here and nowhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostsError {
    BadArgs,
    NotPkexec,
    ReservedName,
    TooMany,
    Symlink,
    NotRegular,
    Unprotected,
    MountPoint,
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

/// Token, error, exit code. Exit 2 is a refused precondition, 1 any other error.
pub const TOKENS: [(&str, HostsError, i32); 18] = [
    ("bad-args", HostsError::BadArgs, 2),
    ("not-pkexec", HostsError::NotPkexec, 2),
    ("reserved-name", HostsError::ReservedName, 2),
    ("too-many", HostsError::TooMany, 2),
    ("symlink", HostsError::Symlink, 1),
    ("not-regular", HostsError::NotRegular, 1),
    ("unprotected", HostsError::Unprotected, 1),
    ("mount-point", HostsError::MountPoint, 1),
    ("no-mount-id", HostsError::NoMountId, 1),
    ("hardlinked", HostsError::Hardlinked, 1),
    ("too-large", HostsError::TooLarge, 1),
    ("damaged-block", HostsError::DamagedBlock, 1),
    ("bad-lock", HostsError::BadLock, 1),
    ("busy", HostsError::Busy, 1),
    ("changed", HostsError::Changed, 1),
    ("label", HostsError::Label, 1),
    ("read-only", HostsError::ReadOnly, 1),
    ("write-failed", HostsError::WriteFailed, 1),
];

impl HostsError {
    pub fn parse(token: &str) -> Option<Self> {
        TOKENS
            .iter()
            .find(|(name, _, _)| *name == token)
            .map(|(_, error, _)| *error)
    }

    pub fn token(self) -> &'static str {
        TOKENS
            .iter()
            .find(|(_, error, _)| *error == self)
            .map_or("", |(name, _, _)| name)
    }

    /// The exit code the helper uses with this token.
    pub fn exit_code(self) -> i32 {
        TOKENS
            .iter()
            .find(|(_, error, _)| *error == self)
            .map_or(1, |(_, _, code)| *code)
    }
}

/// What an `ok` reply says happened to `/etc/hosts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Changed,
    Unchanged,
    /// Replaced, but the directory sync failed: durability is uncertain.
    ChangedUnsynced,
}

/// A decoded helper reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `ok set|clear changed|unchanged|changed-unsynced`; `op` is the command word echoed back.
    Ok {
        op: &'static str,
        change: Change,
    },
    Error(HostsError),
}

/// The longest reply line the tray reads (the real ones are under 80 bytes).
const REPLY_LIMIT: usize = 256;

/// Decodes the helper's stdout. Strict: exactly one line ending in exactly one `\n`, single
/// spaces, a known token or a known change word. Any deviation is an error, never a guess.
pub fn parse_reply(bytes: &[u8]) -> Result<Reply, ReplyError> {
    if bytes.len() > REPLY_LIMIT {
        return Err(ReplyError::Malformed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ReplyError::Malformed)?;
    let line = text.strip_suffix('\n').ok_or(ReplyError::Malformed)?;
    if line.contains(['\n', '\r']) {
        return Err(ReplyError::Malformed);
    }
    let words = privport::reply_words(&SPEC, line)?;
    match words.as_slice() {
        [_, "error", token] => HostsError::parse(token)
            .map(Reply::Error)
            .ok_or(ReplyError::Malformed),
        [_, "ok", op, change] => {
            let op = match *op {
                "set" => "set",
                "clear" => "clear",
                _ => return Err(ReplyError::Malformed),
            };
            let change = match *change {
                "changed" => Change::Changed,
                "unchanged" => Change::Unchanged,
                "changed-unsynced" => Change::ChangedUnsynced,
                _ => return Err(ReplyError::Malformed),
            };
            Ok(Reply::Ok { op, change })
        }
        _ => Err(ReplyError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn ops_are_validated() {
        assert!(HostsOp::set(&names(&["otel.example.com"])).is_ok());
        let eight: Vec<String> = (0..8).map(|i| format!("h{i}.example.com")).collect();
        assert!(HostsOp::set(&eight).is_ok());
        let nine: Vec<String> = (0..9).map(|i| format!("h{i}.example.com")).collect();
        assert!(HostsOp::set(&nine).is_err());
        for bad in [
            names(&[]),
            names(&["localhost"]),
            names(&["A.example.com"]),
            names(&["a.example.com", "a.example.com"]),
            names(&["a.example.com\n#x"]),
            names(&["-x.example.com"]),
            names(&["*.example.com"]),
            names(&["1.2.3.4"]),
        ] {
            assert!(HostsOp::set(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(HostsOp::Clear.word(), "clear");
    }

    #[test]
    fn token_table_round_trips() {
        for (token, error, code) in TOKENS {
            assert_eq!(HostsError::parse(token), Some(error));
            assert_eq!(error.token(), token);
            assert_eq!(error.exit_code(), code);
        }
        assert_eq!(HostsError::parse("nope"), None);
        let mut seen: Vec<&str> = TOKENS.iter().map(|(t, _, _)| *t).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), TOKENS.len());
    }

    #[test]
    fn reply_grammar() {
        let ok = |text: &str| parse_reply(text.as_bytes());
        assert_eq!(
            ok("cainary-hosts-helper/1 ok set changed\n"),
            Ok(Reply::Ok {
                op: "set",
                change: Change::Changed
            })
        );
        assert_eq!(
            ok("cainary-hosts-helper/1 ok clear unchanged\n"),
            Ok(Reply::Ok {
                op: "clear",
                change: Change::Unchanged
            })
        );
        assert_eq!(
            ok("cainary-hosts-helper/1 ok set changed-unsynced\n"),
            Ok(Reply::Ok {
                op: "set",
                change: Change::ChangedUnsynced
            })
        );
        assert_eq!(
            ok("cainary-hosts-helper/1 error damaged-block\n"),
            Ok(Reply::Error(HostsError::DamagedBlock))
        );
        for text in [
            "",
            "\n",
            "cainary-hosts-helper/1 ok set changed",
            "cainary-hosts-helper/1 ok set changed\n\n",
            "cainary-hosts-helper/1 ok set changed\nextra\n",
            "cainary-hosts-helper/1 ok set changed\r\n",
            "cainary-hosts-helper/1  ok set changed\n",
            "cainary-hosts-helper/1 ok set changed \n",
            "cainary-hosts-helper/1 ok set\n",
            "cainary-hosts-helper/1 ok add changed\n",
            "cainary-hosts-helper/1 ok set maybe\n",
            "cainary-hosts-helper/1 ok set changed extra\n",
            "cainary-hosts-helper/1 error\n",
            "cainary-hosts-helper/1 error nope\n",
            "cainary-hosts-helper/1 error busy extra\n",
            "cainary-hosts-helper/1 OK set changed\n",
            "cainary-bind-helper/1 ok set changed\n",
            "hello there\n",
        ] {
            assert_eq!(ok(text), Err(ReplyError::Malformed), "{text:?}");
        }
        assert_eq!(
            parse_reply(&[0xff, 0xfe, b'\n']),
            Err(ReplyError::Malformed)
        );
        assert_eq!(
            ok("cainary-hosts-helper/2 ok set changed\n"),
            Err(ReplyError::Protocol("2".into()))
        );
        assert_eq!(
            ok("cainary-hosts-helper/2 whatever\n"),
            Err(ReplyError::Protocol("2".into()))
        );
        let long = format!("cainary-hosts-helper/1 error {}\n", "x".repeat(300));
        assert_eq!(ok(&long), Err(ReplyError::Malformed));
    }

    #[test]
    fn sandbox_detection() {
        assert!(sandboxed_with(true, None));
        assert!(sandboxed_with(false, Some(std::ffi::OsStr::new("podman"))));
        assert!(!sandboxed_with(false, None));
    }

    #[test]
    fn version_line_is_this_helpers() {
        use privport::{VersionCheck, check_version_for};
        let v = env!("CARGO_PKG_VERSION");
        assert_eq!(
            check_version_for(&SPEC, &format!("cainary-hosts-helper {v} protocol 1\n"), v),
            VersionCheck::Match
        );
        // The bind helper's line is not this helper's.
        assert!(matches!(
            check_version_for(&SPEC, &format!("cainary-bind-helper {v} protocol 1\n"), v),
            VersionCheck::Blocked(_)
        ));
        match check_version_for(&SPEC, &format!("cainary-hosts-helper {v} protocol 2\n"), v) {
            VersionCheck::Blocked(why) => assert!(why.contains("Update the hosts helper"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            check_version_for(&SPEC, "cainary-hosts-helper 0.0.1 protocol 1\n", v),
            VersionCheck::Mismatch(_)
        ));
    }
}
