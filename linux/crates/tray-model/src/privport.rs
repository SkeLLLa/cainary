//! Binding a privileged (< 1024) loopback port through the root helper: where the helper and its
//! polkit policy must be, whether they can be trusted, and what the helper's one-line replies
//! mean. Nothing here starts a process or touches a socket; `runner::bind_privileged` does that.
//!
//! The helper runs as root, so the tray refuses to ask for it unless the file, the policy that
//! authorises exactly that file, and every directory above both belong to root and can't be
//! changed by anyone else. The walk is descriptor-relative from `/` (`openat` with
//! `O_NOFOLLOW` on every component), so a symlink or a swapped directory can't redirect it.
//! The two fixed install paths are the only places looked at: there is no environment override.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};

/// Where the distribution package puts the helper.
pub const HELPER_PACKAGED: &str = "/usr/libexec/cainary/cainary-bind-helper";
/// Where an administrator or a developer installs it by hand.
pub const HELPER_LOCAL: &str = "/usr/local/libexec/cainary/cainary-bind-helper";
pub const POLICY_PACKAGED: &str = "/usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.policy";
pub const POLICY_LOCAL: &str = "/usr/share/polkit-1/actions/ua.SkeLLLa.cAInary.local.policy";
pub const ACTION_PACKAGED: &str = "ua.SkeLLLa.cAInary.bind-loopback-port";
pub const ACTION_LOCAL: &str = "ua.SkeLLLa.cAInary.bind-loopback-port.local";

/// The word the helper's `--version` output and replies start with, up to the protocol number.
const PROTOCOL_PREFIX: &str = "cainary-bind-helper/";
const PROGRAM: &str = "cainary-bind-helper";
/// The protocol this tray speaks.
pub const PROTOCOL: u32 = 1;
const UNPRIVILEGED_PORT_START: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
const POLICY_LIMIT: u64 = 64 << 10;

/// One helper install location and the policy that authorises exactly it.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub helper: &'static str,
    pub policy: &'static str,
    pub action: &'static str,
}

/// In order of preference.
pub const CANDIDATES: [Candidate; 2] = [
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
];

/// The lowest port a non-root user may bind (1024 unless the sysctl says otherwise).
pub fn unprivileged_port_start() -> u32 {
    std::fs::read_to_string(UNPRIVILEGED_PORT_START)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(1024)
}

/// Whether binding `port` needs root, given the lowest unprivileged port.
pub fn needs_privilege_with(port: u16, unprivileged_start: u32) -> bool {
    u32::from(port) < unprivileged_start
}

pub fn needs_privilege(port: u16) -> bool {
    needs_privilege_with(port, unprivileged_port_start())
}

/// What the tray knows about reaching a port that needs root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivState {
    /// An ordinary port: the collector binds it itself.
    NotNeeded,
    /// No usable helper; the text says why, for the settings page.
    NoHelper(String),
    /// A trusted helper and policy are installed; asking would show the authentication prompt.
    Ready { helper: PathBuf, policy: PathBuf },
    /// The tray already holds the reserved sockets for this port.
    Held(u16),
    /// A trusted helper of another build: still used, but the user is told.
    Mismatch {
        helper: PathBuf,
        policy: PathBuf,
        warn: String,
    },
}

/// Where the trust walk starts and whose files count as trusted. Production is `/` and uid 0;
/// tests build a fake tree in which "root" is their own uid.
#[derive(Clone, Debug)]
pub struct TrustEnv {
    pub root: PathBuf,
    pub uid: u32,
    /// The extended attribute whose presence means the helper has file capabilities.
    pub capability_xattr: &'static str,
}

impl TrustEnv {
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            uid: 0,
            capability_xattr: "security.capability",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// Nothing there (a missing component): the caller moves on to the next location.
    Missing,
    /// Something is there and can't be trusted.
    Untrusted(String),
}

impl TrustError {
    pub fn reason(&self) -> String {
        match self {
            Self::Missing => "not installed".into(),
            Self::Untrusted(why) => why.clone(),
        }
    }
}

fn untrusted<T>(why: impl Into<String>) -> Result<T, TrustError> {
    Err(TrustError::Untrusted(why.into()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaf {
    Helper,
    Policy,
}

fn cstr(name: &std::ffi::OsStr) -> Result<CString, TrustError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(name.as_bytes()).map_err(|_| TrustError::Untrusted("path has a NUL".into()))
}

fn openat(dir: RawFd, name: &CString, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated and `dir` is a live descriptor.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new descriptor we own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn fstat(fd: RawFd) -> Result<libc::stat, TrustError> {
    // SAFETY: `stat` is plain data and `fd` is live.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return untrusted(format!("can't stat: {}", io::Error::last_os_error()));
    }
    Ok(stat)
}

/// Whether `name` in `dir` is a symlink, for a better message than "not a directory".
fn names_a_link(dir: RawFd, name: &CString) -> bool {
    // SAFETY: as above.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    rc == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn check_protected(stat: &libc::stat, env: &TrustEnv, what: &str) -> Result<(), TrustError> {
    if stat.st_uid != env.uid {
        return untrusted(format!("{what} is not owned by root"));
    }
    if stat.st_mode & (libc::S_IWGRP | libc::S_IWOTH) != 0 {
        return untrusted(format!("{what} is writable by group or others"));
    }
    Ok(())
}

/// Opens `path` below `env.root`, requiring every directory on the way (and the root itself) to
/// be a protected, non-symlink directory. Returns the leaf, opened for reading.
fn walk(env: &TrustEnv, path: &Path, kind: Leaf) -> Result<OwnedFd, TrustError> {
    let mut names = Vec::new();
    let mut absolute = false;
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::Normal(name) => names.push(name),
            _ => return untrusted("path is not canonical"),
        }
    }
    let Some((leaf, dirs)) = names.split_last().filter(|_| absolute) else {
        return untrusted("path is not absolute");
    };

    let root = cstr(env.root.as_os_str())?;
    let mut dir = match openat(
        libc::AT_FDCWD,
        &root,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY,
    ) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Err(TrustError::Missing),
        Err(e) => return untrusted(format!("can't open the root directory: {e}")),
    };
    check_protected(&fstat(dir.as_raw_fd())?, env, "the root directory")?;

    let mut walked = PathBuf::from("/");
    for name in dirs {
        walked.push(name);
        let c = cstr(name)?;
        let next = match openat(
            dir.as_raw_fd(),
            &c,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        ) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Err(TrustError::Missing),
            Err(_) if names_a_link(dir.as_raw_fd(), &c) => {
                return untrusted(format!("{} is a symlink", walked.display()));
            }
            Err(e) => return untrusted(format!("{}: {e}", walked.display())),
        };
        let stat = fstat(next.as_raw_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return untrusted(format!("{} is not a directory", walked.display()));
        }
        check_protected(&stat, env, &walked.display().to_string())?;
        dir = next;
    }

    let c = cstr(leaf)?;
    walked.push(leaf);
    let what = walked.display().to_string();
    let pinned = match openat(dir.as_raw_fd(), &c, libc::O_PATH | libc::O_NOFOLLOW) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Err(TrustError::Missing),
        Err(e) => return untrusted(format!("{what}: {e}")),
    };
    let stat = fstat(pinned.as_raw_fd())?;
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => {}
        libc::S_IFLNK => return untrusted(format!("{what} is a symlink")),
        _ => return untrusted(format!("{what} is not a regular file")),
    }
    check_protected(&stat, env, &what)?;
    if kind == Leaf::Helper && stat.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
        return untrusted(format!("{what} is setuid or setgid"));
    }

    // An O_PATH descriptor can't be read (nor asked for xattrs): open the same file for reading
    // and make sure it is the one that was checked.
    let file = openat(
        dir.as_raw_fd(),
        &c,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(|e| TrustError::Untrusted(format!("{what}: {e}")))?;
    let again = fstat(file.as_raw_fd())?;
    if again.st_dev != stat.st_dev || again.st_ino != stat.st_ino || again.st_mode != stat.st_mode {
        return untrusted(format!("{what} changed while it was checked"));
    }
    if kind == Leaf::Helper {
        match has_xattr(file.as_raw_fd(), env.capability_xattr) {
            Ok(false) => {}
            Ok(true) => return untrusted(format!("{what} has file capabilities")),
            Err(e) => return untrusted(format!("{what}: can't read its attributes: {e}")),
        }
    }
    Ok(file)
}

fn has_xattr(fd: RawFd, name: &str) -> io::Result<bool> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: a zero-length query writes nothing.
    let rc = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
    if rc >= 0 {
        return Ok(true);
    }
    match io::Error::last_os_error() {
        e if e.raw_os_error() == Some(libc::ENODATA) => Ok(false),
        // No xattr support means no file capabilities either.
        e if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(false),
        e => Err(e),
    }
}

/// Whether `path` is a trusted helper binary (and so is everything above it).
pub fn check_helper(env: &TrustEnv, path: &Path) -> Result<(), TrustError> {
    walk(env, path, Leaf::Helper).map(drop)
}

/// The text of a trusted policy file (and so everything above it is trusted).
pub fn read_policy(env: &TrustEnv, path: &Path) -> Result<String, TrustError> {
    let file = walk(env, path, Leaf::Policy)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        // SAFETY: reads into a live buffer of the stated length from a descriptor we own.
        let n = unsafe { libc::read(file.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        match n {
            0 => break,
            n if n > 0 => bytes.extend_from_slice(&chunk[..n as usize]),
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            _ => {
                let why = io::Error::last_os_error();
                return untrusted(format!("can't read the policy: {why}"));
            }
        }
        if bytes.len() as u64 > POLICY_LIMIT {
            return untrusted("the policy file is too large");
        }
    }
    String::from_utf8(bytes).or_else(|_| untrusted("the policy file isn't UTF-8"))
}

/// The text between `<tag>` and `</tag>` when the tag occurs exactly once, else `None`.
fn only_element<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if text.matches(&format!("<{tag}")).count() != 1 || text.matches(&close).count() != 1 {
        return None;
    }
    let start = text.find(&open)? + open.len();
    let end = text.find(&close)?;
    (start <= end).then(|| text[start..end].trim())
}

fn strip_comments(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("-->")?;
        rest = &rest[start + end + 3..];
    }
    out.push_str(rest);
    Some(out)
}

/// Checks that `text` is a polkit policy that authorises exactly `action` for exactly `helper`,
/// only for an active local session after administrator authentication. The parser is
/// deliberately narrow: anything it doesn't understand is a mismatch.
pub fn check_policy_text(text: &str, action: &str, helper: &str) -> Result<(), String> {
    let mismatch = |why: &str| Err(format!("the polkit policy doesn't match: {why}"));
    let Some(text) = strip_comments(text) else {
        return mismatch("unterminated comment");
    };
    if text.contains("<![CDATA[") || text.contains("<!ENTITY") {
        return mismatch("unsupported markup");
    }
    if text.matches("<action ").count() + text.matches("<action>").count() != 1
        || text.matches("</action>").count() != 1
    {
        return mismatch("expected exactly one action");
    }
    if !text.contains(&format!("<action id=\"{action}\">")) {
        return mismatch("wrong action id");
    }
    let start = text.find("<action ").unwrap_or(0);
    let end = text.find("</action>").unwrap_or(0);
    if start >= end {
        return mismatch("malformed action");
    }
    let body = &text[start..end];
    for (tag, want) in [
        ("allow_any", "no"),
        ("allow_inactive", "no"),
        ("allow_active", "auth_admin"),
    ] {
        match only_element(body, tag) {
            Some(value) if value == want => {}
            Some(_) => return mismatch(&format!("{tag} must be {want}")),
            None => return mismatch(&format!("{tag} must appear once")),
        }
    }
    let key = "<annotate key=\"org.freedesktop.policykit.exec.path\">";
    if body.matches("org.freedesktop.policykit.exec.path").count() != 1 || !body.contains(key) {
        return mismatch("exec.path must appear once");
    }
    let after = &body[body.find(key).unwrap_or(0) + key.len()..];
    let Some(value) = after.split("</annotate>").next().map(str::trim) else {
        return mismatch("malformed exec.path");
    };
    if value != helper {
        return mismatch("exec.path is not the installed helper");
    }
    Ok(())
}

/// What `<helper> --version` told us, judged against this build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionCheck {
    Match,
    /// Same protocol, other build: usable, the user is told.
    Mismatch(String),
    /// Another protocol (or no answer): not used.
    Blocked(String),
}

/// `cainary-bind-helper <version> protocol <N>`, the helper's `--version` line. The tray runs it
/// unprivileged and directly (never through pkexec), with a short timeout and bounded stdout.
pub fn check_version(output: &str, expected_version: &str) -> VersionCheck {
    let line = output.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let words: Vec<&str> = line.split_whitespace().collect();
    let [PROGRAM, version, "protocol", protocol] = words.as_slice() else {
        return VersionCheck::Blocked(
            "the helper didn't identify itself. Update the helper".into(),
        );
    };
    if *protocol != PROTOCOL.to_string() {
        return VersionCheck::Blocked(format!(
            "the helper speaks protocol {protocol}, this app speaks {PROTOCOL}. Update the helper"
        ));
    }
    if *version == expected_version {
        VersionCheck::Match
    } else {
        VersionCheck::Mismatch(format!(
            "the helper is version {version}, this app is {expected_version}"
        ))
    }
}

/// Works out the state for `port`. `held` is whether the tray already holds the sockets;
/// `version` runs `<helper> --version` (the caller decides how, normally through the runner).
pub fn assess(
    port: u16,
    held: bool,
    unprivileged_start: u32,
    env: &TrustEnv,
    version: impl Fn(&Path) -> Result<String, String>,
) -> PrivState {
    if !needs_privilege_with(port, unprivileged_start) {
        return PrivState::NotNeeded;
    }
    if held {
        return PrivState::Held(port);
    }
    let mut first_problem = None;
    for candidate in CANDIDATES {
        let helper = PathBuf::from(candidate.helper);
        let policy = PathBuf::from(candidate.policy);
        match check_helper(env, &helper) {
            Ok(()) => {}
            Err(TrustError::Missing) => continue,
            Err(e) => {
                first_problem.get_or_insert(format!("{}: {}", candidate.helper, e.reason()));
                continue;
            }
        }
        let policy_ok = match read_policy(env, &policy) {
            Ok(text) => check_policy_text(&text, candidate.action, candidate.helper),
            Err(TrustError::Missing) => Err("the polkit policy for the helper is missing".into()),
            Err(e) => Err(e.reason()),
        };
        if let Err(why) = policy_ok {
            first_problem.get_or_insert(why);
            continue;
        }
        match version(&helper) {
            Err(why) => {
                first_problem.get_or_insert(format!("couldn't ask the helper its version: {why}"));
            }
            Ok(output) => match check_version(&output, env!("CARGO_PKG_VERSION")) {
                VersionCheck::Match => return PrivState::Ready { helper, policy },
                VersionCheck::Mismatch(warn) => {
                    return PrivState::Mismatch {
                        helper,
                        policy,
                        warn,
                    };
                }
                VersionCheck::Blocked(why) => {
                    first_problem.get_or_insert(why);
                }
            },
        }
    }
    PrivState::NoHelper(first_problem.unwrap_or_else(|| "the port helper isn't installed".into()))
}

/// Why the helper refused (its `error <code>` replies).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperError {
    PortInUse,
    BadArgs,
    BadChannel,
    BindFailed,
    NotPkexec,
    SendFailed,
}

impl HelperError {
    fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "port-in-use" => Self::PortInUse,
            "bad-args" => Self::BadArgs,
            "bad-channel" => Self::BadChannel,
            "bind-failed" => Self::BindFailed,
            "not-pkexec" => Self::NotPkexec,
            "send-failed" => Self::SendFailed,
            _ => return None,
        })
    }
}

/// A decoded helper reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Ok {
        port: u16,
        count: usize,
        version: String,
        ipv6_unavailable: bool,
    },
    Error(HelperError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyError {
    Malformed,
    /// Another protocol number.
    Protocol(String),
}

/// Decodes one reply datagram. Strict: any deviation is an error, never a guess.
pub fn parse_reply(bytes: &[u8]) -> Result<Reply, ReplyError> {
    if bytes.len() > 256 {
        return Err(ReplyError::Malformed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ReplyError::Malformed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let words: Vec<&str> = text.split(' ').collect();
    let Some(protocol) = words
        .first()
        .and_then(|word| word.strip_prefix(PROTOCOL_PREFIX))
    else {
        return Err(ReplyError::Malformed);
    };
    if protocol != PROTOCOL.to_string() {
        let printable = protocol.chars().take(8).filter(char::is_ascii_graphic);
        return Err(ReplyError::Protocol(printable.collect()));
    }
    match words.as_slice() {
        [_, "error", code] => HelperError::parse(code)
            .map(Reply::Error)
            .ok_or(ReplyError::Malformed),
        [_, "ok", port, count, version, rest @ ..] => {
            let ipv6_unavailable = match rest {
                [] => false,
                ["ipv6-unavailable"] => true,
                _ => return Err(ReplyError::Malformed),
            };
            let port: u16 = port.parse().map_err(|_| ReplyError::Malformed)?;
            let count: usize = count.parse().map_err(|_| ReplyError::Malformed)?;
            let version_ok = !version.is_empty()
                && version.len() <= 32
                && version.bytes().all(|b| b.is_ascii_graphic());
            // Two sockets, or one exactly when IPv6 was reported unavailable.
            let count_ok = count == if ipv6_unavailable { 1 } else { 2 };
            if port == 0 || !version_ok || !count_ok {
                return Err(ReplyError::Malformed);
            }
            Ok(Reply::Ok {
                port,
                count,
                version: (*version).to_owned(),
                ipv6_unavailable,
            })
        }
        _ => Err(ReplyError::Malformed),
    }
}
