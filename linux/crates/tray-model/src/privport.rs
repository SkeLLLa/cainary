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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    Ready { helper: VerifiedHelper },
    /// The tray already holds the reserved sockets for this port.
    Held(u16),
    /// A trusted helper of another build: still used, but the user is told.
    Mismatch {
        helper: VerifiedHelper,
        warn: String,
    },
}

/// A helper and policy that passed the trust walk. Only this module can make one, and
/// `runner::bind_privileged` accepts nothing else; it walks again right before it runs pkexec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHelper {
    candidate: Candidate,
    env: TrustEnv,
}

impl VerifiedHelper {
    pub fn helper_path(&self) -> &Path {
        Path::new(self.candidate.helper)
    }

    pub fn policy_path(&self) -> &Path {
        Path::new(self.candidate.policy)
    }

    /// Runs the whole trust walk again (helper, its chain, the policy and its content).
    pub fn recheck(&self) -> Result<(), String> {
        verify(&self.env, self.candidate)
            .map(drop)
            .map_err(|e| e.reason())
    }
}

fn verify(env: &TrustEnv, candidate: Candidate) -> Result<VerifiedHelper, TrustError> {
    check_helper(env, Path::new(candidate.helper))?;
    let text = read_policy(env, Path::new(candidate.policy)).map_err(|e| match e {
        TrustError::Missing => {
            TrustError::Untrusted("the polkit policy for the helper is missing".into())
        }
        other => other,
    })?;
    check_policy_text(&text, candidate.action, candidate.helper).map_err(TrustError::Untrusted)?;
    Ok(VerifiedHelper {
        candidate,
        env: env.clone(),
    })
}

/// Where the trust walk starts and whose files count as trusted. Production is `/` and uid 0;
/// tests build a fake tree in which "root" is their own uid.
#[derive(Clone, Debug, PartialEq, Eq)]
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

// ---- polkit policy: a small strict XML reader ---------------------------------------------------
//
// The policy decides who may run the root helper, so it is read structurally, not searched: a
// tag that merely appears inside a comment, a processing instruction or an attribute must not
// count. Only what a policy file needs is accepted (declaration, the polkit DOCTYPE, elements,
// attributes, text, comments); everything else is an error.

const DOCTYPE_PUBLIC: [&str; 2] = [
    "-//freedesktop//DTD polkit Policy Configuration 1.0//EN",
    "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN",
];
const DOCTYPE_SYSTEM: &str = "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd";
const EXEC_PATH_KEY: &str = "org.freedesktop.policykit.exec.path";
const MAX_DEPTH: usize = 12;

#[derive(Debug)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

#[derive(Debug)]
enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn elements<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter_map(move |node| match node {
            Node::Element(e) if e.name == name => Some(e),
            _ => None,
        })
    }

    /// The element's text, if it holds nothing else.
    fn only_text(&self) -> Option<String> {
        let mut text = String::new();
        for node in &self.children {
            match node {
                Node::Text(t) => text.push_str(t),
                Node::Element(_) => return None,
            }
        }
        Some(text.trim().to_owned())
    }

    fn count_named(&self, name: &str) -> usize {
        usize::from(self.name == name)
            + self
                .children
                .iter()
                .map(|node| match node {
                    Node::Element(e) => e.count_named(name),
                    Node::Text(_) => 0,
                })
                .sum::<usize>()
    }
}

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn eat(&mut self, token: &str) -> bool {
        let found = self.rest().starts_with(token);
        if found {
            self.at += token.len();
        }
        found
    }

    fn skip_space(&mut self) -> bool {
        let before = self.at;
        while self.rest().starts_with([' ', '\t', '\r', '\n']) {
            self.at += 1;
        }
        self.at > before
    }

    /// Skips a `<!-- … -->` comment if one starts here.
    fn comment(&mut self) -> Result<bool, String> {
        if !self.eat("<!--") {
            return Ok(false);
        }
        match self.rest().find("-->") {
            Some(end) => {
                self.at += end + 3;
                Ok(true)
            }
            None => Err("unterminated comment".into()),
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let start = self.at;
        while let Some(c) = self.rest().chars().next() {
            let ok = c.is_ascii_alphabetic()
                || c == '_'
                || (self.at > start && (c.is_ascii_digit() || matches!(c, '-' | '.' | ':')));
            if !ok {
                break;
            }
            self.at += 1;
        }
        if self.at == start {
            Err("expected a name".into())
        } else {
            Ok(self.text[start..self.at].to_owned())
        }
    }

    fn quoted(&mut self) -> Result<String, String> {
        let quote = match self.rest().chars().next() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err("expected a quoted value".into()),
        };
        self.at += 1;
        let end = self.rest().find(quote).ok_or("unterminated value")?;
        let raw = &self.rest()[..end];
        self.at += end + 1;
        if raw.contains('<') {
            return Err("'<' in an attribute value".into());
        }
        decode_entities(raw)
    }

    fn declaration(&mut self) -> Result<(), String> {
        if self.rest().starts_with("<?xml") && self.rest()[5..].starts_with([' ', '\t', '\r', '\n'])
        {
            let end = self.rest().find("?>").ok_or("unterminated declaration")?;
            if self.rest()[5..end].contains(['<', '&']) {
                return Err("malformed declaration".into());
            }
            self.at += end + 2;
        }
        Ok(())
    }

    /// `<!DOCTYPE policyconfig PUBLIC "…" "…">` with the known ids and no internal subset.
    fn doctype(&mut self) -> Result<(), String> {
        self.at += "<!DOCTYPE".len();
        let bad = || "unsupported DOCTYPE".to_owned();
        if !self.skip_space() || self.name()? != "policyconfig" || !self.skip_space() {
            return Err(bad());
        }
        if self.name()? != "PUBLIC" || !self.skip_space() {
            return Err(bad());
        }
        let public = self.quoted().map_err(|_| bad())?;
        if !self.skip_space() {
            return Err(bad());
        }
        let system = self.quoted().map_err(|_| bad())?;
        self.skip_space();
        if !DOCTYPE_PUBLIC.contains(&public.as_str()) || system != DOCTYPE_SYSTEM || !self.eat(">")
        {
            return Err(bad());
        }
        Ok(())
    }

    fn element(&mut self, depth: usize) -> Result<Element, String> {
        if depth > MAX_DEPTH {
            return Err("nested too deeply".into());
        }
        if !self.eat("<") {
            return Err("expected an element".into());
        }
        let name = self.name()?;
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            let spaced = self.skip_space();
            if self.eat("/>") {
                return Ok(Element {
                    name,
                    attrs,
                    children: Vec::new(),
                });
            }
            if self.eat(">") {
                break;
            }
            if !spaced {
                return Err("malformed tag".into());
            }
            let key = self.name()?;
            self.skip_space();
            if !self.eat("=") {
                return Err("expected '='".into());
            }
            self.skip_space();
            let value = self.quoted()?;
            if attrs.iter().any(|(k, _)| *k == key) {
                return Err("duplicate attribute".into());
            }
            attrs.push((key, value));
        }
        let mut children = Vec::new();
        loop {
            if self.eat("</") {
                let close = self.name()?;
                self.skip_space();
                if close != name || !self.eat(">") {
                    return Err("mismatched closing tag".into());
                }
                return Ok(Element {
                    name,
                    attrs,
                    children,
                });
            }
            if self.comment()? {
                continue;
            }
            if self.rest().starts_with("<!") || self.rest().starts_with("<?") {
                return Err("unsupported markup".into());
            }
            if self.rest().starts_with('<') {
                children.push(Node::Element(self.element(depth + 1)?));
            } else if self.rest().is_empty() {
                return Err("unexpected end of file".into());
            } else {
                let end = self.rest().find('<').unwrap_or(self.rest().len());
                children.push(Node::Text(decode_entities(&self.rest()[..end])?));
                self.at += end;
            }
        }
    }
}

/// Only the five predefined entities; any other `&` is refused.
fn decode_entities(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after
            .find(';')
            .filter(|e| *e <= 4)
            .ok_or("unsupported entity")?;
        out.push(match &after[..end] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => return Err("unsupported entity".into()),
        });
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn parse_policy(text: &str) -> Result<Element, String> {
    let mut reader = Reader { text, at: 0 };
    reader.declaration()?;
    let mut seen_doctype = false;
    loop {
        reader.skip_space();
        if reader.comment()? {
            continue;
        }
        if reader.rest().starts_with("<!DOCTYPE") && !seen_doctype {
            seen_doctype = true;
            reader.doctype()?;
        } else if reader.rest().starts_with("<!") || reader.rest().starts_with("<?") {
            return Err("unsupported markup".into());
        } else {
            break;
        }
    }
    let root = reader.element(0)?;
    loop {
        reader.skip_space();
        if reader.comment()? {
            continue;
        }
        if reader.rest().is_empty() {
            return Ok(root);
        }
        return Err("content after the policy".into());
    }
}

/// Checks that `text` is a polkit policy that authorises exactly `action` for exactly `helper`,
/// only for an active local session after administrator authentication. Anything the reader
/// doesn't understand is a mismatch.
pub fn check_policy_text(text: &str, action: &str, helper: &str) -> Result<(), String> {
    let mismatch = |why: &str| Err(format!("the polkit policy doesn't match: {why}"));
    let root = match parse_policy(text) {
        Ok(root) => root,
        Err(why) => return mismatch(&why),
    };
    if root.name != "policyconfig" {
        return mismatch("the root isn't <policyconfig>");
    }
    if root
        .children
        .iter()
        .any(|n| matches!(n, Node::Text(t) if !t.trim().is_empty()))
    {
        return mismatch("text outside any element");
    }
    // Exactly one action in the whole file, and it is a direct child of the root.
    if root.count_named("action") != 1 || root.elements("action").count() != 1 {
        return mismatch("expected exactly one action");
    }
    let Some(entry) = root.elements("action").next() else {
        return mismatch("expected exactly one action");
    };
    if entry.attr("id") != Some(action) {
        return mismatch("wrong action id");
    }
    let mut defaults = entry.elements("defaults");
    let (Some(defaults), None) = (defaults.next(), defaults.next()) else {
        return mismatch("defaults must appear once");
    };
    for (tag, want) in [
        ("allow_any", "no"),
        ("allow_inactive", "no"),
        ("allow_active", "auth_admin"),
    ] {
        let mut found = defaults.elements(tag);
        match (found.next(), found.next()) {
            (Some(e), None) if e.only_text().as_deref() == Some(want) => {}
            (Some(_), None) => return mismatch(&format!("{tag} must be {want}")),
            _ => return mismatch(&format!("{tag} must appear once")),
        }
    }
    let mut paths = entry
        .elements("annotate")
        .filter(|e| e.attr("key") == Some(EXEC_PATH_KEY));
    let (Some(path), None) = (paths.next(), paths.next()) else {
        return mismatch("exec.path must appear once");
    };
    if path.only_text().as_deref() != Some(helper) {
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

/// Works out the state for `port` against the real system. `held` is whether the tray already
/// holds the sockets; `version` runs `<helper> --version` (unprivileged, directly).
pub fn assess(
    port: u16,
    held: bool,
    version: impl Fn(&Path) -> Result<String, String>,
) -> PrivState {
    assess_with(
        port,
        held,
        unprivileged_port_start(),
        &TrustEnv::system(),
        version,
    )
}

/// [`assess`] against a fake tree and an injected threshold, for tests.
#[cfg(any(test, feature = "test-fakes"))]
pub fn assess_in(
    port: u16,
    held: bool,
    unprivileged_start: u32,
    env: &TrustEnv,
    version: impl Fn(&Path) -> Result<String, String>,
) -> PrivState {
    assess_with(port, held, unprivileged_start, env, version)
}

fn assess_with(
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
        let verified = match verify(env, candidate) {
            Ok(verified) => verified,
            Err(TrustError::Missing) => continue,
            Err(e) => {
                first_problem.get_or_insert(format!("{}: {}", candidate.helper, e.reason()));
                continue;
            }
        };
        match version(verified.helper_path()) {
            Err(why) => {
                first_problem.get_or_insert(format!("couldn't ask the helper its version: {why}"));
            }
            Ok(output) => match check_version(&output, env!("CARGO_PKG_VERSION")) {
                VersionCheck::Match => return PrivState::Ready { helper: verified },
                VersionCheck::Mismatch(warn) => {
                    return PrivState::Mismatch {
                        helper: verified,
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
