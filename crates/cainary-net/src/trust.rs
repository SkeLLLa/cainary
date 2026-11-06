//! `--trust` (design §17): let Claude Code and Codex trust the takeover CA.
//!
//! On an explicit action only, this edits one key (`env.NODE_EXTRA_CA_CERTS`) in the user's
//! Claude Code settings, after a backup, and can undo it; and it writes combined certificate
//! bundles next to the collector CA. It never edits Codex configuration, shell profiles or any
//! system trust store. Every file operation is relative to a validated directory descriptor.
//! The managed-settings check is the core's own Claude Code config resolution, in-process and
//! read-only. Certificate bundles of other programs are read narrowly here (`read_certs`),
//! because the harness refuses `*.pem` by design.

use crate::setup::quote;
use crate::tls::ca_file::{CA_FILE, CaDir};
use cainary_core::harness::ctx::ScanCtx;
use cainary_core::harness::{Harness, ToolHome};
use cainary_core::model::Tool;
use cainary_core::scanners::claude_code::{self, CcFrom};
use serde_json::{Map, Value, json};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const KEY: &str = "NODE_EXTRA_CA_CERTS";
pub const CLAUDE_BUNDLE: &str = "otel-debug-claude-bundle.pem";
pub const CODEX_BUNDLE: &str = "otel-debug-codex-bundle.pem";
pub const STATE_FILE: &str = "otel-debug-trust.json";
const MAX_FILE: usize = 1 << 20;
const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Where things are: the harness (home, managed settings, system roots) and the directory the
/// collector CA lives in.
pub struct Env<'h> {
    pub harness: &'h Harness,
    pub ca_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    ClaudeCode,
    Codex,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Target::ClaudeCode => "claude-code",
            Target::Codex => "codex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Preview,
    Applied,
    Already,
    Undone,
    NothingToUndo,
    Refused,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Preview => "preview",
            Action::Applied => "applied",
            Action::Already => "already",
            Action::Undone => "undone",
            Action::NothingToUndo => "nothing-to-undo",
            Action::Refused => "refused",
        }
    }
}

/// One `trust` line (design §17.1). `message` is fixed text; everything variable is a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub target: Target,
    pub action: Action,
    pub message: String,
    pub settings_path: Option<String>,
    pub backup_path: Option<String>,
    pub key: Option<&'static str>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub bundle_path: Option<String>,
    pub command: Option<String>,
}

fn now_string(h: &Harness) -> String {
    cainary_core::value::rfc3339(h.now())
}

impl Line {
    fn new(target: Target, action: Action, message: impl Into<String>) -> Line {
        Line {
            target,
            action,
            message: message.into(),
            settings_path: None,
            backup_path: None,
            key: None,
            from: None,
            to: None,
            bundle_path: None,
            command: None,
        }
    }

    fn refused(target: Target, message: impl Into<String>) -> Line {
        Line::new(target, Action::Refused, message)
    }

    /// Exit code: 1 for a refusal, 0 otherwise.
    pub fn code(&self) -> u8 {
        u8::from(self.action == Action::Refused)
    }

    pub fn json(&self, ts: &str) -> String {
        let mut m = Map::new();
        m.insert("v".into(), json!(1));
        m.insert("type".into(), json!("trust"));
        m.insert("ts".into(), json!(ts));
        m.insert("target".into(), json!(self.target.as_str()));
        m.insert("action".into(), json!(self.action.as_str()));
        m.insert("message".into(), json!(self.message));
        m.insert("settingsPath".into(), json!(self.settings_path));
        m.insert("backupPath".into(), json!(self.backup_path));
        m.insert("key".into(), json!(self.key));
        m.insert("from".into(), json!(self.from));
        m.insert("to".into(), json!(self.to));
        m.insert("bundlePath".into(), json!(self.bundle_path));
        m.insert("command".into(), json!(self.command));
        format!("{}\n", Value::Object(m))
    }

    /// The same, for a person: the message, then what changes.
    pub fn text(&self) -> String {
        use crate::output::escape;
        let mut t = format!("{}: {}\n", self.action.as_str(), self.message);
        let mut row = |label: &str, v: &Option<String>| {
            if let Some(v) = v {
                t.push_str(&format!("  {label}: {}\n", escape(v)));
            }
        };
        row("settings", &self.settings_path);
        row("backup", &self.backup_path);
        row("was", &self.from);
        row("now", &self.to);
        row("bundle", &self.bundle_path);
        row("run", &self.command);
        t
    }
}

// ── fixed texts ──────────────────────────────────────────────────────────────────────────────

const ORG_NOTE: &str =
    "While the HTTPS takeover is active, your organization's collector receives nothing.";
const RESTART: &str = "Restart Claude Code afterwards.";
const SHELL_WINS: &str = "Your shell sets NODE_EXTRA_CA_CERTS, which wins over the settings value.";

fn with_shell(h: &Harness, base: &str) -> String {
    if h.env(KEY).is_some() {
        format!("{base} {SHELL_WINS}")
    } else {
        base.to_string()
    }
}

// ── descriptor-relative file operations (this file is the writer, design §17.1) ─────────────

fn cname(name: &str) -> CString {
    CString::new(name).expect("fixed names have no NUL")
}

fn euid() -> u32 {
    #[cfg(test)]
    if let Some(u) = tests::FAKE_EUID.with(std::cell::Cell::get) {
        return u;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[derive(Debug)]
enum Why {
    Symlink,
    Owner,
    NotRegular,
    TooBig,
    Io,
}

/// Reads `name` in `dir`: `Ok(None)` if absent; refuses a symlink, a file that isn't ours or
/// isn't a regular one-link file, and anything over 1 MiB.
fn read_in(dir: &CaDir, name: &str) -> Result<Option<Vec<u8>>, Why> {
    let n = cname(name);
    // SAFETY: valid descriptor and NUL-terminated name; the flags are plain constants.
    let raw = unsafe {
        libc::openat(
            dir.raw_fd(),
            n.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(Why::Symlink),
            _ => Err(Why::Io),
        };
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    let mut f = unsafe { File::from_raw_fd(raw) };
    let md = f.metadata().map_err(|_| Why::Io)?;
    if !md.is_file() || md.nlink() != 1 {
        return Err(Why::NotRegular);
    }
    if md.uid() != euid() {
        return Err(Why::Owner);
    }
    if md.len() > MAX_FILE as u64 {
        return Err(Why::TooBig);
    }
    let mut buf = Vec::new();
    io::Read::read_to_end(&mut f, &mut buf).map_err(|_| Why::Io)?;
    Ok(Some(buf))
}

fn open_new(dir: &CaDir, name: &str, mode: u32) -> io::Result<File> {
    let n = cname(name);
    // SAFETY: valid descriptor and NUL-terminated name; `mode` is read only with O_CREAT.
    let raw = unsafe {
        libc::openat(
            dir.raw_fd(),
            n.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    let f = unsafe { File::from_raw_fd(raw) };
    let md = f.metadata()?;
    if !md.is_file() || md.uid() != euid() || md.nlink() != 1 {
        return Err(io::Error::other("not a fresh regular file of ours"));
    }
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(f)
}

fn unlink_in(dir: &CaDir, name: &str) -> io::Result<()> {
    let n = cname(name);
    // SAFETY: valid descriptor and NUL-terminated name.
    let r = unsafe { libc::unlinkat(dir.raw_fd(), n.as_ptr(), 0) };
    if r == 0 || io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Tmp (`create_new | O_NOFOLLOW`), 0600→`mode`, write, fsync, rename over `name` in the same
/// directory.
fn write_atomic(dir: &CaDir, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    // SAFETY: getpid has no preconditions and cannot fail.
    let tmp = format!("{name}.cainary-tmp.{}", unsafe { libc::getpid() });
    let mut f = open_new(dir, &tmp, mode)?;
    let r = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = r {
        let _ = unlink_in(dir, &tmp);
        return Err(e);
    }
    let (t, n) = (cname(&tmp), cname(name));
    // SAFETY: valid descriptor and NUL-terminated names.
    let r = unsafe { libc::renameat(dir.raw_fd(), t.as_ptr(), dir.raw_fd(), n.as_ptr()) };
    if r != 0 {
        let e = io::Error::last_os_error();
        let _ = unlink_in(dir, &tmp);
        return Err(e);
    }
    Ok(())
}

/// A backup next to the file: `<name>.cainary-<UTC yyyymmddThhmmssZ>.bak`, 0600, never
/// overwriting an earlier one.
fn backup(dir: &CaDir, name: &str, bytes: &[u8], stamp: &str) -> io::Result<String> {
    for n in 0..10 {
        let suffix = if n == 0 {
            String::new()
        } else {
            format!("-{n}")
        };
        let b = format!("{name}.cainary-{stamp}{suffix}.bak");
        match open_new(dir, &b, 0o600) {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
                return Ok(b);
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("too many backups in one second"))
}

/// `20261106T154658Z` from an RFC 3339 UTC time.
fn stamp(rfc: &str) -> String {
    rfc.chars().filter(|c| *c != '-' && *c != ':').collect()
}

// ── PEM ──────────────────────────────────────────────────────────────────────────────────────

/// The certificate blocks of a PEM text, each normalized to one `BEGIN … END\n` string.
pub fn pem_certs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find(BEGIN) {
        let after = &rest[s..];
        let Some(e) = after.find(END) else { break };
        let block = &after[..e + END.len()];
        let body: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        out.push(format!("{}\n", body.join("\n")));
        rest = &after[e + END.len()..];
    }
    out
}

fn bundle(parts: &[String], ca: &str) -> String {
    // The collector certificate is always last, and exactly once, whatever the parts hold.
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    for c in parts.iter().filter(|c| c.as_str() != ca) {
        if seen.insert(c.clone()) {
            out.push_str(c);
        }
    }
    out.push_str(ca);
    out
}

/// A certificate bundle of someone else (the file `NODE_EXTRA_CA_CERTS` already names, or the
/// system roots), as its certificate blocks only. The core harness refuses `*.pem` by design (they
/// may hold keys), so this reads the file itself, narrowly: a regular file of at most 2 MiB that
/// others can't write, symlinks followed (`/etc/ssl/cert.pem` is one), and a file that holds a
/// private key is refused outright, so key material is never handled at all.
fn read_certs(path: &Path) -> Option<Vec<String>> {
    const CAP: u64 = 2 << 20;
    let resolved = std::fs::canonicalize(path).ok()?;
    let f = File::open(&resolved).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || md.len() > CAP || md.mode() & 0o022 != 0 {
        return None;
    }
    let mut buf = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(f, CAP + 1), &mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    if text.contains("PRIVATE KEY") {
        return None;
    }
    let certs = pem_certs(&text);
    (!certs.is_empty()).then_some(certs)
}

/// The system trust bundle: the first of the usual places that exists.
fn system_roots(h: &Harness) -> Option<Vec<String>> {
    const CANDIDATES: [&str; 3] = [
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
    ];
    CANDIDATES.iter().find_map(|c| read_certs(h.sys(c).path()))
}

/// The collector's certificate, exactly one, from the CA directory.
fn collector_ca(ca: &CaDir) -> Result<String, &'static str> {
    const MISSING: &str = "Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.";
    match read_in(ca, CA_FILE) {
        Ok(Some(b)) => {
            let certs = pem_certs(&String::from_utf8_lossy(&b));
            match certs.as_slice() {
                [one] => Ok(one.clone()),
                _ => Err(MISSING),
            }
        }
        _ => Err(MISSING),
    }
}

// ── state file ───────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ClaudeState {
    settings_path: String,
    original: Option<String>,
    written: String,
    created_env: bool,
    created_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct State {
    claude: Option<ClaudeState>,
    codex_bundle: Option<String>,
}

impl State {
    fn parse(bytes: &[u8]) -> State {
        let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(bytes) else {
            return State::default();
        };
        let claude = m
            .get("claudeCode")
            .and_then(Value::as_object)
            .and_then(|c| {
                Some(ClaudeState {
                    settings_path: c.get("settingsPath")?.as_str()?.to_string(),
                    original: c
                        .get("original")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    written: c.get("written")?.as_str()?.to_string(),
                    created_env: c
                        .get("createdEnv")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    created_file: c
                        .get("createdFile")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            });
        let codex_bundle = m
            .get("codex")
            .and_then(|c| c.get("bundlePath"))
            .and_then(Value::as_str)
            .map(str::to_string);
        State {
            claude,
            codex_bundle,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut m = Map::new();
        if let Some(c) = &self.claude {
            m.insert(
                "claudeCode".into(),
                json!({"settingsPath": c.settings_path, "original": c.original, "written": c.written,
                       "createdEnv": c.created_env, "createdFile": c.created_file}),
            );
        }
        if let Some(b) = &self.codex_bundle {
            m.insert("codex".into(), json!({"bundlePath": b}));
        }
        format!(
            "{}\n",
            serde_json::to_string_pretty(&Value::Object(m)).expect("serializes")
        )
        .into_bytes()
    }

    fn is_empty(&self) -> bool {
        self.claude.is_none() && self.codex_bundle.is_none()
    }
}

fn read_state(ca: &CaDir) -> State {
    read_in(ca, STATE_FILE)
        .ok()
        .flatten()
        .map(|b| State::parse(&b))
        .unwrap_or_default()
}

fn save_state(ca: &CaDir, st: &State) -> io::Result<()> {
    if st.is_empty() {
        unlink_in(ca, STATE_FILE)
    } else {
        write_atomic(ca, STATE_FILE, &st.to_bytes(), 0o600)
    }
}

// ── Claude Code ──────────────────────────────────────────────────────────────────────────────

fn why_text(w: &Why) -> &'static str {
    match w {
        Why::Symlink => "The settings file is a symlink; refusing to edit it.",
        Why::Owner => "The settings file is not owned by you; refusing to edit it.",
        Why::NotRegular => {
            "The settings file is not a regular file with a single link; refusing to edit it."
        }
        Why::TooBig => "The settings file is over 1 MiB; refusing to edit it.",
        Why::Io => "The settings file could not be read.",
    }
}

fn dir_error(target: Target, what: &str) -> Line {
    Line::refused(
        target,
        format!(
            "The {what} directory is not safe to edit (a symlink, or not owned by you, or writable by others)."
        ),
    )
}

struct Settings {
    dir: CaDir,
    path: PathBuf,
    /// The file as it was, when it existed.
    original_bytes: Option<Vec<u8>>,
    doc: Map<String, Value>,
}

fn open_settings(env: &Env<'_>, create_dir: bool) -> Result<Option<Settings>, Box<Line>> {
    let t = Target::ClaudeCode;
    let dir_path = env
        .harness
        .tool_home(ToolHome::ClaudeConfig)
        .path()
        .to_path_buf();
    let dir = match CaDir::open_shared(&dir_path, create_dir) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(_) => return Err(Box::new(dir_error(t, "Claude Code settings"))),
    };
    let path = dir.path().join("settings.json");
    let original_bytes = read_in(&dir, "settings.json").map_err(|w| {
        let mut l = Line::refused(t, why_text(&w));
        l.settings_path = Some(path.display().to_string());
        Box::new(l)
    })?;
    let doc = match &original_bytes {
        None => Map::new(),
        Some(b) => match serde_json::from_slice::<Value>(b) {
            Ok(Value::Object(m)) => m,
            _ => {
                let mut l = Line::refused(
                    t,
                    "The settings file is not a valid JSON object; refusing to edit it.",
                );
                l.settings_path = Some(path.display().to_string());
                return Err(Box::new(l));
            }
        },
    };
    Ok(Some(Settings {
        dir,
        path,
        original_bytes,
        doc,
    }))
}

fn env_value(doc: &Map<String, Value>) -> Result<Option<String>, ()> {
    match doc.get("env") {
        None => Ok(None),
        Some(Value::Object(e)) => match e.get(KEY) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(()),
        },
        Some(_) => Err(()),
    }
}

fn render(doc: &Map<String, Value>) -> Vec<u8> {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&Value::Object(doc.clone())).expect("serializes")
    )
    .into_bytes()
}

/// Managed settings (or any admin tier) that set the key win over ours: refuse. The shell value
/// is only mentioned.
fn managed_sets_key(h: &Harness) -> bool {
    let mut ctx = ScanCtx::new(h, Tool::ClaudeCode);
    let cfg = claude_code::resolve(&mut ctx);
    claude_code::env(&cfg, KEY).is_some_and(|v| matches!(v.from, CcFrom::Tier(_)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Apply { dry_run: bool },
    Undo { dry_run: bool },
}

pub fn claude_code(env: &Env<'_>, mode: Mode) -> Line {
    match mode {
        Mode::Apply { dry_run } => claude_apply(env, dry_run),
        Mode::Undo { dry_run } => claude_undo(env, dry_run),
    }
}

fn fill_paths(l: &mut Line, s: &Settings) {
    l.settings_path = Some(s.path.display().to_string());
    l.key = Some(KEY);
}

fn claude_apply(env: &Env<'_>, dry_run: bool) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    if managed_sets_key(h) {
        return Line::refused(
            t,
            "Your organization's managed settings set NODE_EXTRA_CA_CERTS; they override this.",
        );
    }
    let settings = match open_settings(env, !dry_run) {
        Ok(Some(s)) => s,
        // A dry run doesn't create the directory: it describes creating the file.
        Ok(None) => return preview_new_claude(env),
        Err(l) => return *l,
    };
    let ca_dir = match CaDir::open(&env.ca_dir) {
        Ok(d) => d,
        Err(_) => return dir_error(t, "collector certificate"),
    };
    let ca_path = ca_dir.path().join(CA_FILE).display().to_string();
    let bundle_path = ca_dir.path().join(CLAUDE_BUNDLE).display().to_string();
    let existing = match env_value(&settings.doc) {
        Ok(v) => v,
        Err(()) => {
            let mut l = Line::refused(
                t,
                "env.NODE_EXTRA_CA_CERTS in the settings file is not a string; refusing to edit it.",
            );
            fill_paths(&mut l, &settings);
            return l;
        }
    };
    let state = read_state(&ca_dir);
    let written_before = state.claude.as_ref().map(|c| c.written.as_str());
    let mut line = Line::new(t, Action::Already, "");
    fill_paths(&mut line, &settings);
    line.to = existing.clone();
    if existing.as_deref() == Some(ca_path.as_str())
        || (existing.as_deref() == Some(bundle_path.as_str())
            && written_before == Some(bundle_path.as_str()))
    {
        line.message = with_shell(h, "Claude Code already trusts the collector certificate.");
        line.from = existing.clone();
        if existing.as_deref() == Some(bundle_path.as_str()) {
            line.bundle_path = Some(bundle_path);
        }
        return line;
    }

    // What to write, and the bundle it may need.
    let (written, bundle_text): (String, Option<String>) = match &existing {
        None => (ca_path.clone(), None),
        Some(p) => {
            let ca = match collector_ca(&ca_dir) {
                Ok(c) => c,
                Err(m) => {
                    let mut l = Line::refused(t, m);
                    fill_paths(&mut l, &settings);
                    return l;
                }
            };
            let Some(certs) = read_certs(Path::new(p)) else {
                let mut l = Line::refused(
                    t,
                    "The file your NODE_EXTRA_CA_CERTS points at could not be read as a certificate bundle, so a combined bundle can't be made.",
                );
                fill_paths(&mut l, &settings);
                l.from = Some(p.clone());
                return l;
            };
            (bundle_path.clone(), Some(bundle(&certs, &ca)))
        }
    };
    let backup_name = settings
        .original_bytes
        .as_ref()
        .map(|_| format!("settings.json.cainary-{}.bak", stamp(&now_string(h))));
    line.from = existing.clone();
    line.to = Some(written.clone());
    line.bundle_path = bundle_text.as_ref().map(|_| bundle_path.clone());
    line.backup_path = backup_name
        .as_ref()
        .map(|n| settings.dir.path().join(n).display().to_string());
    if dry_run {
        line.action = Action::Preview;
        line.message = with_shell(
            h,
            &if bundle_text.is_some() {
                format!(
                    "Would point env.NODE_EXTRA_CA_CERTS at a combined bundle (your current file plus the collector certificate) in your Claude Code settings, after a backup. {RESTART} {ORG_NOTE}"
                )
            } else {
                format!(
                    "Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup. {RESTART} {ORG_NOTE}"
                )
            },
        );
        return line;
    }

    // Apply: backup, bundle, settings, state; a failed state write puts the settings back.
    let mut doc = settings.doc.clone();
    let created_env = !doc.get("env").is_some_and(Value::is_object);
    let env_map = doc
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("env is an object");
    env_map.insert(KEY.into(), Value::String(written.clone()));
    let fail = |m: &str| {
        let mut l = Line::refused(t, m);
        fill_paths(&mut l, &settings);
        l
    };
    let stamp_now = stamp(&now_string(h));
    let backup_name = match &settings.original_bytes {
        Some(b) => match backup(&settings.dir, "settings.json", b, &stamp_now) {
            Ok(n) => Some(n),
            Err(_) => {
                return fail("The settings backup could not be written; nothing was changed.");
            }
        },
        None => None,
    };
    if let Some(text) = &bundle_text
        && write_atomic(&ca_dir, CLAUDE_BUNDLE, text.as_bytes(), 0o644).is_err()
    {
        return fail("The combined bundle could not be written; nothing was changed.");
    }
    if write_atomic(&settings.dir, "settings.json", &render(&doc), 0o600).is_err() {
        return fail("The settings file could not be written; nothing was changed.");
    }
    let new_state = State {
        claude: Some(ClaudeState {
            settings_path: settings.path.display().to_string(),
            original: existing.clone(),
            written: written.clone(),
            created_env,
            created_file: settings.original_bytes.is_none(),
        }),
        codex_bundle: state.codex_bundle.clone(),
    };
    if save_state(&ca_dir, &new_state).is_err() {
        // Put the settings back as they were.
        let _ = match &settings.original_bytes {
            Some(b) => write_atomic(&settings.dir, "settings.json", b, 0o600),
            None => unlink_in(&settings.dir, "settings.json"),
        };
        return fail("The state file could not be written; the settings were put back.");
    }
    line.action = Action::Applied;
    line.backup_path = backup_name.map(|n| settings.dir.path().join(n).display().to_string());
    line.message = with_shell(
        h,
        "Claude Code will trust the collector certificate once it is restarted.",
    );
    line
}

/// A dry run with no `~/.claude` yet: the file would be created.
fn preview_new_claude(env: &Env<'_>) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    let dir = env
        .harness
        .tool_home(ToolHome::ClaudeConfig)
        .path()
        .to_path_buf();
    let mut l = Line::new(
        t,
        Action::Preview,
        with_shell(
            h,
            &format!(
                "Would create your Claude Code settings file with only env.NODE_EXTRA_CA_CERTS (no backup is needed). {RESTART} {ORG_NOTE}"
            ),
        ),
    );
    l.settings_path = Some(dir.join("settings.json").display().to_string());
    l.key = Some(KEY);
    l.to = Some(env.ca_dir.join(CA_FILE).display().to_string());
    l
}

fn claude_undo(env: &Env<'_>, dry_run: bool) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    let nothing = || {
        Line::new(
            t,
            Action::NothingToUndo,
            "cAInary has not changed your Claude Code settings.",
        )
    };
    let Ok(Some(ca_dir)) = CaDir::open_existing(&env.ca_dir) else {
        return nothing();
    };
    let mut state = read_state(&ca_dir);
    let Some(cs) = state.claude.clone() else {
        return nothing();
    };
    let settings = match open_settings(env, false) {
        Ok(Some(s)) => s,
        Ok(None) => {
            // The directory is gone: the record is stale.
            state.claude = None;
            let _ = save_state(&ca_dir, &state);
            return nothing();
        }
        Err(l) => return *l,
    };
    let current = env_value(&settings.doc).ok().flatten();
    if settings.original_bytes.is_none() || current.as_deref() != Some(cs.written.as_str()) {
        let mut l = Line::refused(
            t,
            "The setting changed since cAInary wrote it; leaving it alone.",
        );
        fill_paths(&mut l, &settings);
        l.from = current;
        return l;
    }
    let mut doc = settings.doc.clone();
    if let Some(Value::Object(e)) = doc.get_mut("env") {
        match &cs.original {
            Some(o) => {
                e.insert(KEY.into(), Value::String(o.clone()));
            }
            None => {
                e.remove(KEY);
            }
        }
        if cs.created_env && e.is_empty() {
            doc.remove("env");
        }
    }
    let delete_file = cs.created_file && doc.is_empty();
    let backup_name = format!("settings.json.cainary-{}.bak", stamp(&now_string(h)));
    let mut l = Line::new(t, Action::Undone, "");
    fill_paths(&mut l, &settings);
    l.from = Some(cs.written.clone());
    l.to = cs.original.clone();
    l.backup_path = Some(settings.dir.path().join(&backup_name).display().to_string());
    let bundle_here = ca_dir.path().join(CLAUDE_BUNDLE).display().to_string();
    if cs.written == bundle_here {
        l.bundle_path = Some(bundle_here.clone());
    }
    if dry_run {
        l.action = Action::Preview;
        l.message = format!(
            "Would {} in your Claude Code settings, after a backup. {RESTART}",
            match (&cs.original, delete_file) {
                (_, true) => "remove the settings file cAInary created".to_string(),
                (Some(_), _) => "restore your previous NODE_EXTRA_CA_CERTS value".to_string(),
                (None, _) => "remove env.NODE_EXTRA_CA_CERTS".to_string(),
            }
        );
        return l;
    }
    let fail = |m: &str| {
        let mut x = Line::refused(t, m);
        fill_paths(&mut x, &settings);
        x
    };
    let original = settings.original_bytes.clone().unwrap_or_default();
    let backup_name = match backup(
        &settings.dir,
        "settings.json",
        &original,
        &stamp(&now_string(h)),
    ) {
        Ok(n) => n,
        Err(_) => return fail("The settings backup could not be written; nothing was changed."),
    };
    let done = if delete_file {
        unlink_in(&settings.dir, "settings.json")
    } else {
        write_atomic(&settings.dir, "settings.json", &render(&doc), 0o600)
    };
    if done.is_err() {
        return fail("The settings file could not be changed; nothing was undone.");
    }
    if cs.written == bundle_here {
        let _ = unlink_in(&ca_dir, CLAUDE_BUNDLE);
    }
    state.claude = None;
    let _ = save_state(&ca_dir, &state);
    l.backup_path = Some(settings.dir.path().join(backup_name).display().to_string());
    l.message = format!("Restored your previous Claude Code setting. {RESTART}");
    l
}

// ── Codex ────────────────────────────────────────────────────────────────────────────────────

fn codex_command(path: &str) -> String {
    format!("env CODEX_CA_CERTIFICATE={} codex", quote(path))
}

pub fn codex(env: &Env<'_>, undo: bool) -> Line {
    let t = Target::Codex;
    let ca_dir = match if undo {
        CaDir::open_existing(&env.ca_dir)
    } else {
        CaDir::open(&env.ca_dir).map(Some)
    } {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Line::new(
                t,
                Action::NothingToUndo,
                "No Codex certificate bundle was prepared.",
            );
        }
        Err(_) => return dir_error(t, "collector certificate"),
    };
    let path = ca_dir.path().join(CODEX_BUNDLE).display().to_string();
    let mut state = read_state(&ca_dir);
    if undo {
        let existed = matches!(read_in(&ca_dir, CODEX_BUNDLE), Ok(Some(_)));
        if !existed && state.codex_bundle.is_none() {
            return Line::new(
                t,
                Action::NothingToUndo,
                "No Codex certificate bundle was prepared.",
            );
        }
        if unlink_in(&ca_dir, CODEX_BUNDLE).is_err() {
            return Line::refused(t, "The Codex bundle could not be removed.");
        }
        state.codex_bundle = None;
        let _ = save_state(&ca_dir, &state);
        let mut l = Line::new(t, Action::Undone, "Removed the Codex certificate bundle.");
        l.bundle_path = Some(path);
        return l;
    }
    let ca = match collector_ca(&ca_dir) {
        Ok(c) => c,
        Err(m) => return Line::refused(t, m),
    };
    let Some(roots) = system_roots(env.harness) else {
        return Line::refused(
            t,
            "No system certificate bundle was found, so a combined bundle can't be made.",
        );
    };
    let text = bundle(&roots, &ca);
    let same = matches!(read_in(&ca_dir, CODEX_BUNDLE), Ok(Some(b)) if b == text.as_bytes());
    if !same && write_atomic(&ca_dir, CODEX_BUNDLE, text.as_bytes(), 0o644).is_err() {
        return Line::refused(t, "The Codex bundle could not be written.");
    }
    state.codex_bundle = Some(path.clone());
    if save_state(&ca_dir, &state).is_err() {
        return Line::refused(t, "The state file could not be written.");
    }
    let mut l = Line::new(
        t,
        if same {
            Action::Already
        } else {
            Action::Applied
        },
        "Codex will trust the collector certificate when started with this command. Nothing in your Codex configuration or shell profile was changed.",
    );
    l.command = Some(codex_command(&path));
    l.bundle_path = Some(path);
    l
}

// ── status ───────────────────────────────────────────────────────────────────────────────────

/// The `trust-status` line.
pub fn status_json(env: &Env<'_>, ts: &str) -> String {
    let h = env.harness;
    let ca_path = env.ca_dir.join(CA_FILE).display().to_string();
    let (state, claude_dir) = match CaDir::open_existing(&env.ca_dir) {
        Ok(Some(d)) => (read_state(&d), Some(d)),
        _ => (State::default(), None),
    };
    let settings_path = h
        .tool_home(ToolHome::ClaudeConfig)
        .path()
        .join("settings.json")
        .display()
        .to_string();
    let (claude_state, value) = if managed_sets_key(h) {
        ("managed", None)
    } else {
        match open_settings(env, false) {
            Ok(Some(s)) => match env_value(&s.doc) {
                Ok(Some(v))
                    if state.claude.as_ref().is_some_and(|c| c.written == v) || v == ca_path =>
                {
                    ("applied", Some(v))
                }
                Ok(Some(v)) => ("other-value", Some(v)),
                _ => ("absent", None),
            },
            _ => ("absent", None),
        }
    };
    let codex_path = claude_dir
        .as_ref()
        .map(|d| d.path().join(CODEX_BUNDLE).display().to_string());
    let ready = claude_dir
        .as_ref()
        .is_some_and(|d| matches!(read_in(d, CODEX_BUNDLE), Ok(Some(_))));
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("type".into(), json!("trust-status"));
    m.insert("ts".into(), json!(ts));
    m.insert(
        "claudeCode".into(),
        json!({"state": claude_state, "settingsPath": settings_path, "value": value}),
    );
    m.insert(
        "codex".into(),
        json!({
            "state": if ready { "ready" } else { "absent" },
            "bundlePath": codex_path.as_ref().filter(|_| ready),
            "command": codex_path.as_ref().filter(|_| ready).map(|p| codex_command(p)),
        }),
    );
    m.insert("caPath".into(), json!(ca_path));
    format!("{}\n", Value::Object(m))
}

/// A person's version of the status.
pub fn status_text(env: &Env<'_>) -> String {
    let v: Value = serde_json::from_str(&status_json(env, "")).expect("our own JSON");
    let s = |p: &Value| p.as_str().unwrap_or("-").to_string();
    format!(
        "claude code: {} ({})\ncodex: {}\ncertificate: {}\n",
        s(&v["claudeCode"]["state"]),
        crate::output::escape(&s(&v["claudeCode"]["settingsPath"])),
        s(&v["codex"]["state"]),
        crate::output::escape(&s(&v["caPath"])),
    )
}

// ── each `--tls` start ───────────────────────────────────────────────────────────────────────

/// After a new CA is published: regenerate the combined bundles recorded in the state file from
/// their originals plus this run's certificate. The paths never change; the clients must still
/// be restarted. Returns what could not be refreshed.
pub fn refresh(env: &Env<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    let Ok(Some(ca_dir)) = CaDir::open_existing(&env.ca_dir) else {
        return warnings;
    };
    let state = read_state(&ca_dir);
    if state.is_empty() {
        return warnings;
    }
    let ca = match collector_ca(&ca_dir) {
        Ok(c) => c,
        Err(_) => {
            return vec![
                "the collector certificate is missing; trust bundles were not refreshed".into(),
            ];
        }
    };
    if let Some(cs) = &state.claude {
        let bundle_path = ca_dir.path().join(CLAUDE_BUNDLE).display().to_string();
        if cs.written == bundle_path {
            let certs = cs
                .original
                .as_deref()
                .and_then(|p| read_certs(Path::new(p)));
            match certs {
                Some(certs) => {
                    let b = bundle(&certs, &ca);
                    if write_atomic(&ca_dir, CLAUDE_BUNDLE, b.as_bytes(), 0o644).is_err() {
                        warnings.push("the Claude Code trust bundle could not be rewritten".into());
                    }
                }
                None => warnings.push("the file your Claude Code bundle was made from can't be read; the bundle was not refreshed".into()),
            }
        }
    }
    if state.codex_bundle.is_some() {
        match system_roots(env.harness) {
            Some(roots) => {
                let b = bundle(&roots, &ca);
                if write_atomic(&ca_dir, CODEX_BUNDLE, b.as_bytes(), 0o644).is_err() {
                    warnings.push("the Codex bundle could not be rewritten".into());
                }
            }
            None => warnings.push(
                "no system certificate bundle was found; the Codex bundle was not refreshed".into(),
            ),
        }
    }
    warnings
}

/// For the tests and the CLI: the time stamp used in backup names.
pub fn backup_stamp(t: SystemTime) -> String {
    stamp(&cainary_core::value::rfc3339(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cainary_core::harness::platform::Os;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::symlink;

    thread_local! {
        /// Pretend to be another user, to see a file that isn't ours.
        pub(super) static FAKE_EUID: Cell<Option<u32>> = const { Cell::new(None) };
    }

    const CA1: &str =
        "-----BEGIN CERTIFICATE-----\nQ09MTEVDVE9SLU9ORQ==\n-----END CERTIFICATE-----\n";
    const CA2: &str =
        "-----BEGIN CERTIFICATE-----\nQ09MTEVDVE9SLVRXTw==\n-----END CERTIFICATE-----\n";
    const ROOT_A: &str = "-----BEGIN CERTIFICATE-----\nUk9PVC1B\n-----END CERTIFICATE-----\n";
    const ROOT_B: &str = "-----BEGIN CERTIFICATE-----\nUk9PVC1C\n-----END CERTIFICATE-----\n";
    const ROOT_C: &str = "-----BEGIN CERTIFICATE-----\nUk9PVC1D\n-----END CERTIFICATE-----\n";

    struct Fx {
        base: PathBuf,
        harness: Harness,
        ca_dir: PathBuf,
        _lock: Option<crate::tls::ca_file::Published>,
    }

    impl Fx {
        fn new(tag: &str, fixture_env: &str) -> Fx {
            let base =
                std::env::temp_dir().join(format!("cainary-trust-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("fx/root")).unwrap();
            fs::create_dir_all(base.join("fx/home")).unwrap();
            fs::write(
                base.join("fx/fixture.json"),
                format!(r#"{{"os":"linux","user":"alice","now":"2026-01-01T00:00:00Z","tools":["claude-code"],"env":{{{fixture_env}}}}}"#),
            )
            .unwrap();
            let harness = Harness::from_fixture(&base.join("fx")).unwrap();
            let _ = Os::Linux;
            let ca_dir = base.join("state dir/cainary");
            // The collector's published certificate (a fake PEM: only the blocks matter here).
            let lock = crate::tls::ca_file::publish(&ca_dir, CA1).unwrap();
            Fx {
                base,
                harness,
                ca_dir,
                _lock: Some(lock),
            }
        }

        fn env(&self) -> Env<'_> {
            Env {
                harness: &self.harness,
                ca_dir: self.ca_dir.clone(),
            }
        }

        fn claude_dir(&self) -> PathBuf {
            self.base.join("fx/home/.claude")
        }

        fn settings(&self) -> PathBuf {
            self.claude_dir().join("settings.json")
        }

        fn write_settings(&self, text: &str) {
            fs::create_dir_all(self.claude_dir()).unwrap();
            fs::write(self.settings(), text).unwrap();
        }

        fn read_settings(&self) -> String {
            fs::read_to_string(self.settings()).unwrap()
        }

        fn managed(&self, json: &str) {
            let d = self.base.join("fx/root/etc/claude-code");
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("managed-settings.json"), json).unwrap();
        }

        fn roots(&self) {
            let d = self.base.join("fx/root/etc/ssl/certs");
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("ca-certificates.crt"),
                format!("{ROOT_A}{ROOT_B}{ROOT_C}"),
            )
            .unwrap();
        }

        fn baks(&self) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(self.claude_dir())
                .map(|d| {
                    d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            v.retain(|n| n.ends_with(".bak"));
            v.sort();
            v
        }

        fn ca_path(&self) -> String {
            self.ca_dir.join(CA_FILE).display().to_string()
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            self._lock = None;
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn apply(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Apply { dry_run: false })
    }
    fn preview(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Apply { dry_run: true })
    }
    fn undo(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Undo { dry_run: false })
    }
    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }
    fn env_key(fx: &Fx) -> Option<String> {
        let v: Value = serde_json::from_str(&fx.read_settings()).unwrap();
        v["env"][KEY].as_str().map(str::to_string)
    }

    #[test]
    fn a_missing_settings_file_is_previewed_then_created_with_only_the_key() {
        let fx = Fx::new("create", "");
        let p = preview(&fx);
        assert_eq!(p.action, Action::Preview);
        assert!(p.message.contains("Would create") && p.message.contains("Restart Claude Code"));
        assert!(
            p.message
                .contains("your organization's collector receives nothing")
        );
        assert!(
            !fx.settings().exists() && !fx.claude_dir().exists(),
            "a dry run writes nothing"
        );
        let a = apply(&fx);
        assert_eq!((a.action, a.code()), (Action::Applied, 0), "{a:?}");
        assert_eq!(a.key, Some(KEY));
        assert_eq!(a.to.as_deref(), Some(fx.ca_path().as_str()));
        assert_eq!(a.from, None);
        assert_eq!(a.backup_path, None, "no backup when there was no file");
        assert_eq!(
            fx.read_settings(),
            format!(
                "{{\n  \"env\": {{\n    \"{KEY}\": \"{}\"\n  }}\n}}\n",
                fx.ca_path()
            )
        );
        assert_eq!(mode(&fx.settings()), 0o600);
        assert_eq!(mode(&fx.ca_dir.join(STATE_FILE)), 0o600);
        assert!(fx.baks().is_empty());
        // Again: nothing to do.
        let again = apply(&fx);
        assert_eq!(again.action, Action::Already);
        assert!(fx.baks().is_empty());
    }

    #[test]
    fn existing_settings_keep_their_order_and_get_a_byte_identical_backup() {
        let fx = Fx::new("order", "");
        let original =
            "{\n    \"zeta\": 1,\n    \"model\": \"opus\",\n    \"alpha\": {\"x\": [1, 2]}\n}\n";
        fx.write_settings(original);
        let p = preview(&fx);
        let planned = p.backup_path.clone().expect("the backup is announced");
        assert!(
            planned.contains("settings.json.cainary-20260101T000000Z.bak"),
            "{planned}"
        );
        assert_eq!(fx.read_settings(), original, "the preview changed nothing");
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        assert_eq!(a.backup_path.as_deref(), Some(planned.as_str()));
        assert_eq!(fs::read_to_string(&planned).unwrap(), original);
        assert_eq!(mode(Path::new(&planned)), 0o600);
        let after = fx.read_settings();
        let keys: Vec<String> = serde_json::from_str::<Map<String, Value>>(&after)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["zeta", "model", "alpha", "env"], "{after}");
        assert!(
            after.ends_with("}\n") && after.contains("\n  \"zeta\": 1,"),
            "2-space indent: {after}"
        );
        assert_eq!(env_key(&fx), Some(fx.ca_path()));
        // Undo removes the key it added (and the env object it created), keeping the rest.
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        let back: Value = serde_json::from_str(&fx.read_settings()).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(original).unwrap());
        assert!(back.get("env").is_none());
        // The undo made a backup of the file as it stood, without clobbering the first one.
        assert_eq!(fx.baks().len(), 2, "{:?}", fx.baks());
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
    }

    #[test]
    fn undo_keeps_an_env_object_it_did_not_create() {
        let fx = Fx::new("keepenv", "");
        fx.write_settings("{\"env\":{\"FOO\":\"bar\"}}\n");
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(undo(&fx).action, Action::Undone);
        let back: Value = serde_json::from_str(&fx.read_settings()).unwrap();
        assert_eq!(back, json!({"env": {"FOO": "bar"}}));
    }

    #[test]
    fn undo_deletes_a_file_cainary_created_and_only_then() {
        let fx = Fx::new("undocreated", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert!(!fx.settings().exists());
        // If the user added their own keys meanwhile, the file stays.
        assert_eq!(apply(&fx).action, Action::Applied);
        let mut doc: Map<String, Value> = serde_json::from_str(&fx.read_settings()).unwrap();
        doc.insert("model".into(), json!("opus"));
        fx.write_settings(&Value::Object(doc).to_string());
        assert_eq!(undo(&fx).action, Action::Undone);
        assert_eq!(
            serde_json::from_str::<Value>(&fx.read_settings()).unwrap(),
            json!({"model": "opus"})
        );
    }

    #[test]
    fn another_value_gets_a_combined_bundle_and_undo_restores_it() {
        let fx = Fx::new("other", "");
        let mine = fx.base.join("my-bundle.pem");
        fs::write(&mine, format!("{ROOT_A}{ROOT_B}")).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        let bundle_path = fx.ca_dir.join(CLAUDE_BUNDLE).display().to_string();
        assert_eq!(a.bundle_path.as_deref(), Some(bundle_path.as_str()));
        assert_eq!(a.from.as_deref(), Some(mine.display().to_string().as_str()));
        assert_eq!(a.to.as_deref(), Some(bundle_path.as_str()));
        assert_eq!(env_key(&fx), Some(bundle_path.clone()));
        let b = fs::read_to_string(&bundle_path).unwrap();
        assert_eq!(
            pem_certs(&b),
            [ROOT_A, ROOT_B, CA1],
            "the user's certs, then exactly one collector cert"
        );
        assert_eq!(mode(Path::new(&bundle_path)), 0o644);
        assert_eq!(
            fs::read_to_string(&mine).unwrap(),
            format!("{ROOT_A}{ROOT_B}"),
            "their file is untouched"
        );
        // Re-running is a no-op; undo restores their path and removes our bundle.
        assert_eq!(apply(&fx).action, Action::Already);
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert_eq!(env_key(&fx), Some(mine.display().to_string()));
        assert!(!Path::new(&bundle_path).exists());
    }

    #[test]
    fn the_collector_cert_is_not_duplicated_when_the_users_file_already_has_it() {
        let fx = Fx::new("dedupe", "");
        let mine = fx.base.join("b.pem");
        fs::write(&mine, format!("{ROOT_A}{CA1}{ROOT_A}")).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        apply(&fx);
        let b = fs::read_to_string(fx.ca_dir.join(CLAUDE_BUNDLE)).unwrap();
        assert_eq!(pem_certs(&b), [ROOT_A, CA1]);
    }

    #[test]
    fn an_unreadable_other_bundle_or_a_missing_collector_cert_refuses() {
        let fx = Fx::new("refuse-bundle", "");
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"/nonexistent/bundle.pem\"}}}}\n"
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(
            a.message
                .contains("could not be read as a certificate bundle"),
            "{}",
            a.message
        );
        assert_eq!(a.code(), 1);
        assert!(fx.baks().is_empty(), "nothing was changed");
        fs::remove_file(fx.ca_dir.join(CA_FILE)).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            fx.base.join("b.pem").display()
        ));
        fs::write(fx.base.join("b.pem"), ROOT_A).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(
            a.message.contains("Start the takeover once"),
            "{}",
            a.message
        );
    }

    #[test]
    fn managed_settings_that_set_the_key_refuse() {
        let fx = Fx::new("managed", "");
        fx.managed(&format!("{{\"env\":{{\"{KEY}\":\"/etc/org-ca.pem\"}}}}"));
        fx.write_settings("{\"model\":\"opus\"}\n");
        for l in [apply(&fx), preview(&fx)] {
            assert_eq!(l.action, Action::Refused, "{l:?}");
            assert_eq!(
                l.message,
                "Your organization's managed settings set NODE_EXTRA_CA_CERTS; they override this."
            );
            assert_eq!(l.code(), 1);
        }
        assert_eq!(fx.read_settings(), "{\"model\":\"opus\"}\n");
        assert!(fx.baks().is_empty());
        let st: Value = serde_json::from_str(&status_json(&fx.env(), "T")).unwrap();
        assert_eq!(st["claudeCode"]["state"], "managed");
        // Managed settings that don't touch the key don't block.
        let other = Fx::new("managed-other", "");
        other.managed("{\"allowManagedHooksOnly\":true}");
        assert_eq!(apply(&other).action, Action::Applied);
    }

    #[test]
    fn a_shell_value_is_mentioned_not_refused() {
        let fx = Fx::new("shell", "\"NODE_EXTRA_CA_CERTS\":\"/home/u/shell.pem\"");
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        assert!(
            a.message.contains(
                "Your shell sets NODE_EXTRA_CA_CERTS, which wins over the settings value."
            )
        );
        let none = Fx::new("noshell", "");
        assert!(!apply(&none).message.contains("Your shell"));
    }

    #[test]
    fn unsafe_settings_files_are_refused_untouched() {
        // A symlink, even to a file of ours.
        let fx = Fx::new("symlink", "");
        fs::create_dir_all(fx.claude_dir()).unwrap();
        let target = fx.base.join("dotfiles-settings.json");
        fs::write(&target, "{}\n").unwrap();
        symlink(&target, fx.settings()).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("symlink"), "{}", a.message);
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");
        // Not valid JSON, and valid JSON that isn't an object.
        for (tag, body) in [
            ("badjson", "{\"env\": "),
            ("array", "[1,2]"),
            ("badenv", "{\"env\": 3}"),
        ] {
            let fx = Fx::new(tag, "");
            fx.write_settings(body);
            let a = apply(&fx);
            assert_eq!(a.action, Action::Refused, "{tag}: {a:?}");
            assert_eq!(fx.read_settings(), body);
            assert!(fx.baks().is_empty());
        }
        // A file of someone else.
        let fx = Fx::new("owner", "");
        fx.write_settings("{}\n");
        FAKE_EUID.with(|c| c.set(Some(unsafe { libc::geteuid() } + 1)));
        let a = apply(&fx);
        FAKE_EUID.with(|c| c.set(None));
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("not owned by you"), "{}", a.message);
        assert_eq!(fx.read_settings(), "{}\n");
        // A symlinked ~/.claude.
        let fx = Fx::new("dirlink", "");
        let real = fx.base.join("real-claude");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, fx.claude_dir()).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("not safe to edit"), "{}", a.message);
        assert!(!real.join("settings.json").exists());
    }

    #[test]
    fn undo_refuses_when_the_value_changed_and_says_nothing_to_undo_without_a_record() {
        let fx = Fx::new("changed", "");
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
        assert_eq!(apply(&fx).action, Action::Applied);
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"/somewhere/else.pem\"}}}}\n"
        ));
        let u = undo(&fx);
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert!(u.message.contains("changed since"));
        assert_eq!(
            env_key(&fx).as_deref(),
            Some("/somewhere/else.pem"),
            "left alone"
        );
        // The undo preview of a clean state describes the change without making it.
        let fx = Fx::new("undopreview", "");
        apply(&fx);
        let before = fx.read_settings();
        let p = claude_code(&fx.env(), Mode::Undo { dry_run: true });
        assert_eq!(p.action, Action::Preview);
        assert_eq!(fx.read_settings(), before);
    }

    #[test]
    fn status_reports_each_state() {
        let fx = Fx::new("status", "");
        let st = |fx: &Fx| -> Value { serde_json::from_str(&status_json(&fx.env(), "T")).unwrap() };
        assert_eq!(st(&fx)["claudeCode"]["state"], "absent");
        assert_eq!(st(&fx)["codex"]["state"], "absent");
        fx.write_settings(&format!("{{\"env\":{{\"{KEY}\":\"/theirs.pem\"}}}}\n"));
        assert_eq!(st(&fx)["claudeCode"]["state"], "other-value");
        assert_eq!(st(&fx)["claudeCode"]["value"], "/theirs.pem");
        fs::remove_file(fx.settings()).unwrap();
        apply(&fx);
        let s = st(&fx);
        assert_eq!(s["claudeCode"]["state"], "applied");
        assert_eq!(s["claudeCode"]["value"], fx.ca_path());
        assert_eq!(s["caPath"], fx.ca_path());
        // The documented shape, in order.
        let line = status_json(&fx.env(), "T");
        let v: Map<String, Value> = serde_json::from_str(&line).unwrap();
        assert_eq!(
            v.keys().collect::<Vec<_>>(),
            ["v", "type", "ts", "claudeCode", "codex", "caPath"]
        );
        assert_eq!(
            v["claudeCode"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["state", "settingsPath", "value"]
        );
        assert_eq!(
            v["codex"].as_object().unwrap().keys().collect::<Vec<_>>(),
            ["state", "bundlePath", "command"]
        );
        assert_eq!(v["type"], "trust-status");
        assert!(line.ends_with("}\n"));
    }

    #[test]
    fn trust_lines_have_the_documented_shape() {
        let fx = Fx::new("shape", "");
        let l = apply(&fx);
        let json = l.json("2026-01-01T00:00:00Z");
        let v: Map<String, Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "v",
                "type",
                "ts",
                "target",
                "action",
                "message",
                "settingsPath",
                "backupPath",
                "key",
                "from",
                "to",
                "bundlePath",
                "command"
            ]
        );
        assert_eq!(
            (
                v["v"].clone(),
                v["type"].clone(),
                v["target"].clone(),
                v["action"].clone()
            ),
            (
                json!(1),
                json!("trust"),
                json!("claude-code"),
                json!("applied")
            )
        );
        assert!(
            v["backupPath"].is_null()
                && v["from"].is_null()
                && v["bundlePath"].is_null()
                && v["command"].is_null()
        );
        assert_eq!(v["key"], KEY);
        assert_eq!(json.lines().count(), 1);
        for a in [
            Action::Preview,
            Action::Applied,
            Action::Already,
            Action::Undone,
            Action::NothingToUndo,
            Action::Refused,
        ] {
            assert!(
                [
                    "preview",
                    "applied",
                    "already",
                    "undone",
                    "nothing-to-undo",
                    "refused"
                ]
                .contains(&a.as_str())
            );
        }
    }

    #[test]
    fn codex_gets_a_combined_bundle_and_a_command_and_nothing_else_changes() {
        let fx = Fx::new("codex", "");
        // No system bundle yet.
        let r = codex(&fx.env(), false);
        assert_eq!(r.action, Action::Refused);
        assert!(r.message.contains("No system certificate bundle"));
        fx.roots();
        let a = codex(&fx.env(), false);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        let path = fx.ca_dir.join(CODEX_BUNDLE).display().to_string();
        assert_eq!(a.bundle_path.as_deref(), Some(path.as_str()));
        // The CA directory has a space in its name, so the path is quoted for fish and bash.
        assert_eq!(
            a.command,
            Some(format!("env CODEX_CA_CERTIFICATE='{path}' codex"))
        );
        let b = fs::read_to_string(&path).unwrap();
        assert_eq!(
            pem_certs(&b),
            [ROOT_A, ROOT_B, ROOT_C, CA1],
            "system roots plus exactly one collector cert"
        );
        assert_eq!(mode(Path::new(&path)), 0o644);
        assert_eq!(codex(&fx.env(), false).action, Action::Already);
        let s: Value = serde_json::from_str(&status_json(&fx.env(), "T")).unwrap();
        assert_eq!(s["codex"]["state"], "ready");
        assert_eq!(s["codex"]["bundlePath"], path);
        assert_eq!(
            s["codex"]["command"],
            format!("env CODEX_CA_CERTIFICATE='{path}' codex")
        );
        // No Codex config or shell profile exists to have been touched; the home is still empty.
        assert!(
            fs::read_dir(fx.base.join("fx/home"))
                .unwrap()
                .next()
                .is_none()
        );
        let u = codex(&fx.env(), true);
        assert_eq!(u.action, Action::Undone);
        assert!(!Path::new(&path).exists());
        assert_eq!(codex(&fx.env(), true).action, Action::NothingToUndo);
        // Without the collector certificate there is nothing to bundle.
        fs::remove_file(fx.ca_dir.join(CA_FILE)).unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Refused);
    }

    #[test]
    fn a_new_tls_start_regenerates_the_bundles_at_the_same_paths() {
        let fx = Fx::new("refresh", "");
        fx.roots();
        let mine = fx.base.join("mine.pem");
        fs::write(&mine, ROOT_A).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let (cb, xb) = (fx.ca_dir.join(CLAUDE_BUNDLE), fx.ca_dir.join(CODEX_BUNDLE));
        // A new run publishes a new certificate over the old one.
        fs::write(fx.ca_dir.join(CA_FILE), CA2).unwrap();
        let w = refresh(&fx.env());
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(pem_certs(&fs::read_to_string(&cb).unwrap()), [ROOT_A, CA2]);
        assert_eq!(
            pem_certs(&fs::read_to_string(&xb).unwrap()),
            [ROOT_A, ROOT_B, ROOT_C, CA2]
        );
        assert_eq!(
            env_key(&fx),
            Some(cb.display().to_string()),
            "the settings still point at the same path"
        );
        // Nothing recorded, nothing refreshed.
        let empty = Fx::new("refresh-empty", "");
        assert!(refresh(&empty.env()).is_empty());
        assert!(!empty.ca_dir.join(CLAUDE_BUNDLE).exists());
        // A bundle whose source vanished is reported, not silently stale.
        fs::remove_file(&mine).unwrap();
        let w = refresh(&fx.env());
        assert!(w.iter().any(|m| m.contains("Claude Code bundle")), "{w:?}");
    }

    #[test]
    fn pem_blocks_are_extracted_and_normalized() {
        let text = format!(
            "junk\n{ROOT_A}more junk\n-----BEGIN CERTIFICATE-----\n  AAAA  \n\n-----END CERTIFICATE-----\ntrailing"
        );
        let c = pem_certs(&text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], ROOT_A);
        assert_eq!(
            c[1],
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        );
        assert!(pem_certs("-----BEGIN CERTIFICATE-----\nunterminated").is_empty());
        assert!(pem_certs("").is_empty());
        assert_eq!(stamp("2026-11-06T15:46:58Z"), "20261106T154658Z");
        assert_eq!(backup_stamp(std::time::UNIX_EPOCH), "19700101T000000Z");
    }

    #[test]
    fn a_bundle_with_a_private_key_or_open_permissions_is_never_used() {
        let fx = Fx::new("keys", "");
        let mine = fx.base.join("withkey.pem");
        fs::write(
            &mine,
            format!("{ROOT_A}-----BEGIN PRIVATE KEY-----\nU0VDUkVU\n-----END PRIVATE KEY-----\n"),
        )
        .unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(!fx.ca_dir.join(CLAUDE_BUNDLE).exists());
        fs::write(&mine, ROOT_A).unwrap();
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            apply(&fx).action,
            Action::Refused,
            "a file others can write isn't a trustworthy source"
        );
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(apply(&fx).action, Action::Applied);
        // The bundle text never carried anything but certificates.
        let b = fs::read_to_string(fx.ca_dir.join(CLAUDE_BUNDLE)).unwrap();
        assert!(!b.contains("PRIVATE") && !b.contains("U0VDUkVU"));
    }
}
