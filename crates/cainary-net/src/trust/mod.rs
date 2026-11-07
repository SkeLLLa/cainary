//! `--trust` (design §17): let Claude Code and Codex trust the takeover CA.
//!
//! On an explicit action only, this edits one key (`env.NODE_EXTRA_CA_CERTS`) in the user's
//! Claude Code settings, after a backup, and can undo it; and it writes combined certificate
//! bundles next to the collector CA. It never edits Codex configuration, shell profiles or any
//! system trust store. Every file operation is relative to a validated directory descriptor.
//! The managed-settings check is the core's own Claude Code config resolution, in-process and
//! read-only. Certificate bundles of other programs are read narrowly here (`read_certs`),
//! because the harness refuses `*.pem` by design.

mod bundle;
mod claude;
mod codex;
mod files;
mod state;

pub use bundle::pem_certs;
pub use claude::claude_code;
pub use codex::codex;

use crate::jsonedit;
use crate::setup::quote;
use crate::tls::ca_file::{CA_FILE, CaDir, PROXY_CA_FILE};
use bundle::{collector_ca, sha_of};
use cainary_core::harness::{Harness, ToolHome};
use claude::{inspect_note, managed_sets_key, open_settings, recover, settings_view, sibling_sha};
use codex::codex_command;
use files::{lock_trust, read_in};
use serde_json::{Map, Value, json};
use state::{Owned, Rec, Refused, State, check_owned, read_state, rebuild, save_state};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The modes a bundle can trust (the `modes` table of the state file is keyed by name).
pub const TAKEOVER: &str = "takeover";
pub(super) const PROXY: &str = "proxy";
/// Every mode with the file its certificate lives in. This order is the bundle order.
pub(super) const MODES: [(&str, &str); 2] = [(TAKEOVER, CA_FILE), (PROXY, PROXY_CA_FILE)];
/// Said for every write or undo when the state file has a schema this build doesn't know.
pub(super) const NEWER: &str = "trust state was written by a newer cAInary; refusing to change it";

pub const KEY: &str = "NODE_EXTRA_CA_CERTS";
pub const CLAUDE_BUNDLE: &str = "otel-debug-claude-bundle.pem";
pub const CODEX_BUNDLE: &str = "otel-debug-codex-bundle.pem";
pub const STATE_FILE: &str = "otel-debug-trust.json";
pub const LOCK_FILE: &str = "otel-debug-trust.lock";

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
const RESTART: &str = "Close Claude Code before applying this, and restart it afterwards.";
const SHELL_WINS: &str = "Your shell sets NODE_EXTRA_CA_CERTS, which wins over the settings value.";

fn with_shell(h: &Harness, base: &str) -> String {
    if h.env(KEY).is_some() {
        format!("{base} {SHELL_WINS}")
    } else {
        base.to_string()
    }
}

/// `20261106T154658Z` from an RFC 3339 UTC time.
fn stamp(rfc: &str) -> String {
    rfc.chars().filter(|c| *c != '-' && *c != ':').collect()
}

fn dir_error(target: Target, what: &str, dir: &Path) -> Line {
    Line::refused(
        target,
        format!(
            "The {what} directory {} is not safe to edit (a symlink, not owned by you, or writable by group or others). If it is group- or other-writable, run: chmod go-w {}",
            crate::output::escape(&dir.display().to_string()),
            quote(&dir.display().to_string())
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Apply { dry_run: bool },
    Undo { dry_run: bool },
}

const BUSY: &str =
    "Another cainary-otel-debug --trust call is working on this right now; try again in a moment.";
#[cfg_attr(test, allow(dead_code))]
const LOCK_WAIT: Duration = Duration::from_secs(10);

fn lock_wait() -> Duration {
    #[cfg(test)]
    return Duration::from_millis(300);
    #[cfg(not(test))]
    LOCK_WAIT
}

fn status_wait() -> Duration {
    #[cfg(test)]
    return Duration::from_millis(100);
    #[cfg(not(test))]
    STATUS_WAIT
}
/// `--trust-status` waits this long for the lock, then only inspects.
#[cfg_attr(test, allow(dead_code))]
const STATUS_WAIT: Duration = Duration::from_secs(2);

// ── status ───────────────────────────────────────────────────────────────────────────────────

/// The `trust-status` line.
pub fn status_json(env: &Env<'_>, ts: &str) -> String {
    let h = env.harness;
    let ca_path = env.ca_dir.join(CA_FILE).display().to_string();
    let ca_open = CaDir::open_existing(&env.ca_dir).ok().flatten();
    // With the lock, an interrupted transaction is finished (or cleared) first, so the status is
    // of the result. Without it (another call is working; this waits `STATUS_WAIT`) the status
    // only inspects: it must never clear a transaction that is in progress.
    let lock = ca_open
        .as_ref()
        .and_then(|c| lock_trust(c, status_wait()).ok().flatten());
    let note = match (&ca_open, &lock) {
        (Some(c), Some(l)) => recover(env, c, l),
        (Some(c), None) => Some(
            inspect_note(env, c).unwrap_or_else(|| {
                "Another cainary-otel-debug --trust call is working; this is the state of the files right now.".to_string()
            }),
        ),
        _ => None,
    };
    let (state, claude_dir) = match ca_open {
        Some(d) => (read_state(&d), Some(d)),
        None => (State::default(), None),
    };
    let ca_exists = claude_dir.as_ref().is_some_and(|d| collector_ca(d).is_ok());
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
            Ok(Some(s)) => {
                let text = s.text();
                let value = jsonedit::parse(&text)
                    .ok()
                    .and_then(|d| d.env_value(KEY).ok().flatten());
                match value {
                    // A record only counts for the settings it was made for.
                    Some(v)
                        if v == ca_path
                            || state.claude.as_ref().is_some_and(|c| {
                                c.written == v && c.settings_path == s.path_str()
                            }) =>
                    {
                        ("applied", Some(v))
                    }
                    Some(v) => ("other-value", Some(v)),
                    None => ("absent", None),
                }
            }
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
    m.insert("caExists".into(), json!(ca_exists));
    let note = note.or_else(|| state.newer.then(|| NEWER.to_string()));
    m.insert("note".into(), json!(note));
    m.insert(
        "owned".into(),
        Value::Array(owned_entries(&state, claude_dir.as_ref())),
    );
    format!("{}\n", Value::Object(m))
}

/// One `owned[]` entry of the status line: a file, the modes it serves (registry order), and the
/// fingerprint of each mode's certificate when the file is a bundle.
#[allow(clippy::too_many_arguments)]
fn owned_entry(
    modes: &[&str],
    target: Target,
    kind: &str,
    path: &str,
    key: Option<&str>,
    fingerprints: &[String],
    ca_fingerprints: Map<String, Value>,
    sha: Option<String>,
    foreign: bool,
) -> Value {
    json!({"modes": modes, "target": target.as_str(), "kind": kind, "path": path, "key": key,
           "fingerprints": fingerprints, "caFingerprints": ca_fingerprints, "foreign": foreign,
           "sha256": sha})
}

/// Every file cAInary recorded as its own, with whether it is still what cAInary wrote. A file
/// that is gone is not foreign (`sha256` is null). The settings file is shared with Claude Code,
/// so it is foreign only when our key no longer holds our value.
fn owned_entries(state: &State, ca: Option<&CaDir>) -> Vec<Value> {
    let mut out = Vec::new();
    // The target's modes in registry order (the order the bundle is built in).
    let in_order = |modes: &[String]| -> Vec<&'static str> {
        MODES
            .iter()
            .map(|(m, _)| *m)
            .filter(|m| modes.iter().any(|x| x == m))
            .collect()
    };
    // The certificates a bundle holds: those of the modes its target is enabled for.
    let mode_fps = |modes: &[&str]| -> Map<String, Value> {
        modes
            .iter()
            .filter_map(|m| {
                state
                    .modes
                    .get(*m)
                    .map(|c| ((*m).to_string(), json!(c.fingerprint)))
            })
            .collect()
    };
    let bundle_state = |name: &str, written: Option<&str>| match ca {
        Some(d) => (
            check_owned(d, name, &Rec::of(written)).owned == Owned::Foreign,
            read_in(d, name).ok().flatten().map(|b| sha_of(&b)),
        ),
        None => (false, None),
    };
    if let Some(cs) = &state.claude {
        let dir = Path::new(&cs.settings_path).parent();
        let bundle_path = ca.map(|d| d.path().join(CLAUDE_BUNDLE).display().to_string());
        let modes = in_order(&cs.modes);
        let view = settings_view(&cs.settings_path);
        let foreign = view
            .as_ref()
            .is_some_and(|(_, v)| v.as_deref() != Some(cs.written.as_str()));
        out.push(owned_entry(
            &modes,
            Target::ClaudeCode,
            "settings",
            &cs.settings_path,
            Some(KEY),
            &[],
            Map::new(),
            view.map(|(s, _)| s),
            foreign,
        ));
        if let (Some(name), Some(dir)) = (&cs.backup, dir) {
            let sha = sibling_sha(&cs.settings_path, name);
            let foreign = sha.is_some() && cs.orig_sha.is_some() && sha != cs.orig_sha;
            out.push(owned_entry(
                &modes,
                Target::ClaudeCode,
                "backup",
                &dir.join(name).display().to_string(),
                None,
                &[],
                Map::new(),
                sha,
                foreign,
            ));
        }
        if let Some(bp) = bundle_path.as_ref().filter(|p| **p == cs.written) {
            let (foreign, sha) = bundle_state(CLAUDE_BUNDLE, cs.bundle_sha.as_deref());
            let cas = mode_fps(&modes);
            let fps: Vec<String> = cs
                .orig_fps
                .iter()
                .cloned()
                .chain(cas.values().filter_map(|v| v.as_str().map(str::to_string)))
                .collect();
            out.push(owned_entry(
                &modes,
                Target::ClaudeCode,
                "bundle",
                bp,
                None,
                &fps,
                cas,
                sha,
                foreign,
            ));
        }
    }
    if let Some(c) = &state.codex {
        let modes = in_order(&c.modes);
        let (foreign, sha) = bundle_state(CODEX_BUNDLE, c.bundle_sha.as_deref());
        let cas = mode_fps(&modes);
        let fps: Vec<String> = cas
            .values()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        out.push(owned_entry(
            &modes,
            Target::Codex,
            "bundle",
            &c.bundle_path,
            None,
            &fps,
            cas,
            sha,
            foreign,
        ));
    }
    out
}

/// A person's version of the status.
pub fn status_text(env: &Env<'_>) -> String {
    let v: Value = serde_json::from_str(&status_json(env, "")).expect("our own JSON");
    let s = |p: &Value| p.as_str().unwrap_or("-").to_string();
    let mut text = format!(
        "claude code: {} ({})\ncodex: {}\ncertificate: {}\n",
        s(&v["claudeCode"]["state"]),
        crate::output::escape(&s(&v["claudeCode"]["settingsPath"])),
        s(&v["codex"]["state"]),
        crate::output::escape(&s(&v["caPath"])),
    );
    for o in v["owned"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "owned: {} {} {} ({}){}\n",
            o["modes"]
                .as_array()
                .map(|m| m.iter().map(&s).collect::<Vec<_>>().join(","))
                .unwrap_or_default(),
            s(&o["target"]),
            s(&o["kind"]),
            crate::output::escape(&s(&o["path"])),
            if o["foreign"] == true { " foreign" } else { "" },
        ));
    }
    text
}

// ── each `--tls` start ───────────────────────────────────────────────────────────────────────

/// After a new CA is published: regenerate the combined bundles recorded in the state file from
/// their originals plus the certificate of every mode they are enabled for. The paths never
/// change; the clients must still be restarted. Returns what could not be refreshed.
pub fn refresh(env: &Env<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    let Ok(Some(ca_dir)) = CaDir::open_existing(&env.ca_dir) else {
        return warnings;
    };
    let _lock = match lock_trust(&ca_dir, Duration::from_secs(5)) {
        Ok(Some(l)) => l,
        _ => {
            return vec![
                "another trust command is running; the trust bundles were not refreshed".into(),
            ];
        }
    };
    if let claude::Recovery::Pending(why) = claude::recover_outcome(env, &ca_dir, &_lock) {
        return vec![format!(
            "a previous trust change is still being recovered ({why}); the trust bundles were not refreshed"
        )];
    }
    let mut state = read_state(&ca_dir);
    if state.is_empty() {
        return warnings;
    }
    if state.newer {
        return vec![format!("{NEWER}; the trust bundles were not refreshed")];
    }
    // Replacements an earlier run didn't finish were settled from the files' hashes by `recover`.
    let mut changed = false;
    let claude_modes = state
        .claude
        .as_ref()
        .filter(|c| c.written == ca_dir.path().join(CLAUDE_BUNDLE).display().to_string())
        .map(|c| c.modes.clone());
    let codex_modes = state.codex.as_ref().map(|c| c.modes.clone());
    for (target, modes) in [
        (Target::ClaudeCode, claude_modes),
        (Target::Codex, codex_modes),
    ] {
        let Some(modes) = modes else { continue };
        let what = match target {
            Target::ClaudeCode => "the Claude Code trust bundle",
            Target::Codex => "the Codex bundle",
        };
        match rebuild(env, &ca_dir, &mut state, target, &modes) {
            Ok(_) => changed = true,
            Err(Refused::Foreign) => warnings.push(format!(
                "{what} was changed since cAInary wrote it; it was not refreshed"
            )),
            Err(Refused::MissingCa(m)) => warnings.push(format!(
                "the {m} certificate is missing; {what} was left as it is"
            )),
            Err(Refused::NoSource) => warnings.push(match target {
                Target::ClaudeCode => "the file your Claude Code bundle was made from can't be read; the bundle was not refreshed".to_string(),
                Target::Codex => "no system certificate bundle was found; the Codex bundle was not refreshed".to_string(),
            }),
            Err(_) => warnings.push(format!("{what} could not be rewritten")),
        }
    }
    if changed && save_state(&ca_dir, &state).is_err() {
        warnings.push("the trust state could not be updated".into());
    }
    warnings
}

/// Adds `mode` to `target`'s trust (the CLI's `--trust X` is this with `TAKEOVER`).
pub(crate) fn apply_mode(env: &Env<'_>, target: Target, mode: &str) -> Line {
    match target {
        Target::ClaudeCode => claude::claude_mode(env, mode, false),
        Target::Codex => codex::codex_mode(env, mode, false),
    }
}

/// Removes `mode` from `target`'s trust; the last mode undoes the target completely.
pub(crate) fn undo_mode(env: &Env<'_>, target: Target, mode: &str) -> Line {
    match target {
        Target::ClaudeCode => claude::claude_mode(env, mode, true),
        Target::Codex => codex::codex_mode(env, mode, true),
    }
}

/// The trust lock, kept by `--delete-ca` from the undo of every target to the unlink of the CA.
pub struct Held(#[allow(dead_code)] files::TrustLock);

/// What `undo_mode_everywhere_held` found: its lines, and (only when the CA may now be deleted)
/// the lock to hold until it is.
pub struct Cleared {
    pub lines: Vec<Line>,
    pub held: Option<Held>,
    pub ok: bool,
}

/// `--delete-ca`'s first step, called with the run lock held: removes `mode` from every target
/// that has it (the trust lock is taken here, after the run lock, never the other way round).
/// A target without the mode is left alone, so with no trust recorded there are no lines.
pub fn undo_mode_everywhere(env: &Env<'_>, mode: &str) -> Vec<Line> {
    undo_mode_everywhere_held(env, mode).lines
}

/// Like `undo_mode_everywhere`, but the trust lock is held from recovery through every undo and a
/// final check that nothing still holds the takeover certificate, and handed back so the caller
/// unlinks the CA before anything else can apply. `ok` is false when the CA must stay.
pub fn undo_mode_everywhere_held(env: &Env<'_>, mode: &str) -> Cleared {
    let refuse = |lines: Vec<Line>| Cleared {
        lines,
        held: None,
        ok: false,
    };
    let Ok(Some(ca)) = CaDir::open_existing(&env.ca_dir) else {
        return Cleared {
            lines: Vec::new(),
            held: None,
            ok: true,
        };
    };
    let t = Target::ClaudeCode;
    let lock = match lock_trust(&ca, lock_wait()) {
        Ok(Some(l)) => l,
        Ok(None) => return refuse(vec![Line::refused(t, BUSY)]),
        Err(_) => {
            return refuse(vec![Line::refused(t, "The trust lock could not be taken.")]);
        }
    };
    if let claude::Recovery::Pending(why) = claude::recover_outcome(env, &ca, &lock) {
        return refuse(vec![Line::refused(
            t,
            format!("A trust change is still being recovered, so the certificate was kept: {why}"),
        )]);
    }
    let state = read_state(&ca);
    if state.newer {
        return refuse(vec![Line::refused(t, NEWER)]);
    }
    let has = |modes: &[String]| modes.iter().any(|m| m == mode);
    let mut targets = Vec::new();
    if state.claude.as_ref().is_some_and(|c| has(&c.modes)) {
        targets.push(Target::ClaudeCode);
    }
    if state.codex.as_ref().is_some_and(|c| has(&c.modes)) {
        targets.push(Target::Codex);
    }
    let mut lines: Vec<Line> = targets
        .into_iter()
        .map(|t| match t {
            Target::ClaudeCode => claude::claude_mode_locked(env, &ca, &lock, mode, true),
            Target::Codex => codex::codex_mode_locked(env, &ca, &lock, mode, true),
        })
        .collect();
    if lines.iter().any(|l| l.code() != 0) {
        return refuse(lines);
    }
    if let Some(m) = still_holds(&ca, mode) {
        lines.push(Line::refused(t, m));
        return refuse(lines);
    }
    Cleared {
        lines,
        held: Some(Held(lock)),
        ok: true,
    }
}

/// Why the CA of `mode` must stay: a record still enables it, or a bundle still contains it.
fn still_holds(ca: &CaDir, mode: &str) -> Option<String> {
    let state = read_state(ca);
    if state.pending.is_some() || !state.journal.is_empty() || state.newer {
        return Some(
            "A trust change is still being recovered, so the certificate was kept.".into(),
        );
    }
    let on = |modes: &[String]| modes.iter().any(|m| m == mode);
    let direct = ca.path().join(CA_FILE).display().to_string();
    if state
        .claude
        .as_ref()
        .is_some_and(|c| on(&c.modes) || c.written == direct)
        || state.codex.as_ref().is_some_and(|c| on(&c.modes))
    {
        return Some("A trust record still enables the certificate, so it was kept.".into());
    }
    let file = MODES.iter().find(|(m, _)| *m == mode)?.1;
    let fp = bundle::cert_fingerprint(
        &pem_certs(&String::from_utf8_lossy(&read_in(ca, file).ok().flatten()?))
            .into_iter()
            .next()?,
    );
    for name in [CLAUDE_BUNDLE, CODEX_BUNDLE] {
        let Ok(Some(b)) = read_in(ca, name) else {
            continue;
        };
        if pem_certs(&String::from_utf8_lossy(&b))
            .iter()
            .any(|c| bundle::cert_fingerprint(c) == fp)
        {
            return Some(format!(
                "A certificate bundle still contains the certificate, so it was kept: {name}."
            ));
        }
    }
    None
}

/// For the tests and the CLI: the time stamp used in backup names.
pub fn backup_stamp(t: SystemTime) -> String {
    stamp(&cainary_core::value::rfc3339(t))
}
/// Test-only fault injection: a simulated crash at a named point, a failing state write, and a
/// callback just before the compare-then-swap. Compiled to nothing outside tests.
mod hook {
    #[cfg(not(test))]
    pub fn stop(_: &str) -> bool {
        false
    }
    #[cfg(not(test))]
    pub fn fail_save() -> bool {
        false
    }
    #[cfg(not(test))]
    pub fn before_cas(_: &str) {}
    #[cfg(not(test))]
    pub fn fail_sync() -> bool {
        false
    }
    #[cfg(not(test))]
    pub fn after_stat(_: &str) {}

    #[cfg(test)]
    pub type CasHook = Box<dyn FnMut(&str)>;

    #[cfg(test)]
    thread_local! {
        pub static STOP: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
        pub static FAIL_SAVES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        pub static FAIL_SYNCS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        pub static CAS: std::cell::RefCell<Option<CasHook>> = std::cell::RefCell::new(None);
        pub static AFTER_STAT: std::cell::RefCell<Option<CasHook>> = std::cell::RefCell::new(None);
        pub static FAKE_EUID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    }
    #[cfg(test)]
    pub fn stop(at: &str) -> bool {
        STOP.with(|s| s.get() == Some(at))
    }
    #[cfg(test)]
    pub fn fail_save() -> bool {
        FAIL_SAVES.with(|c| {
            let n = c.get();
            if n > 0 {
                c.set(n - 1);
            }
            n > 0
        })
    }
    #[cfg(test)]
    pub fn fail_sync() -> bool {
        FAIL_SYNCS.with(|c| {
            let n = c.get();
            if n > 0 {
                c.set(n - 1);
            }
            n > 0
        })
    }
    #[cfg(test)]
    pub fn after_stat(name: &str) {
        AFTER_STAT.with(|c| {
            if let Some(f) = c.borrow_mut().as_mut() {
                f(name);
            }
        });
    }
    #[cfg(test)]
    pub fn before_cas(point: &str) {
        CAS.with(|c| {
            if let Some(f) = c.borrow_mut().as_mut() {
                f(point);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::files::TrustLock;
    use super::*;
    use cainary_core::harness::platform::Os;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    pub(super) use super::hook::FAKE_EUID;

    pub(super) const CA1: &str =
        "-----BEGIN CERTIFICATE-----\nQ09MTEVDVE9SLU9ORQ==\n-----END CERTIFICATE-----\n";
    pub(super) const CA2: &str =
        "-----BEGIN CERTIFICATE-----\nQ09MTEVDVE9SLVRXTw==\n-----END CERTIFICATE-----\n";
    pub(super) const ROOT_A: &str =
        "-----BEGIN CERTIFICATE-----\nUk9PVC1B\n-----END CERTIFICATE-----\n";
    pub(super) const ROOT_B: &str =
        "-----BEGIN CERTIFICATE-----\nUk9PVC1C\n-----END CERTIFICATE-----\n";
    pub(super) const ROOT_C: &str =
        "-----BEGIN CERTIFICATE-----\nUk9PVC1D\n-----END CERTIFICATE-----\n";

    pub(super) struct Fx {
        pub(super) base: PathBuf,
        pub(super) harness: Harness,
        pub(super) ca_dir: PathBuf,
        pub(super) _lock: Option<crate::tls::ca_file::Published>,
    }

    impl Fx {
        pub(super) fn new(tag: &str, fixture_env: &str) -> Fx {
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

        pub(super) fn env(&self) -> Env<'_> {
            Env {
                harness: &self.harness,
                ca_dir: self.ca_dir.clone(),
            }
        }

        pub(super) fn claude_dir(&self) -> PathBuf {
            self.base.join("fx/home/.claude")
        }

        pub(super) fn settings(&self) -> PathBuf {
            self.claude_dir().join("settings.json")
        }

        pub(super) fn write_settings(&self, text: &str) {
            fs::create_dir_all(self.claude_dir()).unwrap();
            fs::write(self.settings(), text).unwrap();
        }

        pub(super) fn read_settings(&self) -> String {
            fs::read_to_string(self.settings()).unwrap()
        }

        pub(super) fn managed(&self, json: &str) {
            let d = self.base.join("fx/root/etc/claude-code");
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("managed-settings.json"), json).unwrap();
        }

        pub(super) fn roots(&self) {
            let d = self.base.join("fx/root/etc/ssl/certs");
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("ca-certificates.crt"),
                format!("{ROOT_A}{ROOT_B}{ROOT_C}"),
            )
            .unwrap();
        }

        pub(super) fn baks(&self) -> Vec<String> {
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

        pub(super) fn ca_path(&self) -> String {
            self.ca_dir.join(CA_FILE).display().to_string()
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            self._lock = None;
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    pub(super) fn apply(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Apply { dry_run: false })
    }
    pub(super) fn preview(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Apply { dry_run: true })
    }
    pub(super) fn undo(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Undo { dry_run: false })
    }
    pub(super) fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }
    pub(super) fn env_key(fx: &Fx) -> Option<String> {
        let v: Value = serde_json::from_str(&fx.read_settings()).unwrap();
        v["env"][KEY].as_str().map(str::to_string)
    }

    // ── transactions, compare-and-swap, fidelity, locations ──
    pub(super) fn stop_at(point: &'static str) {
        hook::STOP.with(|s| s.set(Some(point)));
    }
    pub(super) fn clear_hooks() {
        hook::STOP.with(|s| s.set(None));
        hook::FAIL_SYNCS.with(|c| c.set(0));
        hook::AFTER_STAT.with(|c| *c.borrow_mut() = None);
        hook::FAIL_SAVES.with(|c| c.set(0));
        hook::CAS.with(|c| *c.borrow_mut() = None);
    }
    pub(super) fn on_cas(f: impl FnMut(&str) + 'static) {
        hook::CAS.with(|c| *c.borrow_mut() = Some(Box::new(f)));
    }
    pub(super) fn state_bytes(fx: &Fx) -> Option<Vec<u8>> {
        fs::read(fx.ca_dir.join(STATE_FILE)).ok()
    }
    pub(super) fn status(fx: &Fx) -> Value {
        serde_json::from_str(&status_json(&fx.env(), "T")).unwrap()
    }

    pub(super) fn hold(fx: &Fx) -> (CaDir, TrustLock) {
        let ca = CaDir::open_existing(&fx.ca_dir).unwrap().unwrap();
        let lock = lock_trust(&ca, Duration::from_secs(1))
            .unwrap()
            .expect("free");
        (ca, lock)
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
        assert_eq!(
            s["claudeCode"]["value"],
            fx.ca_dir.join(CLAUDE_BUNDLE).display().to_string()
        );
        assert_eq!(s["caPath"], fx.ca_path());
        // The documented shape, in order.
        let line = status_json(&fx.env(), "T");
        let v: Map<String, Value> = serde_json::from_str(&line).unwrap();
        assert_eq!(
            v.keys().collect::<Vec<_>>(),
            [
                "v",
                "type",
                "ts",
                "claudeCode",
                "codex",
                "caPath",
                "caExists",
                "note",
                "owned"
            ]
        );
        assert_eq!(v["caExists"], true);
        assert!(v["note"].is_null());
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
                && v["bundlePath"].is_string()
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
    fn status_says_whether_the_ca_exists() {
        let fx = Fx::new("caexists", "");
        assert_eq!(status(&fx)["caExists"], true);
        fs::remove_file(fx.ca_dir.join(CA_FILE)).unwrap();
        assert_eq!(status(&fx)["caExists"], false);
        let none = Fx::new("caexists-none", "");
        fs::remove_dir_all(&none.ca_dir).ok();
        let env = Env {
            harness: &none.harness,
            ca_dir: none.base.join("nowhere/cainary"),
        };
        let s: Value = serde_json::from_str(&status_json(&env, "T")).unwrap();
        assert_eq!(s["caExists"], false);
    }

    #[test]
    fn calls_are_serialized_by_one_lock_and_a_status_cannot_clear_a_transaction_in_progress() {
        let fx = Fx::new("lock", "");
        fx.write_settings("{\"model\":\"opus\"}\n");
        // Another process is mid-transaction: a pending record exists and it holds the lock.
        stop_at("after-rename");
        let _ = apply(&fx);
        clear_hooks();
        let (_ca, held) = hold(&fx);
        let before = state_bytes(&fx);
        assert!(String::from_utf8_lossy(before.as_ref().unwrap()).contains("pending"));
        // Every writer is refused with the same fixed answer, and nothing moves.
        let a = apply(&fx);
        assert_eq!(
            (a.action, a.message.as_str()),
            (Action::Refused, BUSY),
            "{a:?}"
        );
        let u = undo(&fx);
        assert_eq!((u.action, u.message.as_str()), (Action::Refused, BUSY));
        let c = codex(&fx.env(), false);
        assert_eq!((c.action, c.message.as_str()), (Action::Refused, BUSY));
        assert_eq!(codex(&fx.env(), true).message, BUSY);
        assert!(
            refresh(&fx.env())
                .iter()
                .any(|w| w.contains("another trust command"))
        );
        // A status waits briefly, then only inspects: it reports and leaves the record alone.
        let s = status(&fx);
        assert!(s["note"].as_str().unwrap().contains("pending"), "{s}");
        assert_eq!(state_bytes(&fx), before, "the transaction is untouched");
        // Previews take no lock at all and write nothing.
        let p = preview(&fx);
        assert_ne!(p.action, Action::Refused, "{p:?}");
        assert_eq!(state_bytes(&fx), before);
        drop(held);
        // With the lock free, the next status finishes it.
        let s = status(&fx);
        assert!(
            s["note"]
                .as_str()
                .unwrap()
                .contains("Finished an interrupted"),
            "{s}"
        );
        assert_eq!(s["claudeCode"]["state"], "applied");
    }

    #[test]
    fn inspection_never_writes_state_or_deletes_bundles() {
        let fx = Fx::new("inspect", "");
        let mine = fx.base.join("mine.pem");
        fs::write(&mine, ROOT_A).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        assert_eq!(apply(&fx).action, Action::Applied);
        let bundle = fx.ca_dir.join(CLAUDE_BUNDLE);
        assert!(bundle.exists());
        // An undo that stops after the swap: settings restored, bundle and transaction left.
        stop_at("after-rename");
        let _ = undo(&fx);
        clear_hooks();
        let before = state_bytes(&fx);
        let listing = |fx: &Fx| -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(&fx.ca_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n != "otel-debug-trust.lock")
                .collect();
            v.sort();
            v
        };
        let files = listing(&fx);
        for l in [
            preview(&fx),
            claude_code(&fx.env(), Mode::Undo { dry_run: true }),
        ] {
            // (The undo preview may say the setting is no longer the one cAInary wrote: the
            // interrupted undo had already restored it. It still must not touch anything.)
            assert!(l.message.contains("pending"), "{}", l.message);
        }
        // A status that can't take the lock only inspects.
        let (_ca, held) = hold(&fx);
        let s = status(&fx);
        assert!(s["note"].as_str().unwrap().contains("pending"), "{s}");
        drop(held);
        assert_eq!(state_bytes(&fx), before, "no state written");
        assert_eq!(listing(&fx), files, "no file created or deleted");
        assert!(bundle.exists(), "the bundle is still there");
        // The real thing finishes it, and removes the bundle then.
        let s = status(&fx);
        assert!(
            s["note"].as_str().unwrap().contains("interrupted undo"),
            "{s}"
        );
        assert!(!bundle.exists());
        assert!(state_bytes(&fx).is_none());
    }
}
