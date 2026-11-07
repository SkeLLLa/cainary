//! The trust state file (`otel-debug-trust.json`): what a committed Claude Code edit left
//! behind, the Codex bundle path, and a transaction that may not have finished.

use super::bundle::{cert_fingerprint, collector_ca, sha_of};
use super::files::{
    Replace, Snapshot, read_in, read_snapshot, replace_checked, unlink_in, unlink_unchanged,
    write_atomic,
};
use super::{CLAUDE_BUNDLE, CODEX_BUNDLE, NEWER, STATE_FILE, TAKEOVER, Target, hook};
use crate::tls::ca_file::{CA_FILE, CaDir};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// The state file's schema version. A file without `v` is version 1 (the first shape).
pub(super) const VERSION: u64 = 2;

fn default_modes() -> Vec<String> {
    vec![TAKEOVER.to_string()]
}

/// What a committed Claude Code edit left behind, enough to undo it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ClaudeState {
    pub(super) settings_path: String,
    pub(super) original: Option<String>,
    pub(super) written: String,
    pub(super) created_env: bool,
    pub(super) created_file: bool,
    /// SHA-256 of the file as it was before the edit (`None`: there was no file), the backup
    /// that holds those bytes, and SHA-256 of the file as cAInary left it. With all three, an
    /// undo of an untouched file restores the original bytes exactly.
    pub(super) orig_sha: Option<String>,
    pub(super) backup: Option<String>,
    pub(super) new_sha: Option<String>,
    /// The modes this target is enabled for (only `takeover` exists yet).
    pub(super) modes: Vec<String>,
    /// SHA-256 of the combined bundle as cAInary last wrote it (`None`: no bundle, or a record
    /// from before v2, whose bundle can't be checked).
    pub(super) bundle_sha: Option<String>,
    /// Fingerprints of the user's own certificates the bundle preserved.
    pub(super) orig_fps: Vec<String>,
}

/// The Codex target: the combined bundle it wrote and the modes it is enabled for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodexState {
    pub(super) bundle_path: String,
    pub(super) bundle_sha: Option<String>,
    pub(super) modes: Vec<String>,
}

/// One mode's collector certificate: the file and its fingerprint (SHA-256 of the DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModeCa {
    pub(super) ca_file: String,
    pub(super) fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingKind {
    Apply,
    Undo,
}

/// A transaction that was started and maybe not finished (design §17.2): written durably before
/// the settings change, cleared after the new record is. Whatever state the file is found in,
/// the hashes say how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pending {
    pub(super) kind: PendingKind,
    /// For an apply, the record to commit; for an undo, the record being undone.
    pub(super) claude: ClaudeState,
    /// SHA-256 of the settings file before the change (`None`: absent) and after (`None`: gone).
    pub(super) before: Option<String>,
    pub(super) after: Option<String>,
}

/// A bundle replacement that was started and maybe not finished: written durably before the
/// file is replaced, cleared once its hash is recorded. The file's hash says how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Journal {
    pub(super) target: Target,
    pub(super) path: String,
    pub(super) old_sha: Option<String>,
    pub(super) new_sha: String,
}

impl Journal {
    fn name(&self) -> Option<&str> {
        Path::new(&self.path).file_name()?.to_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct State {
    pub(super) claude: Option<ClaudeState>,
    pub(super) codex: Option<CodexState>,
    /// Keyed by mode name, so a later `proxy` fits without a schema change.
    pub(super) modes: BTreeMap<String, ModeCa>,
    pub(super) pending: Option<Pending>,
    /// Bundle replacements in flight (`pendingBundles`).
    pub(super) journal: Vec<Journal>,
    /// The file was written by a cAInary that knows a newer schema: readable for display, never
    /// written.
    pub(super) newer: bool,
}

pub(super) fn claude_json(c: &ClaudeState) -> Value {
    json!({"settingsPath": c.settings_path, "original": c.original, "written": c.written,
           "createdEnv": c.created_env, "createdFile": c.created_file,
           "origSha": c.orig_sha, "backup": c.backup, "newSha": c.new_sha,
           "modes": c.modes, "bundleSha": c.bundle_sha, "originalFingerprints": c.orig_fps})
}

pub(super) fn claude_from(c: &Map<String, Value>) -> Option<ClaudeState> {
    let s = |k: &str| c.get(k).and_then(Value::as_str).map(str::to_string);
    Some(ClaudeState {
        settings_path: s("settingsPath")?,
        original: s("original"),
        written: s("written")?,
        created_env: c
            .get("createdEnv")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        created_file: c
            .get("createdFile")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        orig_sha: s("origSha"),
        backup: s("backup"),
        new_sha: s("newSha"),
        modes: modes_of(c),
        bundle_sha: s("bundleSha"),
        orig_fps: strings(c.get("originalFingerprints")),
    })
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A v1 record has no `modes`: it is the takeover.
fn modes_of(c: &Map<String, Value>) -> Vec<String> {
    match c.get("modes") {
        Some(m) => strings(Some(m)),
        None => default_modes(),
    }
}

impl State {
    pub(super) fn parse(bytes: &[u8]) -> State {
        let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(bytes) else {
            return State::default();
        };
        let claude = m
            .get("claudeCode")
            .and_then(Value::as_object)
            .and_then(claude_from);
        let codex = m.get("codex").and_then(Value::as_object).and_then(|c| {
            Some(CodexState {
                bundle_path: c.get("bundlePath")?.as_str()?.to_string(),
                bundle_sha: c
                    .get("bundleSha")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                modes: modes_of(c),
            })
        });
        let modes = m
            .get("modes")
            .and_then(Value::as_object)
            .map(|t| {
                t.iter()
                    .filter_map(|(k, v)| {
                        Some((
                            k.clone(),
                            ModeCa {
                                ca_file: v.get("caFile")?.as_str()?.to_string(),
                                fingerprint: v.get("fingerprint")?.as_str()?.to_string(),
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let journal = m
            .get("pendingBundles")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|j| {
                        Some(Journal {
                            target: match j.get("target")?.as_str()? {
                                "claude-code" => Target::ClaudeCode,
                                "codex" => Target::Codex,
                                _ => return None,
                            },
                            path: j.get("path")?.as_str()?.to_string(),
                            old_sha: j.get("oldSha").and_then(Value::as_str).map(str::to_string),
                            new_sha: j.get("newSha")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // No `v` is the first shape; anything above ours (or not a number) is a newer file.
        let newer = m
            .get("v")
            .is_some_and(|v| v.as_u64().is_none_or(|n| n > VERSION));
        let pending = m.get("pending").and_then(Value::as_object).and_then(|p| {
            let kind = match p.get("kind")?.as_str()? {
                "apply" => PendingKind::Apply,
                "undo" => PendingKind::Undo,
                _ => return None,
            };
            Some(Pending {
                kind,
                claude: claude_from(p.get("claudeCode")?.as_object()?)?,
                before: p.get("before").and_then(Value::as_str).map(str::to_string),
                after: p.get("after").and_then(Value::as_str).map(str::to_string),
            })
        });
        State {
            claude,
            codex,
            modes,
            pending,
            journal,
            newer,
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("v".into(), json!(VERSION));
        let table: Map<String, Value> = self
            .modes
            .iter()
            .map(|(k, c)| {
                (
                    k.clone(),
                    json!({"caFile": c.ca_file, "fingerprint": c.fingerprint}),
                )
            })
            .collect();
        m.insert("modes".into(), Value::Object(table));
        if let Some(c) = &self.claude {
            m.insert("claudeCode".into(), claude_json(c));
        }
        if let Some(c) = &self.codex {
            m.insert(
                "codex".into(),
                json!({"bundlePath": c.bundle_path, "bundleSha": c.bundle_sha, "modes": c.modes}),
            );
        }
        if !self.journal.is_empty() {
            let j: Vec<Value> = self
                .journal
                .iter()
                .map(|j| json!({"target": j.target.as_str(), "path": j.path, "oldSha": j.old_sha, "newSha": j.new_sha}))
                .collect();
            m.insert("pendingBundles".into(), Value::Array(j));
        }
        if let Some(p) = &self.pending {
            m.insert(
                "pending".into(),
                json!({"kind": match p.kind { PendingKind::Apply => "apply", PendingKind::Undo => "undo" },
                       "claudeCode": claude_json(&p.claude), "before": p.before, "after": p.after}),
            );
        }
        format!(
            "{}\n",
            serde_json::to_string_pretty(&Value::Object(m)).expect("serializes")
        )
        .into_bytes()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.claude.is_none()
            && self.codex.is_none()
            && self.pending.is_none()
            && self.journal.is_empty()
    }
}

pub(super) fn read_state(ca: &CaDir) -> State {
    let mut st = read_in(ca, STATE_FILE)
        .ok()
        .flatten()
        .map(|b| State::parse(&b))
        .unwrap_or_default();
    // The Codex bundle has one possible path. A record naming another is not a record of ours.
    if st
        .codex
        .as_ref()
        .is_some_and(|c| c.bundle_path != expected_path(ca, Target::Codex))
    {
        st.codex = None;
    }
    st
}

impl State {
    /// The takeover's collector certificate as it is now, for the `modes` table. Kept as it was
    /// when the certificate can't be read.
    fn stamp_modes(&mut self, ca: &CaDir) {
        if let Ok(c) = collector_ca(ca) {
            self.modes.insert(
                TAKEOVER.to_string(),
                ModeCa {
                    ca_file: ca.path().join(CA_FILE).display().to_string(),
                    fingerprint: cert_fingerprint(&c),
                },
            );
        }
    }
}

/// Every write of the state file goes through here: it is always written as the current schema,
/// and never over a file a newer cAInary wrote.
pub(super) fn save_state(ca: &CaDir, st: &State) -> io::Result<()> {
    if st.newer {
        return Err(io::Error::other(NEWER));
    }
    if hook::fail_save() {
        return Err(io::Error::other("injected failure"));
    }
    if st.is_empty() {
        unlink_in(ca, STATE_FILE)
    } else {
        let mut st = st.clone();
        st.stamp_modes(ca);
        write_atomic(ca, STATE_FILE, &st.to_bytes(), 0o600)
    }
}

/// What the state file records about a file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Rec {
    /// No record that cAInary ever wrote this file.
    None,
    /// A record from before v2, which has no hash: the file is adopted as it is.
    Legacy,
    Sha(String),
}

impl Rec {
    /// For a record that exists: its hash, if it has one.
    pub(super) fn of(written: Option<&str>) -> Rec {
        written.map_or(Rec::Legacy, |w| Rec::Sha(w.to_string()))
    }
}

/// Whether a file cAInary owns is still what cAInary wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owned {
    /// No file: nothing foreign to protect, a write recreates it and an undo just clears the record.
    Missing,
    Ours,
    /// The bytes (or the file itself: a symlink, a directory, too big) are not what was written.
    Foreign,
    /// A record without a hash (v1): the file is adopted as it is.
    Unverified,
    /// A file with no record at all: cAInary never wrote it, so it is never replaced or deleted.
    Unrecorded,
}

impl Owned {
    /// May an owned file be deleted?
    pub(super) fn may_replace(self) -> bool {
        !matches!(self, Owned::Foreign | Owned::Unrecorded)
    }
}

/// The verdict on a file and the snapshot it was made from (for the re-check before the change).
pub(super) struct Checked {
    pub(super) owned: Owned,
    pub(super) snap: Option<Snapshot>,
}

impl Checked {
    /// May `new` be written over it? An unrecorded file only if it already holds exactly `new`
    /// (then it is adopted).
    pub(super) fn allows_write(&self, new: &[u8]) -> bool {
        match self.owned {
            Owned::Unrecorded => self.snap.as_ref().is_some_and(|s| s.bytes == new),
            o => o.may_replace(),
        }
    }
}

/// Compares the file in the collector directory with what the state file recorded for it.
pub(super) fn check_owned(ca: &CaDir, name: &str, rec: &Rec) -> Checked {
    let (owned, snap) = match read_snapshot(ca, name) {
        Ok(None) => (Owned::Missing, None),
        Ok(Some(s)) => (
            match rec {
                Rec::None => Owned::Unrecorded,
                Rec::Legacy => Owned::Unverified,
                Rec::Sha(w) if sha_of(&s.bytes) == *w => Owned::Ours,
                Rec::Sha(_) => Owned::Foreign,
            },
            Some(s),
        ),
        Err(_) => (Owned::Foreign, None),
    };
    Checked { owned, snap }
}

/// Deletes a file cAInary owns, unless it is foreign, unrecorded, or changed between the check and
/// the unlink (then it stays and this is still `Ok`: the caller's record is cleared regardless).
pub(super) fn delete_owned(ca: &CaDir, name: &str, rec: &Rec) -> io::Result<()> {
    let c = check_owned(ca, name, rec);
    if !c.owned.may_replace() {
        return Ok(());
    }
    match unlink_unchanged(ca, name, &c.snap) {
        Ok(()) | Err(Replace::Changed) => Ok(()),
        Err(_) => Err(io::Error::other("could not remove the file")),
    }
}

/// Why a bundle was not published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// Foreign, unrecorded, or changed since the check: left untouched.
    Foreign,
    Failed,
    /// Replaced, but durability is unknown; the journal stays.
    Uncertain,
    /// Test-only simulated crash after the replace.
    Crashed,
}

/// Replaces a bundle the safe way: check ownership, journal `{path, old, new}` durably, stage the
/// new bytes, re-check, rename. Returns the new hash with the journal entry still in `st` (and in
/// the file): the caller records the hash and then clears it, so a crash in between is
/// reconciled by `reconcile`. Identical bytes are not written (no journal).
pub(super) fn publish_bundle(
    ca: &CaDir,
    st: &mut State,
    target: Target,
    name: &str,
    rec: &Rec,
    bytes: &[u8],
) -> Result<String, Refused> {
    let new_sha = sha_of(bytes);
    let c = check_owned(ca, name, rec);
    if !c.allows_write(bytes) {
        return Err(Refused::Foreign);
    }
    if c.snap.as_ref().is_some_and(|s| s.bytes == bytes) {
        return Ok(new_sha);
    }
    let entry = Journal {
        target,
        path: ca.path().join(name).display().to_string(),
        old_sha: c.snap.as_ref().map(|s| sha_of(&s.bytes)),
        new_sha: new_sha.clone(),
    };
    st.journal.push(entry);
    if save_state(ca, st).is_err() {
        st.journal.pop();
        return Err(Refused::Failed);
    }
    let undo_journal = |st: &mut State| {
        st.journal.pop();
        let _ = save_state(ca, st);
    };
    match replace_checked(ca, name, bytes, 0o644, &c.snap) {
        Ok(()) => {}
        Err(Replace::Changed) => {
            undo_journal(st);
            return Err(Refused::Foreign);
        }
        Err(Replace::Failed) => {
            undo_journal(st);
            return Err(Refused::Failed);
        }
        Err(Replace::Uncertain) => return Err(Refused::Uncertain),
    }
    if hook::stop("after-bundle-publish") {
        return Err(Refused::Crashed);
    }
    Ok(new_sha)
}

impl State {
    /// Drops the journal entry for `name` (its hash is recorded now).
    pub(super) fn clear_journal(&mut self, name: &str) {
        self.journal.retain(|j| j.name() != Some(name));
    }
}

/// The one path each target's bundle may have: in the collector directory, under its fixed name.
pub(super) fn bundle_file(target: Target) -> &'static str {
    match target {
        Target::ClaudeCode => CLAUDE_BUNDLE,
        Target::Codex => CODEX_BUNDLE,
    }
}

fn expected_path(ca: &CaDir, target: Target) -> String {
    ca.path().join(bundle_file(target)).display().to_string()
}

/// What `reconcile` did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Reconciled {
    pub(super) changed: bool,
    /// An entry named a file other than its target's bundle and was dropped untouched.
    pub(super) ignored: bool,
}

/// Settles every journal entry from what the file holds now: the new hash means the replace
/// happened (the hash is recorded, or an orphaned Claude Code bundle that no settings file points
/// at is removed); the old hash (or still absent) means it never did; anything else is foreign and
/// left alone. An entry whose path isn't exactly its target's bundle is dropped without reading
/// anything. `claude_bundle_in_use`: the Claude Code settings point at the bundle, so an unrecorded
/// one is kept. Needs the trust lock, and the Claude Code settings transaction resolved first.
pub(super) fn reconcile(ca: &CaDir, st: &mut State, claude_bundle_in_use: bool) -> Reconciled {
    let mut out = Reconciled::default();
    if st.journal.is_empty() {
        return out;
    }
    out.changed = true;
    for j in std::mem::take(&mut st.journal) {
        let expected = expected_path(ca, j.target);
        if j.path != expected {
            out.ignored = true;
            continue;
        }
        let name = bundle_file(j.target);
        let now = match read_snapshot(ca, name) {
            Ok(s) => s.map(|s| sha_of(&s.bytes)),
            Err(_) => continue,
        };
        if now.as_deref() != Some(j.new_sha.as_str()) {
            continue;
        }
        let recorded = match j.target {
            Target::Codex => {
                let c = st.codex.get_or_insert_with(|| CodexState {
                    bundle_path: expected.clone(),
                    bundle_sha: None,
                    modes: default_modes(),
                });
                c.bundle_sha = Some(j.new_sha.clone());
                true
            }
            Target::ClaudeCode => match st.claude.as_mut() {
                Some(c) if c.written == expected => {
                    c.bundle_sha = Some(j.new_sha.clone());
                    true
                }
                _ => false,
            },
        };
        if !recorded && !claude_bundle_in_use {
            let _ = delete_owned(ca, name, &Rec::Sha(j.new_sha.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::bundle::cert_fingerprint;
    use crate::trust::tests::*;
    use crate::trust::*;
    use std::fs;
    use std::path::Path;

    const V1: &str = r#"{"claudeCode":{"settingsPath":"/h/.claude/settings.json","original":null,"written":"/s/ca.pem","createdEnv":true,"createdFile":false,"origSha":"aa","backup":"settings.json.cainary-1.bak","newSha":"bb"},"codex":{"bundlePath":"/s/codex.pem"}}"#;

    fn owned(s: &Value) -> Vec<Value> {
        s["owned"].as_array().unwrap().clone()
    }

    fn entry(s: &Value, target: &str, kind: &str) -> Value {
        owned(s)
            .into_iter()
            .find(|o| o["target"] == target && o["kind"] == kind)
            .unwrap_or_else(|| panic!("no {target} {kind} in {s}"))
    }

    fn put_state(fx: &Fx, text: &str) {
        let p = fx.ca_dir.join(STATE_FILE);
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }

    fn mine(fx: &Fx) {
        fx.roots();
        let m = fx.base.join("mine.pem");
        fs::write(&m, ROOT_A).unwrap();
        fx.write_settings(&format!("{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n", m.display()));
    }

    #[test]
    fn v1_parses_as_v2_takeover() {
        let st = State::parse(V1.as_bytes());
        assert!(!st.newer);
        let c = st.claude.as_ref().unwrap();
        assert_eq!(c.modes, [TAKEOVER]);
        assert_eq!(c.bundle_sha, None);
        assert!(c.orig_fps.is_empty());
        let x = st.codex.as_ref().unwrap();
        assert_eq!(
            (x.bundle_path.as_str(), x.modes.clone()),
            ("/s/codex.pem", vec![TAKEOVER.to_string()])
        );
        // It is rewritten as v2 on the next successful write.
        let fx = Fx::new("v1", "");
        fx.roots();
        let bundle = fx.ca_dir.join(CODEX_BUNDLE).display().to_string();
        put_state(&fx, &format!(r#"{{"codex":{{"bundlePath":"{bundle}"}}}}"#));
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let v: Value = serde_json::from_slice(&state_bytes(&fx).unwrap()).unwrap();
        assert_eq!(v["v"], 2);
        assert_eq!(v["codex"]["modes"], json!(["takeover"]));
        assert_eq!(v["modes"]["takeover"]["caFile"], fx.ca_path());
        assert_eq!(v["modes"]["takeover"]["fingerprint"], cert_fingerprint(CA1));
        assert!(v["codex"]["bundleSha"].is_string());
    }

    #[test]
    fn v2_roundtrip() {
        let mut st = State::parse(V1.as_bytes());
        st.claude.as_mut().unwrap().bundle_sha = Some("cc".into());
        st.claude.as_mut().unwrap().orig_fps = vec!["f1".into(), "f2".into()];
        st.codex.as_mut().unwrap().bundle_sha = Some("dd".into());
        st.modes.insert(
            TAKEOVER.into(),
            ModeCa {
                ca_file: "/s/ca.pem".into(),
                fingerprint: "ee".into(),
            },
        );
        let bytes = st.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["v"], 2);
        assert_eq!(State::parse(&bytes), st);
        assert_eq!(State::parse(&bytes).to_bytes(), bytes);
    }

    #[test]
    fn unknown_version_refuses_writes() {
        let fx = Fx::new("newer", "");
        mine(&fx);
        let bundle = fx.ca_dir.join(CODEX_BUNDLE);
        fs::write(&bundle, "x").unwrap();
        let text = format!(
            r#"{{"v":3,"codex":{{"bundlePath":"{}","future":1}},"extra":true}}"#,
            bundle.display()
        );
        put_state(&fx, &text);
        let settings = fx.read_settings();
        for l in [
            apply(&fx),
            undo(&fx),
            codex(&fx.env(), false),
            codex(&fx.env(), true),
        ] {
            assert_eq!(
                (l.action, l.message.as_str()),
                (Action::Refused, NEWER),
                "{l:?}"
            );
        }
        assert!(refresh(&fx.env()).iter().any(|w| w.contains(NEWER)));
        assert_eq!(state_bytes(&fx).unwrap(), text.as_bytes());
        assert_eq!(fs::read(&bundle).unwrap(), b"x");
        assert_eq!(fx.read_settings(), settings);
        // Status still shows what it can parse.
        let s = status(&fx);
        assert_eq!(s["note"], NEWER);
        assert_eq!(
            entry(&s, "codex", "bundle")["path"],
            bundle.display().to_string()
        );
        // A non-numeric version is just as unknown.
        put_state(&fx, r#"{"v":"two"}"#);
        assert_eq!(codex(&fx.env(), false).message, NEWER);
    }

    #[test]
    fn status_lists_owned() {
        let fx = Fx::new("owned", "");
        mine(&fx);
        assert!(owned(&status(&fx)).is_empty());
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let s = status(&fx);
        assert_eq!(owned(&s).len(), 4, "{s}");
        let sha = |p: &Path| sha_of(&fs::read(p).unwrap());
        let st = entry(&s, "claude-code", "settings");
        assert_eq!(st["mode"], "takeover");
        assert_eq!(st["key"], KEY);
        assert_eq!(st["path"], fx.settings().display().to_string());
        assert_eq!(st["sha256"], sha(&fx.settings()));
        assert_eq!(st["foreign"], false);
        let cb = fx.ca_dir.join(CLAUDE_BUNDLE);
        let b = entry(&s, "claude-code", "bundle");
        assert_eq!(b["path"], cb.display().to_string());
        assert_eq!(b["sha256"], sha(&cb));
        assert_eq!(b["foreign"], false);
        assert!(b["key"].is_null());
        assert_eq!(
            b["fingerprints"],
            json!([cert_fingerprint(ROOT_A), cert_fingerprint(CA1)])
        );
        let bak = entry(&s, "claude-code", "backup");
        assert_eq!(bak["foreign"], false);
        assert!(bak["sha256"].is_string());
        let x = entry(&s, "codex", "bundle");
        assert_eq!(x["sha256"], sha(&fx.ca_dir.join(CODEX_BUNDLE)));
        assert_eq!(x["fingerprints"], json!([cert_fingerprint(CA1)]));
        let t = status_text(&fx.env());
        assert!(t.contains("owned: takeover codex bundle ("), "{t}");
        assert!(t.starts_with("claude code: applied"));
    }

    #[test]
    fn changed_owned_file_untouched() {
        let fx = Fx::new("foreign", "");
        mine(&fx);
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let (cb, xb) = (fx.ca_dir.join(CLAUDE_BUNDLE), fx.ca_dir.join(CODEX_BUNDLE));
        for b in [&cb, &xb] {
            fs::write(b, format!("{}# edited\n", fs::read_to_string(b).unwrap())).unwrap();
        }
        let (cbytes, xbytes) = (fs::read(&cb).unwrap(), fs::read(&xb).unwrap());
        let (settings, state) = (fx.read_settings(), state_bytes(&fx));
        let s = status(&fx);
        assert_eq!(entry(&s, "claude-code", "bundle")["foreign"], true);
        assert_eq!(entry(&s, "codex", "bundle")["foreign"], true);
        assert_eq!(entry(&s, "claude-code", "settings")["foreign"], false);
        assert!(status_text(&fx.env()).contains(" foreign"));
        // Codex: neither a rewrite nor a delete.
        for undo_it in [false, true] {
            let l = codex(&fx.env(), undo_it);
            assert_eq!(l.action, Action::Refused, "{l:?}");
            assert!(l.message.contains("changed since cAInary wrote it"));
        }
        // Claude Code: the undo leaves the bundle and the settings alone.
        let u = undo(&fx);
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert_eq!(undo_preview(&fx).action, Action::Refused);
        // A refresh doesn't overwrite either, and says so.
        fs::write(fx.ca_dir.join(CA_FILE), CA2).unwrap();
        let w = refresh(&fx.env());
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(fs::read(&cb).unwrap(), cbytes);
        assert_eq!(fs::read(&xb).unwrap(), xbytes);
        assert_eq!(fx.read_settings(), settings);
        // (The state may be re-stamped for the new certificate; no owned file hash moved.)
        let v: Value = serde_json::from_slice(&state_bytes(&fx).unwrap()).unwrap();
        let before: Value = serde_json::from_slice(&state.unwrap()).unwrap();
        assert_eq!(v["claudeCode"], before["claudeCode"]);
        assert_eq!(v["codex"], before["codex"]);
        // A changed bundle that a refresh left behind blocks an apply too.
        fs::write(&xb, "other").unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Refused);
        assert_eq!(fs::read(&xb).unwrap(), b"other");
    }

    fn undo_preview(fx: &Fx) -> Line {
        claude_code(&fx.env(), Mode::Undo { dry_run: true })
    }

    #[test]
    fn missing_owned_file_behaviour() {
        // A file that is gone is not foreign: status reports it with no hash, a write
        // recreates it, and an undo just clears the record.
        let fx = Fx::new("missing", "");
        fx.roots();
        let xb = fx.ca_dir.join(CODEX_BUNDLE);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        fs::remove_file(&xb).unwrap();
        let s = status(&fx);
        let e = entry(&s, "codex", "bundle");
        assert_eq!(
            (e["foreign"].clone(), e["sha256"].is_null()),
            (json!(false), true)
        );
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        assert!(xb.exists());
        fs::remove_file(&xb).unwrap();
        assert_eq!(codex(&fx.env(), true).action, Action::Undone);
        assert!(state_bytes(&fx).is_none());
    }

    fn state_json(fx: &Fx) -> Value {
        serde_json::from_slice(&state_bytes(fx).unwrap()).unwrap()
    }

    #[test]
    fn undo_without_record_leaves_existing_bundle() {
        let fx = Fx::new("norecord", "");
        mine(&fx);
        let (cb, xb) = (fx.ca_dir.join(CLAUDE_BUNDLE), fx.ca_dir.join(CODEX_BUNDLE));
        fs::write(&xb, "someone else's file").unwrap();
        fs::write(&cb, "someone else's other file").unwrap();
        // No record: never deleted, never overwritten.
        for undo_it in [true, false] {
            let l = codex(&fx.env(), undo_it);
            assert_eq!(l.action, Action::Refused, "{l:?}");
            assert!(l.message.contains("no record"), "{}", l.message);
        }
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(a.message.contains("no record"), "{}", a.message);
        assert_eq!(fs::read(&xb).unwrap(), b"someone else's file");
        assert_eq!(fs::read(&cb).unwrap(), b"someone else's other file");
        assert_eq!(fx.read_settings().matches("mine.pem").count(), 1);
        assert!(state_bytes(&fx).is_none(), "nothing was recorded");
        // A file that already holds exactly what would be written is adopted, not rewritten.
        fs::remove_file(&xb).unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let good = fs::read(&xb).unwrap();
        fs::remove_file(fx.ca_dir.join(STATE_FILE)).unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Already);
        assert_eq!(fs::read(&xb).unwrap(), good);
        assert!(state_json(&fx)["codex"]["bundleSha"].is_string());
    }

    #[test]
    fn refresh_crash_after_publish_reconciles() {
        let fx = Fx::new("refresh-crash", "");
        mine(&fx);
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        fs::write(fx.ca_dir.join(CA_FILE), CA2).unwrap();
        stop_at("after-bundle-publish");
        let w = refresh(&fx.env());
        clear_hooks();
        assert!(!w.is_empty(), "{w:?}");
        let v = state_json(&fx);
        assert!(
            v["pendingBundles"].is_array(),
            "the journal is durable: {v}"
        );
        // The next run settles it: the files are ours, not foreign.
        let s = status(&fx);
        assert!(s["note"].as_str().unwrap().contains("bundle update"), "{s}");
        for o in owned(&s) {
            assert_eq!(o["foreign"], false, "{o}");
        }
        let v = state_json(&fx);
        assert!(v.get("pendingBundles").is_none());
        for (key, name) in [("claudeCode", CLAUDE_BUNDLE), ("codex", CODEX_BUNDLE)] {
            let on_disk = sha_of(&fs::read(fx.ca_dir.join(name)).unwrap());
            assert_eq!(v[key]["bundleSha"], on_disk, "{key}");
        }
        // And the next refresh and undo work as usual.
        assert!(refresh(&fx.env()).is_empty());
        assert_eq!(codex(&fx.env(), true).action, Action::Undone);
        assert_eq!(undo(&fx).action, Action::Undone);
    }

    #[test]
    fn codex_apply_crash_after_publish_reconciles() {
        let fx = Fx::new("codex-crash", "");
        fx.roots();
        let xb = fx.ca_dir.join(CODEX_BUNDLE);
        stop_at("after-bundle-publish");
        let l = codex(&fx.env(), false);
        clear_hooks();
        assert_eq!(l.action, Action::Refused);
        assert!(xb.exists());
        assert!(state_json(&fx)["pendingBundles"].is_array());
        assert!(
            state_json(&fx).get("codex").is_none(),
            "no hash was recorded yet"
        );
        // The next apply settles it, adopts the file and has nothing to write.
        let a = codex(&fx.env(), false);
        assert_eq!(a.action, Action::Already, "{a:?}");
        let v = state_json(&fx);
        assert!(v.get("pendingBundles").is_none());
        assert_eq!(v["codex"]["bundleSha"], sha_of(&fs::read(&xb).unwrap()));
        assert_eq!(entry(&status(&fx), "codex", "bundle")["foreign"], false);
        assert_eq!(codex(&fx.env(), true).action, Action::Undone);
    }

    #[test]
    fn pending_with_unknown_sha_is_foreign() {
        let fx = Fx::new("unknown-sha", "");
        fx.roots();
        let xb = fx.ca_dir.join(CODEX_BUNDLE);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        fs::write(&xb, "edited by someone").unwrap();
        let mut v = state_json(&fx);
        v["pendingBundles"] = json!([{"target": "codex", "path": xb.display().to_string(),
            "oldSha": "00", "newSha": "11"}]);
        put_state(&fx, &v.to_string());
        let s = status(&fx);
        assert_eq!(entry(&s, "codex", "bundle")["foreign"], true, "{s}");
        assert!(state_json(&fx).get("pendingBundles").is_none());
        assert_eq!(fs::read(&xb).unwrap(), b"edited by someone");
        assert_eq!(codex(&fx.env(), false).action, Action::Refused);
        assert_eq!(codex(&fx.env(), true).action, Action::Refused);
        assert_eq!(fs::read(&xb).unwrap(), b"edited by someone");
    }

    #[test]
    fn replaced_between_check_and_write_is_refused() {
        let fx = Fx::new("race", "");
        fx.roots();
        let xb = fx.ca_dir.join(CODEX_BUNDLE);
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let recorded = state_json(&fx);
        // A writer swaps the file after the check and before the rename: a rewrite is refused.
        fs::write(fx.ca_dir.join(CA_FILE), CA2).unwrap();
        let p = xb.clone();
        on_cas(move |point| {
            if point == CODEX_BUNDLE {
                fs::write(&p, "raced").unwrap();
            }
        });
        let w = refresh(&fx.env());
        clear_hooks();
        assert!(w.iter().any(|m| m.contains("changed since")), "{w:?}");
        assert_eq!(fs::read(&xb).unwrap(), b"raced");
        assert_eq!(state_json(&fx)["codex"], recorded["codex"]);
        assert!(state_json(&fx).get("pendingBundles").is_none());
        // The same before an undo: the file is not deleted.
        fs::remove_file(&xb).unwrap();
        fs::write(fx.ca_dir.join(CA_FILE), CA1).unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Applied);
        let p = xb.clone();
        on_cas(move |point| {
            if point == CODEX_BUNDLE {
                fs::write(&p, "raced again").unwrap();
            }
        });
        let u = codex(&fx.env(), true);
        clear_hooks();
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert_eq!(fs::read(&xb).unwrap(), b"raced again");
    }

    #[test]
    fn forged_journal_path_is_ignored() {
        let fx = Fx::new("forged", "");
        fx.roots();
        let ca_file = fx.ca_dir.join(CA_FILE);
        let other = fx.ca_dir.join("other.pem");
        fs::write(&other, "not ours").unwrap();
        let sha = |p: &Path| sha_of(&fs::read(p).unwrap());
        let entry = |target: &str, p: &Path| {
            json!({"target": target, "path": p.display().to_string(),
                   "oldSha": "00", "newSha": sha(p)})
        };
        let ca_bytes = fs::read(&ca_file).unwrap();
        put_state(
            &fx,
            &json!({"v": 2, "pendingBundles": [entry("claude-code", &ca_file), entry("codex", &other)],
                    "codex": {"bundlePath": other.display().to_string(), "bundleSha": sha(&other)}})
            .to_string(),
        );
        let s = status(&fx);
        assert!(
            s["note"].as_str().unwrap().contains("unexpected file"),
            "{s}"
        );
        assert_eq!(
            fs::read(&ca_file).unwrap(),
            ca_bytes,
            "the collector CA is intact"
        );
        assert_eq!(fs::read(&other).unwrap(), b"not ours");
        // The forged entries are gone, and neither a codex record nor the file was adopted.
        assert!(state_bytes(&fx).is_none_or(|b| {
            let v: Value = serde_json::from_slice(&b).unwrap();
            v.get("pendingBundles").is_none() && v.get("codex").is_none()
        }));
        assert!(owned(&s).is_empty());
    }

    #[test]
    fn claude_crash_after_settings_rename_keeps_bundle() {
        for refresh_first in [false, true] {
            let fx = Fx::new(&format!("order{refresh_first}"), "");
            mine(&fx);
            let cb = fx.ca_dir.join(CLAUDE_BUNDLE);
            stop_at("after-rename");
            let _ = apply(&fx);
            clear_hooks();
            let state = state_json(&fx);
            assert!(state["pending"].is_object() && state.get("claudeCode").is_none());
            assert!(cb.exists());
            let bundle_path = cb.display().to_string();
            // Neither a Codex apply nor a refresh may treat the bundle as an orphan.
            let go = |fx: &Fx, refresh_it: bool| {
                if refresh_it {
                    assert!(refresh(&fx.env()).is_empty());
                } else {
                    assert_eq!(codex(&fx.env(), false).action, Action::Applied);
                }
            };
            go(&fx, refresh_first);
            assert!(cb.exists(), "the bundle was deleted");
            assert_eq!(env_key(&fx), Some(bundle_path.clone()));
            go(&fx, !refresh_first);
            assert!(cb.exists());
            let s = status(&fx);
            assert_eq!(s["claudeCode"]["state"], "applied");
            for o in owned(&s) {
                assert_eq!(o["foreign"], false, "{o}");
            }
            let v = state_json(&fx);
            assert_eq!(
                v["claudeCode"]["bundleSha"],
                sha_of(&fs::read(&cb).unwrap())
            );
            assert!(v.get("pending").is_none() && v.get("pendingBundles").is_none());
            assert_eq!(undo(&fx).action, Action::Undone);
        }
    }
}
