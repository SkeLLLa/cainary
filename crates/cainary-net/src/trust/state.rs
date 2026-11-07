//! The trust state file (`otel-debug-trust.json`): what a committed Claude Code edit left
//! behind, the Codex bundle path, and a transaction that may not have finished.

use super::bundle::{cert_fingerprint, collector_ca, sha_of};
use super::files::{read_in, unlink_in, write_atomic};
use super::{NEWER, STATE_FILE, TAKEOVER, hook};
use crate::tls::ca_file::{CA_FILE, CaDir};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io;

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct State {
    pub(super) claude: Option<ClaudeState>,
    pub(super) codex: Option<CodexState>,
    /// Keyed by mode name, so a later `proxy` fits without a schema change.
    pub(super) modes: BTreeMap<String, ModeCa>,
    pub(super) pending: Option<Pending>,
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
        self.claude.is_none() && self.codex.is_none() && self.pending.is_none()
    }
}

pub(super) fn read_state(ca: &CaDir) -> State {
    read_in(ca, STATE_FILE)
        .ok()
        .flatten()
        .map(|b| State::parse(&b))
        .unwrap_or_default()
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

/// Whether a file cAInary owns is still what cAInary wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owned {
    /// No file: nothing foreign to protect, a write recreates it and an undo just clears the record.
    Missing,
    Ours,
    /// The bytes (or the file itself: a symlink, a directory, too big) are not what was written.
    Foreign,
    /// No hash was recorded (a v1 record): the file is adopted as it is.
    Unverified,
}

impl Owned {
    pub(super) fn may_replace(self) -> bool {
        self != Owned::Foreign
    }
}

/// Compares the file in the collector directory with the hash cAInary recorded for it.
pub(super) fn check_owned(ca: &CaDir, name: &str, written: Option<&str>) -> Owned {
    match read_in(ca, name) {
        Ok(None) => Owned::Missing,
        Ok(Some(b)) => match written {
            None => Owned::Unverified,
            Some(w) if sha_of(&b) == w => Owned::Ours,
            Some(_) => Owned::Foreign,
        },
        Err(_) => Owned::Foreign,
    }
}

/// Deletes a file cAInary owns, unless it was changed since cAInary wrote it (then it stays).
pub(super) fn drop_owned(ca: &CaDir, name: &str, written: Option<&str>) -> io::Result<()> {
    if check_owned(ca, name, written).may_replace() {
        unlink_in(ca, name)
    } else {
        Ok(())
    }
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
}
