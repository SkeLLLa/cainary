//! The trust state file (`otel-debug-trust.json`): what a committed Claude Code edit left
//! behind, the Codex bundle path, and a transaction that may not have finished.

use super::files::{read_in, unlink_in, write_atomic};
use super::{STATE_FILE, hook};
use crate::tls::ca_file::CaDir;
use serde_json::{Map, Value, json};
use std::io;

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
    pub(super) codex_bundle: Option<String>,
    pub(super) pending: Option<Pending>,
}

pub(super) fn claude_json(c: &ClaudeState) -> Value {
    json!({"settingsPath": c.settings_path, "original": c.original, "written": c.written,
           "createdEnv": c.created_env, "createdFile": c.created_file,
           "origSha": c.orig_sha, "backup": c.backup, "newSha": c.new_sha})
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
    })
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
        let codex_bundle = m
            .get("codex")
            .and_then(|c| c.get("bundlePath"))
            .and_then(Value::as_str)
            .map(str::to_string);
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
            codex_bundle,
            pending,
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut m = Map::new();
        if let Some(c) = &self.claude {
            m.insert("claudeCode".into(), claude_json(c));
        }
        if let Some(b) = &self.codex_bundle {
            m.insert("codex".into(), json!({"bundlePath": b}));
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
        self.claude.is_none() && self.codex_bundle.is_none() && self.pending.is_none()
    }
}

pub(super) fn read_state(ca: &CaDir) -> State {
    read_in(ca, STATE_FILE)
        .ok()
        .flatten()
        .map(|b| State::parse(&b))
        .unwrap_or_default()
}

pub(super) fn save_state(ca: &CaDir, st: &State) -> io::Result<()> {
    if hook::fail_save() {
        return Err(io::Error::other("injected failure"));
    }
    if st.is_empty() {
        unlink_in(ca, STATE_FILE)
    } else {
        write_atomic(ca, STATE_FILE, &st.to_bytes(), 0o600)
    }
}
