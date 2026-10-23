//! The schema-3 report the core prints (docs/architecture.md §3.6, §4.3). The tray renders what
//! is here: it never computes a level, a summary or a diff.
//!
//! Slugs other than `level` stay plain strings; `KNOWN_*` lists say which ones this build
//! recognises, so an unknown value shows as its slug instead of failing the decode.

use serde::{Deserialize, Serialize};

use crate::level::Level;

/// The only schema major this build reads. Anything else asks the user to update.
pub const SCHEMA: u64 = 3;

pub const KNOWN_SCOPES: &[&str] = &["entry", "finding", "source", "report"];
pub const KNOWN_CHANGE_KINDS: &[&str] = &["added", "removed", "raised", "lowered", "changed"];
/// Source states that mean the scan couldn't fully read a location.
pub const PROBLEM_STATES: &[&str] = &["error", "refused", "capped"];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub level: Level,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub summary: String,
}

/// Where a finding's setting lives and the lines that prove it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// Stable across scans; the positional `id` is not.
    #[serde(default)]
    pub key: String,
    pub level: Level,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub surface: String,
    #[serde(default)]
    pub sends: Vec<String>,
    #[serde(default)]
    pub set_by: String,
    #[serde(default)]
    pub in_effect: bool,
    #[serde(default)]
    pub maybe: bool,
    #[serde(default)]
    pub config: Config,
    #[serde(default)]
    pub docs: Option<String>,
}

/// An app or monitor and its findings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub installed: bool,
    pub status: Status,
    #[serde(default)]
    pub sends: Vec<String>,
    #[serde(default)]
    pub surfaces: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub kind: String,
}

/// Something the core looked at. `tool` is the surface it belongs to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceRecord {
    #[serde(default)]
    pub tool: String,
    pub source: Location,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// What `--since` compared against. `error` is set when the baseline was unusable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Since {
    #[serde(default)]
    pub scanned_at: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// One difference from the baseline (docs/architecture.md §4.2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    pub scope: String,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub notify: bool,
    #[serde(default)]
    pub text: String,
}

impl Change {
    /// A change with an unknown scope or kind is shown but never notifies.
    pub fn notifies(&self) -> bool {
        self.notify
            && KNOWN_SCOPES.contains(&self.scope.as_str())
            && KNOWN_CHANGE_KINDS.contains(&self.kind.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema: u64,
    #[serde(default)]
    pub generator: String,
    #[serde(default)]
    pub scanned_at: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub env_kind: String,
    #[serde(default)]
    pub complete: bool,
    pub status: Status,
    #[serde(default)]
    pub apps: Vec<Entry>,
    #[serde(default)]
    pub others: Vec<Entry>,
    #[serde(default)]
    pub sources: Vec<SourceRecord>,
    /// Present only when the scan ran with `--since`.
    #[serde(default)]
    pub since: Option<Since>,
    #[serde(default)]
    pub changes: Option<Vec<Change>>,
}

/// Why bytes aren't a report this build can show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not JSON, or not the shape of a report.
    BadJson(String),
    /// A schema major other than [`SCHEMA`].
    UnsupportedSchema(u64),
}

#[derive(Deserialize)]
struct SchemaOnly {
    schema: u64,
}

impl Report {
    /// Decodes a core report. The schema is checked first, so a report from a newer core is
    /// refused as such rather than as malformed. `alert` and `counts` are on the wire but unused.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let head: SchemaOnly =
            serde_json::from_slice(bytes).map_err(|e| DecodeError::BadJson(e.to_string()))?;
        if head.schema != SCHEMA {
            return Err(DecodeError::UnsupportedSchema(head.schema));
        }
        serde_json::from_slice(bytes).map_err(|e| DecodeError::BadJson(e.to_string()))
    }

    /// Apps then others, the order the badge counts in.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.apps.iter().chain(&self.others)
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries().find(|e| e.id == id)
    }

    /// The ids of the `changes` that notify, in core order.
    pub fn notifying_change_ids(&self) -> Vec<String> {
        self.changes
            .iter()
            .flatten()
            .filter(|c| c.notifies())
            .map(|c| c.id.clone())
            .collect()
    }

    /// Locations the scan couldn't fully read.
    pub fn problem_sources(&self) -> impl Iterator<Item = &SourceRecord> {
        self.sources
            .iter()
            .filter(|s| PROBLEM_STATES.contains(&s.state.as_str()))
    }
}
