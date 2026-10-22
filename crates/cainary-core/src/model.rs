//! The wire model (architecture.md §3). Slugs are part of the JSON format and never change.

use crate::harness::platform::{EnvKind, Os};
use crate::redact;
use serde::{Deserialize, Serialize};

macro_rules! slug_enum {
    ($name:ident { $($variant:ident => $slug:literal),+ $(,)? }) => {
        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The wire slug.
            pub fn slug(self) -> &'static str {
                match self {
                    $($name::$variant => $slug),+
                }
            }

            /// Inverse of [`Self::slug`].
            pub fn from_slug(s: &str) -> Option<$name> {
                match s {
                    $($slug => Some($name::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    ClaudeCode,
    ClaudeDesktop,
    Codex,
    Cursor,
    Copilot,
    Chatgpt,
    Device,
}

slug_enum!(Tool {
    ClaudeCode => "claude-code",
    ClaudeDesktop => "claude-desktop",
    Codex => "codex",
    Cursor => "cursor",
    Copilot => "copilot",
    Chatgpt => "chatgpt",
    Device => "device",
});

/// What the user sees as one app. A [`Tool`] is a product or surface; several surfaces can
/// share an app (Claude Code and Claude Desktop are both "Claude").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum App {
    Claude,
    Openai,
    Cursor,
    Copilot,
    Device,
}

slug_enum!(App {
    Claude => "claude",
    Openai => "openai",
    Cursor => "cursor",
    Copilot => "copilot",
    Device => "device",
});

impl App {
    /// Display name used by the text renderer.
    pub fn name(self) -> &'static str {
        match self {
            App::Claude => "Claude",
            App::Openai => "ChatGPT & Codex",
            App::Cursor => "Cursor",
            App::Copilot => "GitHub Copilot",
            App::Device => "This device",
        }
    }

    /// The surfaces that report under this app.
    pub fn tools(self) -> Vec<Tool> {
        Tool::ALL
            .iter()
            .copied()
            .filter(|t| t.app() == self)
            .collect()
    }
}

impl Tool {
    /// The app this surface reports under.
    pub fn app(self) -> App {
        match self {
            Tool::ClaudeCode | Tool::ClaudeDesktop => App::Claude,
            Tool::Codex | Tool::Chatgpt => App::Openai,
            Tool::Cursor => App::Cursor,
            Tool::Copilot => App::Copilot,
            Tool::Device => App::Device,
        }
    }

    /// Display name of the surface; the text renderer labels findings with it.
    pub fn name(self) -> &'static str {
        match self {
            Tool::ClaudeCode => "Claude Code",
            Tool::ClaudeDesktop => "Claude Desktop",
            Tool::Codex => "Codex",
            Tool::Cursor => "Cursor",
            Tool::Copilot => "GitHub Copilot",
            Tool::Chatgpt => "ChatGPT",
            Tool::Device => "This device",
        }
    }
}

/// How much of the user's activity is exposed. Ordered: a higher value is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    Clear,
    Usage,
    Work,
    Conversation,
}

slug_enum!(Exposure {
    Clear => "clear",
    Usage => "usage",
    Work => "work",
    Conversation => "conversation",
});

impl Exposure {
    pub fn name(self) -> &'static str {
        match self {
            Exposure::Clear => "Clear",
            Exposure::Usage => "Usage",
            Exposure::Work => "Work",
            Exposure::Conversation => "Conversation",
        }
    }
}

/// How worried to be about a finding or an entry (architecture.md §3.2). Ascending, so `max()` picks
/// the worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    NotInstalled,
    Ok,
    OptedOut,
    Low,
    Medium,
    High,
}

slug_enum!(Level {
    NotInstalled => "not-installed",
    Ok => "ok",
    OptedOut => "opted-out",
    Low => "low",
    Medium => "medium",
    High => "high",
});

impl Level {
    /// The upper-case text label.
    pub fn label(self) -> &'static str {
        match self {
            Level::NotInstalled => "NOT INSTALLED",
            Level::Ok => "OK",
            Level::OptedOut => "OPTED OUT",
            Level::Low => "LOW",
            Level::Medium => "MEDIUM",
            Level::High => "HIGH",
        }
    }

    /// The short phrase for the level, used where there is no finding title to show.
    pub fn short(self) -> &'static str {
        match self {
            Level::NotInstalled => "Not installed",
            Level::Ok => "Nothing sent",
            Level::OptedOut => "Standard telemetry is off",
            Level::Low => "Usage data is sent",
            Level::Medium => "Activity is sent",
            Level::High => "Conversations are sent",
        }
    }
}

/// What a finding exposes. Declaration order is the sort order of `Finding::signals`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signal {
    Prompts,
    Responses,
    Transcript,
    ToolDetails,
    FileContents,
    Traffic,
    DeviceAccess,
    Usage,
    Identity,
    Vendor,
    Policy,
}

slug_enum!(Signal {
    Prompts => "prompts",
    Responses => "responses",
    Transcript => "transcript",
    ToolDetails => "tool-details",
    FileContents => "file-contents",
    Traffic => "traffic",
    DeviceAccess => "device-access",
    Usage => "usage",
    Identity => "identity",
    Vendor => "vendor",
    Policy => "policy",
});

impl Signal {
    pub fn exposure(self) -> Exposure {
        match self {
            Signal::Prompts | Signal::Responses | Signal::Transcript => Exposure::Conversation,
            Signal::ToolDetails | Signal::FileContents | Signal::Traffic | Signal::DeviceAccess => {
                Exposure::Work
            }
            Signal::Usage | Signal::Identity | Signal::Vendor => Exposure::Usage,
            Signal::Policy => Exposure::Clear,
        }
    }
}

/// Who set a value. Declaration order is "most organizational first".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    Server,
    Mdm,
    System,
    OrgInstalled,
    Unattributed,
    Environment,
    User,
    VendorDefault,
}

slug_enum!(Origin {
    Server => "server",
    Mdm => "mdm",
    System => "system",
    OrgInstalled => "org-installed",
    Unattributed => "unattributed",
    Environment => "environment",
    User => "user",
    VendorDefault => "vendor-default",
});

impl Origin {
    pub fn is_org(self) -> bool {
        matches!(
            self,
            Origin::Server | Origin::Mdm | Origin::System | Origin::OrgInstalled
        )
    }
}

/// Which findings count toward alerts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum AlertMode {
    Org,
    #[default]
    OrgUnknown,
    Everything,
}

slug_enum!(AlertMode {
    Org => "org",
    OrgUnknown => "org-unknown",
    Everything => "everything",
});

impl AlertMode {
    /// Accepts the slugs and the Swift app's names (`relaxed`, `balanced`, `paranoid`).
    pub fn parse(s: &str) -> Option<AlertMode> {
        match s {
            "relaxed" => Some(AlertMode::Org),
            "balanced" => Some(AlertMode::OrgUnknown),
            "paranoid" => Some(AlertMode::Everything),
            _ => AlertMode::from_slug(s),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceState {
    Present,
    Absent,
    Error,
    Refused,
    /// A listing had more entries than the cap; only the first N were scanned.
    Capped,
}

slug_enum!(SourceState {
    Present => "present",
    Absent => "absent",
    Error => "error",
    Refused => "refused",
    Capped => "capped",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    File,
    Dir,
    Env,
    Command,
    Marker,
}

slug_enum!(SourceKind {
    File => "file",
    Dir => "dir",
    Env => "env",
    Command => "command",
    Marker => "marker",
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    /// Display form: `~/.claude/settings.json`, `env:OTEL_LOG_USER_PROMPTS`,
    /// `mdm:com.anthropic.claudecode`, `scutil --proxy`.
    pub path: String,
    pub origin: Origin,
    pub kind: SourceKind,
}

impl Source {
    pub fn new(path: impl Into<String>, origin: Origin, kind: SourceKind) -> Source {
        Source {
            path: path.into(),
            origin,
            kind,
        }
    }
}

/// Serializes in the schema-3 shape (architecture.md §3.6), not field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `<app>-<n>`, n = 1-based index after sorting. Set by `analysis::sort_and_number`.
    pub id: String,
    /// Stable identity across scans (architecture.md §4.1). Set by `analysis::sort_and_number`.
    pub key: String,
    pub app: App,
    pub tool: Tool,
    /// The monitoring agent a device finding belongs to; `None` for apps and plain device findings.
    pub agent: Option<String>,
    /// Sorted in `Signal` declaration order, de-duplicated; empty when `!in_effect`.
    pub signals: Vec<Signal>,
    /// Max over `signals`; `Clear` when none. Computed by [`Finding::finish`].
    pub exposure: Exposure,
    /// Plain words, no config keys.
    pub title: String,
    /// One or two sentences; may name keys.
    pub detail: String,
    pub source: Source,
    /// `key = value` lines, already redacted.
    pub evidence: Vec<String>,
    /// Official doc URL.
    pub reference: Option<String>,
    /// The rule rests on an unverified item; the UI says "may".
    pub best_effort: bool,
    /// False = shadowed by a higher tier, or a hook that never runs.
    pub in_effect: bool,
    /// Counts toward alerts at `Report::alert`. Computed by analysis.
    pub counts: bool,
}

impl Finding {
    /// Sort and de-duplicate `signals`, then set `exposure` from them.
    pub fn finish(&mut self) {
        self.signals.sort();
        self.signals.dedup();
        self.exposure = self
            .signals
            .iter()
            .map(|s| s.exposure())
            .max()
            .unwrap_or(Exposure::Clear);
    }

    /// The finding's level (architecture.md §3.2).
    pub fn level(&self) -> Level {
        if !self.in_effect {
            return if self.source.origin == Origin::VendorDefault {
                Level::OptedOut
            } else {
                Level::Ok
            };
        }
        match self.exposure {
            Exposure::Conversation => Level::High,
            Exposure::Work => Level::Medium,
            Exposure::Usage => Level::Low,
            Exposure::Clear => Level::Ok,
        }
    }
}

#[derive(Serialize)]
struct ConfigWire<'a> {
    path: &'a str,
    kind: SourceKind,
    evidence: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingWire<'a> {
    id: &'a str,
    key: &'a str,
    level: Level,
    title: &'a str,
    detail: &'a str,
    surface: Tool,
    sends: &'a [Signal],
    set_by: Origin,
    in_effect: bool,
    maybe: bool,
    counts: bool,
    config: ConfigWire<'a>,
    docs: Option<&'a str>,
}

impl Serialize for Finding {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        FindingWire {
            id: &self.id,
            key: &self.key,
            level: self.level(),
            title: &self.title,
            detail: &self.detail,
            surface: self.tool,
            sends: &self.signals,
            set_by: self.source.origin,
            in_effect: self.in_effect,
            maybe: self.best_effort,
            counts: self.counts,
            config: ConfigWire {
                path: &self.source.path,
                kind: self.source.kind,
                evidence: &self.evidence,
            },
            docs: self.reference.as_deref(),
        }
        .serialize(s)
    }
}

#[derive(Deserialize)]
struct ConfigIn {
    path: String,
    kind: SourceKind,
    evidence: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindingIn {
    id: String,
    key: String,
    title: String,
    detail: String,
    surface: Tool,
    sends: Vec<Signal>,
    set_by: Origin,
    in_effect: bool,
    maybe: bool,
    counts: bool,
    config: ConfigIn,
    docs: Option<String>,
}

/// Reads the schema-3 shape back (a `--since` baseline). `level` is recomputed and `agent` is
/// not on the wire.
impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Finding, D::Error> {
        let w = FindingIn::deserialize(d)?;
        let mut f = Finding {
            id: w.id,
            key: w.key,
            app: w.surface.app(),
            tool: w.surface,
            agent: None,
            signals: w.sends,
            exposure: Exposure::Clear,
            title: w.title,
            detail: w.detail,
            source: Source::new(w.config.path, w.set_by, w.config.kind),
            evidence: w.config.evidence,
            reference: w.docs,
            best_effort: w.maybe,
            in_effect: w.in_effect,
            counts: w.counts,
        };
        f.finish();
        Ok(f)
    }
}

/// Builds a [`Finding`] without a tool or id. It lives here so rule modules don't depend on the
/// harness; `ScanCtx::emit` calls [`FindingBuilder::build`].
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    agent: Option<String>,
    title: String,
    signals: Vec<Signal>,
    detail: String,
    source: Option<Source>,
    evidence: Vec<String>,
    reference: Option<String>,
    best_effort: bool,
    in_effect: bool,
}

impl FindingBuilder {
    pub fn new(title: impl Into<String>) -> FindingBuilder {
        FindingBuilder {
            agent: None,
            title: title.into(),
            signals: Vec::new(),
            detail: String::new(),
            source: None,
            evidence: Vec::new(),
            reference: None,
            best_effort: false,
            in_effect: true,
        }
    }

    /// Name the monitoring agent this device finding belongs to; findings with the same name
    /// share one monitor entry.
    pub fn agent(mut self, name: impl Into<String>) -> Self {
        self.agent = Some(name.into());
        self
    }

    pub fn signals(mut self, signals: &[Signal]) -> Self {
        self.signals = signals.to_vec();
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn source(mut self, source: Source) -> Self {
        self.source = Some(source);
        self
    }

    pub fn evidence<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.evidence = lines.into_iter().map(Into::into).collect();
        self
    }

    pub fn reference(mut self, url: impl Into<String>) -> Self {
        self.reference = Some(url.into());
        self
    }

    pub fn best_effort(mut self, b: bool) -> Self {
        self.best_effort = b;
        self
    }

    pub fn in_effect(mut self, b: bool) -> Self {
        self.in_effect = b;
        self
    }

    /// Fill in `tool`, clear the signals when `!in_effect`, run the final `redact::text` pass
    /// over title, detail and evidence, and finish. The id stays empty and `counts` false until
    /// `analysis::sort_and_number` and `analysis::analyze` run.
    ///
    /// # Panics
    /// If no source was set: every finding names where it came from.
    pub fn build(self, tool: Tool) -> Finding {
        let source = self.source.expect("FindingBuilder: source is required");
        let mut f = Finding {
            id: String::new(),
            key: String::new(),
            app: tool.app(),
            tool,
            agent: self.agent,
            signals: if self.in_effect {
                self.signals
            } else {
                Vec::new()
            },
            exposure: Exposure::Clear,
            title: redact::text(&self.title),
            detail: redact::text(&self.detail),
            source,
            evidence: self.evidence.iter().map(|e| redact::text(e)).collect(),
            reference: self.reference,
            best_effort: self.best_effort,
            in_effect: self.in_effect,
            counts: false,
        };
        f.finish();
        f
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedSource {
    pub tool: Tool,
    pub source: Source,
    pub state: SourceState,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    App,
    Monitor,
}

slug_enum!(EntryKind {
    App => "app",
    Monitor => "monitor",
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub level: Level,
    /// `Level::label`.
    pub label: String,
    /// One sentence.
    pub summary: String,
}

/// One row of the report: an AI app, or a monitoring agent on the device (architecture.md §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `claude`, `openai`, `cursor`, `copilot`, or the slugified monitor name.
    pub id: String,
    pub name: String,
    pub kind: EntryKind,
    pub installed: bool,
    pub status: Status,
    /// Union of the in-effect signals, in `Signal` order.
    pub sends: Vec<Signal>,
    /// Apps only: the surfaces that are installed or have findings.
    pub surfaces: Vec<Tool>,
    /// Level descending, then `analysis::sort_and_number` order.
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeScope {
    Entry,
    Finding,
    Source,
    Report,
}

slug_enum!(ChangeScope {
    Entry => "entry",
    Finding => "finding",
    Source => "source",
    Report => "report",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Added,
    Removed,
    Raised,
    Lowered,
    Changed,
}

slug_enum!(ChangeKind {
    Added => "added",
    Removed => "removed",
    Raised => "raised",
    Lowered => "lowered",
    Changed => "changed",
});

/// One difference between a baseline report and the current one (architecture.md §4.2, §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// `scope:entry:(key|path|-):kind:to`. Opaque and deterministic.
    pub id: String,
    pub scope: ChangeScope,
    /// `None` for the `report` scope.
    pub entry: Option<String>,
    /// The finding key, for `finding` changes.
    pub key: Option<String>,
    pub kind: ChangeKind,
    /// A level, source state or `complete`/`incomplete` slug; `None` where nothing is on that side.
    pub from: Option<String>,
    pub to: Option<String>,
    pub notify: bool,
    /// One redacted plain line.
    pub text: String,
}

/// What `--since` compared against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Since {
    /// The baseline's `scannedAt`; empty when the baseline could not be read.
    pub scanned_at: String,
    /// A short redacted reason when the baseline was unusable.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Major version of this JSON shape; currently 3.
    pub schema: u32,
    /// `cainary 0.1.0`.
    pub generator: String,
    /// RFC 3339, UTC.
    pub scanned_at: String,
    pub os: Os,
    pub env_kind: EnvKind,
    pub alert: AlertMode,
    /// No source is in the `Error` state.
    pub complete: bool,
    /// The worst entry, as a level and a sentence.
    pub status: Status,
    /// Always the four AI apps in `App` order.
    pub apps: Vec<Entry>,
    /// Monitoring on the device, level descending then name.
    pub others: Vec<Entry>,
    pub sources: Vec<ScannedSource>,
    /// Only with `--since`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Since>,
    /// Only with `--since`; empty when nothing changed or the baseline was unusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changes: Option<Vec<Change>>,
}

/// The current `Report::schema`.
pub const SCHEMA: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip<T>(all: &[T], slug: fn(T) -> &'static str, from: fn(&str) -> Option<T>)
    where
        T: Copy + PartialEq + std::fmt::Debug + Serialize + for<'de> Deserialize<'de>,
    {
        for &v in all {
            let s = slug(v);
            assert_eq!(from(s), Some(v), "{v:?}");
            assert_eq!(serde_json::to_value(v).unwrap(), json!(s), "{v:?}");
            assert_eq!(serde_json::from_value::<T>(json!(s)).unwrap(), v, "{v:?}");
        }
        assert_eq!(from("no-such-slug"), None);
    }

    #[test]
    fn enums_round_trip_through_slugs() {
        round_trip(Tool::ALL, Tool::slug, Tool::from_slug);
        round_trip(App::ALL, App::slug, App::from_slug);
        round_trip(Exposure::ALL, Exposure::slug, Exposure::from_slug);
        round_trip(Level::ALL, Level::slug, Level::from_slug);
        round_trip(EntryKind::ALL, EntryKind::slug, EntryKind::from_slug);
        round_trip(Signal::ALL, Signal::slug, Signal::from_slug);
        round_trip(Origin::ALL, Origin::slug, Origin::from_slug);
        round_trip(AlertMode::ALL, AlertMode::slug, AlertMode::from_slug);
        round_trip(SourceState::ALL, SourceState::slug, SourceState::from_slug);
        round_trip(SourceKind::ALL, SourceKind::slug, SourceKind::from_slug);
    }

    #[test]
    fn slugs_match_the_spec() {
        let tools: Vec<_> = Tool::ALL.iter().map(|t| t.slug()).collect();
        assert_eq!(
            tools,
            [
                "claude-code",
                "claude-desktop",
                "codex",
                "cursor",
                "copilot",
                "chatgpt",
                "device"
            ]
        );
        assert_eq!(Tool::ALL.len(), 7);
        let apps: Vec<_> = App::ALL.iter().map(|a| a.slug()).collect();
        assert_eq!(apps, ["claude", "openai", "cursor", "copilot", "device"]);
        assert_eq!(Tool::ClaudeDesktop.app(), App::Claude);
        assert_eq!(Tool::Chatgpt.app(), App::Openai);
        assert_eq!(App::Openai.tools(), [Tool::Codex, Tool::Chatgpt]);
    }

    #[test]
    fn all_lists_are_in_declaration_order() {
        assert!(Tool::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(App::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(Exposure::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(Signal::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(Origin::ALL.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn signal_exposure_table() {
        use Exposure::*;
        use Signal::*;
        let table = [
            (Prompts, Conversation),
            (Responses, Conversation),
            (Transcript, Conversation),
            (ToolDetails, Work),
            (FileContents, Work),
            (DeviceAccess, Work),
            (Traffic, Work),
            (Signal::Usage, Exposure::Usage),
            (Identity, Exposure::Usage),
            (Vendor, Exposure::Usage),
            (Policy, Clear),
        ];
        assert_eq!(table.len(), Signal::ALL.len());
        for (s, e) in table {
            assert_eq!(s.exposure(), e, "{s:?}");
        }
    }

    #[test]
    fn origin_is_org() {
        let org: Vec<_> = Origin::ALL
            .iter()
            .filter(|o| o.is_org())
            .map(|o| o.slug())
            .collect();
        assert_eq!(org, ["server", "mdm", "system", "org-installed"]);
    }

    #[test]
    fn alert_mode_parse_and_default() {
        assert_eq!(AlertMode::parse("paranoid"), Some(AlertMode::Everything));
        assert_eq!(AlertMode::parse("balanced"), Some(AlertMode::OrgUnknown));
        assert_eq!(AlertMode::parse("relaxed"), Some(AlertMode::Org));
        assert_eq!(AlertMode::parse("org-unknown"), Some(AlertMode::OrgUnknown));
        assert_eq!(AlertMode::parse("loud"), None);
        assert_eq!(AlertMode::default(), AlertMode::OrgUnknown);
    }

    fn finding(signals: &[Signal]) -> Finding {
        Finding {
            id: String::new(),
            key: String::new(),
            app: App::Openai,
            tool: Tool::Codex,
            agent: None,
            signals: signals.to_vec(),
            exposure: Exposure::Clear,
            title: "t".into(),
            detail: String::new(),
            source: Source::new("~/x", Origin::User, SourceKind::File),
            evidence: vec![],
            reference: None,
            best_effort: false,
            in_effect: true,
            counts: false,
        }
    }

    #[test]
    fn finish_sorts_dedups_and_sets_exposure() {
        let mut f = finding(&[Signal::Usage, Signal::Prompts, Signal::Usage]);
        f.finish();
        assert_eq!(f.signals, [Signal::Prompts, Signal::Usage]);
        assert_eq!(f.exposure, Exposure::Conversation);

        let mut none = finding(&[]);
        none.finish();
        assert_eq!(none.exposure, Exposure::Clear);

        let mut policy = finding(&[Signal::Policy]);
        policy.finish();
        assert_eq!(policy.exposure, Exposure::Clear);
    }

    #[test]
    fn finding_serializes_in_schema_3_shape() {
        let mut f = finding(&[Signal::ToolDetails]);
        f.evidence = vec!["k = v".into()];
        f.finish();
        let v = serde_json::to_value(f).unwrap();
        assert_eq!(
            v,
            json!({
                "id": "", "key": "", "level": "medium", "title": "t", "detail": "",
                "surface": "codex", "sends": ["tool-details"], "setBy": "user",
                "inEffect": true, "maybe": false, "counts": false,
                "config": {"path": "~/x", "kind": "file", "evidence": ["k = v"]},
                "docs": null
            })
        );
    }

    #[test]
    fn level_order_and_labels() {
        assert!(Level::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(Level::OptedOut > Level::Ok && Level::OptedOut < Level::Low);
        assert_eq!(Level::NotInstalled.label(), "NOT INSTALLED");
        assert_eq!(Level::OptedOut.slug(), "opted-out");
        assert_eq!(Level::High.short(), "Conversations are sent");
    }

    #[test]
    fn finding_level_mapping() {
        for (signals, want) in [
            (vec![Signal::Prompts], Level::High),
            (vec![Signal::Traffic], Level::Medium),
            (vec![Signal::Usage], Level::Low),
            (vec![Signal::Vendor], Level::Low),
            (vec![Signal::Identity], Level::Low),
            (vec![Signal::Policy], Level::Ok),
            (vec![], Level::Ok),
        ] {
            let mut f = finding(&signals);
            f.finish();
            assert_eq!(f.level(), want, "{signals:?}");
        }
        // Not in effect: an opt-out is `opted-out`, anything else is `ok`.
        let mut f = finding(&[]);
        f.in_effect = false;
        assert_eq!(f.level(), Level::Ok);
        f.source.origin = Origin::VendorDefault;
        assert_eq!(f.level(), Level::OptedOut);
        // The vendor default itself, still in effect, is low.
        f.in_effect = true;
        f.signals = vec![Signal::Vendor];
        f.finish();
        assert_eq!(f.level(), Level::Low);
    }

    #[test]
    fn finding_and_change_round_trip() {
        let mut f = finding(&[Signal::ToolDetails]);
        f.key = "3f9c2a17d04b8e61".into();
        f.finish();
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["key"], "3f9c2a17d04b8e61");
        let back: Finding = serde_json::from_value(v).unwrap();
        assert_eq!(back, f);

        let c = Change {
            id: "entry:claude:-:raised:high".into(),
            scope: ChangeScope::Entry,
            entry: Some("claude".into()),
            key: None,
            kind: ChangeKind::Raised,
            from: Some("low".into()),
            to: Some("high".into()),
            notify: true,
            text: "t".into(),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["scope"], "entry");
        assert_eq!(v["kind"], "raised");
        assert!(v["key"].is_null());
        assert_eq!(serde_json::from_value::<Change>(v).unwrap(), c);
        round_trip(ChangeScope::ALL, ChangeScope::slug, ChangeScope::from_slug);
        round_trip(ChangeKind::ALL, ChangeKind::slug, ChangeKind::from_slug);
    }
}
