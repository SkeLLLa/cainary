//! Pure decoder and bounded view model for `cainary-otel-debug` JSON-lines v1.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::settings::{COLLECTOR_PRESETS, CollectorPatternKind, CollectorSettings};

pub const MAX_LINE: usize = 4 << 20;
pub const MAX_RETAINED: usize = 16 << 20;
pub const MAX_BATCHES: usize = 50;
pub const MAX_ALERTS: usize = 200;
const ALERT_INTERVAL: Duration = Duration::from_secs(60);
const CONFIG_LIMIT: usize = 1 << 20;

/// The object written as the first stdin line when the child starts.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StdinConfig<'a> {
    v: u8,
    red_flags: Vec<RedFlagInput<'a>>,
    presets: HashMap<&'static str, bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RedFlagInput<'a> {
    name: &'a str,
    kind: &'static str,
    pattern: &'a str,
    case_sensitive: bool,
}

/// Only non-sensitive flags are passed on argv. Custom patterns go in config stdin.
pub fn child_args(settings: &CollectorSettings) -> Result<Vec<String>, String> {
    if let Some(problem) = settings.problem() {
        return Err(problem.message);
    }
    let port = if settings.tls {
        settings.tls_port
    } else {
        settings.port
    };
    let mut args = vec!["--json".to_owned(), "--config-stdin".to_owned()];
    if settings.tls {
        args.push("--tls".into());
        for host in settings.valid_tls_hosts() {
            args.push("--tls-host".into());
            args.push(host);
        }
    }
    args.extend(["--port".into(), port.to_string()]);
    if settings.log_to_file {
        let path = if settings.log_path.trim().is_empty() {
            CollectorSettings::suggested_log_path()
        } else {
            settings.log_path.trim().to_owned()
        };
        if path.is_empty() {
            return Err("choose a path for the collector log file".into());
        }
        args.push("--log-file".into());
        args.push(path);
    }
    Ok(args)
}

/// Encodes the private settings separately from argv and keeps stdin open after this line.
pub fn config_stdin(settings: &CollectorSettings) -> Result<Vec<u8>, String> {
    if let Some(problem) = settings.problem() {
        return Err(problem.message);
    }
    let selected = settings
        .presets
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    let config = StdinConfig {
        v: 1,
        red_flags: settings
            .valid_patterns()
            .into_iter()
            .map(|pattern| RedFlagInput {
                name: &pattern.name,
                kind: match pattern.kind {
                    CollectorPatternKind::Text => "text",
                    CollectorPatternKind::Regex => "regex",
                },
                pattern: &pattern.pattern,
                case_sensitive: pattern.case_sensitive,
            })
            .collect(),
        presets: COLLECTOR_PRESETS
            .iter()
            .copied()
            .map(|name| (name, selected.contains(name)))
            .collect(),
    };
    let mut bytes =
        serde_json::to_vec(&config).map_err(|_| "couldn't encode collector settings")?;
    if bytes.len() + 1 > CONFIG_LIMIT {
        return Err("collector settings are too large".into());
    }
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
    UpdateRequired,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    Hello(Hello),
    Batch(Batch),
    Alert(Alert),
    Error(ErrorLine),
    Unknown,
}

pub fn decode_line(line: &str) -> Result<Line, DecodeError> {
    if line.len() > MAX_LINE {
        return Err(DecodeError::Malformed);
    }
    let value: Value = serde_json::from_str(line).map_err(|_| DecodeError::Malformed)?;
    let version = value
        .get("v")
        .and_then(Value::as_u64)
        .ok_or(DecodeError::Malformed)?;
    if version != 1 {
        return Err(DecodeError::UpdateRequired);
    }
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or(DecodeError::Malformed)?
        .to_owned();
    match kind.as_str() {
        "hello" => serde_json::from_value(value)
            .map(Line::Hello)
            .map_err(|_| DecodeError::Malformed),
        "batch" => serde_json::from_value(value)
            .map(Line::Batch)
            .map_err(|_| DecodeError::Malformed),
        "alert" => serde_json::from_value(value)
            .map(Line::Alert)
            .map_err(|_| DecodeError::Malformed),
        "error" => serde_json::from_value(value)
            .map(Line::Error)
            .map_err(|_| DecodeError::Malformed),
        _ => Ok(Line::Unknown),
    }
}

/// A finite set of one-shot helper calls exposed by the tray.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustAction {
    Status,
    PreviewClaude,
    ApplyClaude,
    UndoClaude,
    PrepareCodex,
    UndoCodex,
}

impl TrustAction {
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Status => &["--trust-status", "--json"],
            Self::PreviewClaude => &["--trust", "claude-code", "--dry-run", "--json"],
            Self::ApplyClaude => &["--trust", "claude-code", "--json"],
            Self::UndoClaude => &["--trust", "claude-code", "--undo", "--json"],
            Self::PrepareCodex => &["--trust", "codex", "--json"],
            Self::UndoCodex => &["--trust", "codex", "--undo", "--json"],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrustReply {
    Status(TrustStatusLine),
    Trust(TrustResultLine),
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustStatusLine {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub claude_code: ClaudeTrustStatus,
    #[serde(default)]
    pub codex: CodexTrustStatus,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default)]
    pub ca_exists: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeTrustStatus {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub settings_path: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexTrustStatus {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub bundle_path: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustResultLine {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub settings_path: Option<String>,
    #[serde(default)]
    pub backup_path: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub bundle_path: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

/// Decodes the helper's one-line v1 trust contract. Unknown fields are ignored by serde.
pub fn decode_trust_output(stdout: &[u8]) -> Result<TrustReply, String> {
    if stdout.len() > (64 << 10) {
        return Err("collector trust response is too large".into());
    }
    let value: Value = serde_json::from_slice(stdout)
        .map_err(|_| "collector trust response was unreadable".to_owned())?;
    if value.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("collector trust response needs an update".into());
    }
    match value.get("type").and_then(Value::as_str) {
        Some("trust-status") => serde_json::from_value(value)
            .map(TrustReply::Status)
            .map_err(|_| "collector trust status was incomplete".into()),
        Some("trust") => serde_json::from_value(value)
            .map(TrustReply::Trust)
            .map_err(|_| "collector trust response was incomplete".into()),
        _ => Err("collector trust response had an unknown type".into()),
    }
}

/// Copyable, no-write command using the same fish/bash quoting as the helper's setup output.
pub fn claude_no_write_command(ca_path: &str) -> Option<String> {
    if ca_path.is_empty() {
        return None;
    }
    Some(format!(
        "env NODE_EXTRA_CA_CERTS={} claude",
        shell_quote(ca_path)
    ))
}

fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte));
    if plain {
        return word.to_owned();
    }
    if word.chars().any(char::is_control) {
        return "'<edit: path contains control characters>'".into();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub generator: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub show_values: bool,
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default)]
    pub red_flags: Vec<RedFlagInfo>,
    #[serde(default)]
    pub tls: Option<TlsInfo>,
    #[serde(default)]
    pub setup: Setup,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub ca: TlsCaInfo,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsCaInfo {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedFlagInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub preset: bool,
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    #[serde(default)]
    pub claude_code: Vec<String>,
    #[serde(default)]
    pub codex: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub takeover: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub signal: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub service: ServiceInfo,
    #[serde(default)]
    pub catalog: String,
    #[serde(default)]
    pub records: u64,
    #[serde(default)]
    pub not_in_catalog: u64,
    #[serde(default)]
    pub summary: BatchSummary,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub resources_omitted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSummary {
    #[serde(default)]
    pub identity: Vec<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    #[serde(default)]
    pub records: Vec<SummaryRecord>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryRecord {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub count: u64,
    #[serde(default)]
    pub known: bool,
    #[serde(default)]
    pub what: String,
    #[serde(default)]
    pub attrs: Vec<SummaryAttribute>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryAttribute {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub flag: Option<String>,
    #[serde(default)]
    pub known: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub preset: bool,
    #[serde(default)]
    pub signal: String,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub attribute: String,
    #[serde(default, rename = "where")]
    pub location: String,
    #[serde(default)]
    pub count: u64,
    #[serde(default, rename = "match")]
    pub matched: String,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLine {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub dropped: Option<u64>,
    /// Stable machine-readable reason; absent on lines from older collectors.
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    Off,
    Starting,
    Listening,
    Stopped,
    Failed,
}

#[derive(Clone, Debug)]
struct StoredBatch {
    batch: Batch,
    line_bytes: usize,
    raw_records: String,
}

impl StoredBatch {
    fn new(batch: Batch, line_bytes: usize) -> Self {
        let raw_records = serde_json::to_string_pretty(&batch.resources).unwrap_or_default();
        Self {
            batch,
            line_bytes,
            raw_records,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredAlert {
    alert: Alert,
    line_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Model {
    pub state: State,
    pub message: String,
    pub hello: Option<Hello>,
    pub stderr_tail: String,
    batches: VecDeque<StoredBatch>,
    alerts: VecDeque<StoredAlert>,
    errors: VecDeque<ErrorLine>,
    /// The first `error` seen before `hello`: what the collector said about why it couldn't start.
    startup_error: Option<ErrorLine>,
    failure: Option<Failure>,
    retained_bytes: usize,
    notified: HashMap<String, Instant>,
}

impl Model {
    pub fn starting(&mut self) {
        *self = Self {
            state: State::Starting,
            ..Self::default()
        };
        self.message = "Starting collector…".into();
    }

    pub fn stopped(&mut self, reason: impl Into<String>) {
        self.state = State::Stopped;
        self.message = reason.into();
    }

    /// Clears the retained feed without changing the collector's state or error history.
    pub fn clear(&mut self) {
        self.batches = VecDeque::new();
        self.alerts = VecDeque::new();
        self.retained_bytes = 0;
    }

    /// Records the child's exit. A startup error reported on stdout beats the first stderr line,
    /// and either beats the bare exit status.
    pub fn exited(&mut self, code: Option<i32>, stderr_tail: &str) {
        let startup = self.startup_error.clone();
        let first_stderr = stderr_tail
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or_default();
        let (failure_code, port, text) = match startup {
            Some(error) => {
                let text = error
                    .message
                    .clone()
                    .filter(|message| !message.is_empty())
                    .unwrap_or_else(|| "Collector reported an error".into());
                (error.code, error.port, text)
            }
            None if !first_stderr.is_empty() => (None, None, first_stderr.to_owned()),
            None => match code.filter(|code| *code != 0) {
                Some(code) => (None, None, format!("collector exited with status {code}")),
                None => (None, None, String::new()),
            },
        };
        self.set_stderr_tail(stderr_tail);
        if matches!(self.state, State::Starting | State::Listening) {
            if text.is_empty() {
                self.stopped("Stopped");
            } else {
                self.stopped(format!("Stopped: {text}"));
                self.failure = Some(Failure {
                    code: failure_code,
                    message: text,
                    port,
                });
            }
        }
    }

    pub fn failed(&mut self, reason: impl Into<String>) {
        self.state = State::Failed;
        self.message = reason.into();
    }

    /// The collector can't start with these settings; `code` is a `Problem` code, for the UI.
    pub fn problem(&mut self, code: &str, message: impl Into<String>) {
        let message = message.into();
        self.failed(message.clone());
        self.failure = Some(Failure {
            code: Some(code.to_owned()),
            message,
            port: None,
        });
    }

    pub fn set_stderr_tail(&mut self, tail: impl Into<String>) {
        let mut tail = tail.into();
        const LIMIT: usize = 8 << 10;
        if tail.len() > LIMIT {
            let mut start = tail.len() - LIMIT;
            while !tail.is_char_boundary(start) {
                start += 1;
            }
            tail.drain(..start);
        }
        self.stderr_tail = tail;
    }

    /// Adds one complete line. Returns true when the child must stop.
    pub fn accept(&mut self, line: String) -> (bool, Option<Alert>) {
        if line.len() > MAX_LINE {
            self.failed("Stopped: output too large");
            return (true, None);
        }
        match decode_line(&line) {
            Err(DecodeError::UpdateRequired) => {
                self.stopped("Update cAInary");
                (true, None)
            }
            Err(DecodeError::Malformed) => {
                self.message = "Ignored an unreadable collector line".into();
                (false, None)
            }
            Ok(Line::Hello(hello)) => {
                self.hello = Some(hello);
                self.state = State::Listening;
                self.message.clear();
                (false, None)
            }
            Ok(Line::Batch(batch)) => {
                self.retained_bytes += line.len();
                self.batches.push_back(StoredBatch::new(batch, line.len()));
                self.trim_retained();
                (false, None)
            }
            Ok(Line::Alert(alert)) => {
                self.retained_bytes += line.len();
                self.alerts.push_back(StoredAlert {
                    alert: alert.clone(),
                    line_bytes: line.len(),
                });
                self.trim_retained();
                (false, Some(alert))
            }
            Ok(Line::Error(error)) => {
                if self.hello.is_none() && self.startup_error.is_none() {
                    self.startup_error = Some(error.clone());
                }
                self.errors.push_back(error);
                while self.errors.len() > 20 {
                    self.errors.pop_front();
                }
                (false, None)
            }
            Ok(Line::Unknown) => (false, None),
        }
    }

    fn trim_retained(&mut self) {
        while self.batches.len() > MAX_BATCHES {
            self.drop_oldest_batch();
        }
        while self.alerts.len() > MAX_ALERTS {
            self.drop_oldest_alert();
        }
        while self.retained_bytes > MAX_RETAINED {
            if self.batches.len() > 1 {
                self.drop_oldest_batch();
            } else if !self.alerts.is_empty() {
                self.drop_oldest_alert();
            } else if !self.batches.is_empty() {
                self.drop_oldest_batch();
            } else {
                break;
            }
        }
    }

    fn drop_oldest_batch(&mut self) {
        if let Some(batch) = self.batches.pop_front() {
            self.retained_bytes = self.retained_bytes.saturating_sub(batch.line_bytes);
        }
    }

    fn drop_oldest_alert(&mut self) {
        if let Some(alert) = self.alerts.pop_front() {
            self.retained_bytes = self.retained_bytes.saturating_sub(alert.line_bytes);
        }
    }

    /// One desktop notification per pattern in each rolling 60-second window.
    pub fn alert_notification(
        &mut self,
        alert: &Alert,
        enabled: bool,
        now: Instant,
    ) -> Option<(String, String)> {
        if !enabled || alert.pattern.is_empty() {
            return None;
        }
        if self
            .notified
            .get(&alert.pattern)
            .is_some_and(|last| now.duration_since(*last) < ALERT_INTERVAL)
        {
            return None;
        }
        self.notified.insert(alert.pattern.clone(), now);
        let event = alert
            .event
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| alert.events.first().map(String::as_str))
            .unwrap_or("OTel export");
        let body = if alert.matched.is_empty() {
            format!("{} · {}", event, alert.attribute)
        } else {
            format!("{} · {} ({})", event, alert.attribute, alert.matched)
        };
        Some((format!("Red flag: {}", alert.pattern), body))
    }

    pub fn view(&self) -> View {
        let hello = self.hello.as_ref();
        let endpoint = hello.map(|h| h.endpoint.clone()).unwrap_or_default();
        let tls = hello.and_then(|hello| hello.tls.as_ref());
        let batches = self
            .batches
            .iter()
            .rev()
            .map(BatchView::from)
            .collect::<Vec<_>>();
        let alerts = self
            .alerts
            .iter()
            .rev()
            .map(AlertView::from)
            .collect::<Vec<_>>();
        let errors = self.errors.iter().rev().map(ErrorView::from).collect();
        let rows = build_feed_rows(&batches, &alerts, format_local_clock);
        let flag_groups = build_flag_groups(&alerts, format_local_clock);
        View {
            state: match self.state {
                State::Off => "off",
                State::Starting => "starting",
                State::Listening => "listening",
                State::Stopped => "stopped",
                State::Failed => "failed",
            }
            .into(),
            message: self.message.clone(),
            endpoint,
            mode: hello.map(|hello| hello.mode.clone()).unwrap_or_default(),
            tls_hosts: tls.map(|info| info.hosts.clone()).unwrap_or_default(),
            ca_path: tls.map(|info| info.ca.path.clone()).unwrap_or_default(),
            ca_sha256: tls.map(|info| info.ca.sha256.clone()).unwrap_or_default(),
            claude_code: hello
                .map(|h| h.setup.claude_code.clone())
                .unwrap_or_default(),
            codex: hello.map(|h| h.setup.codex.clone()).unwrap_or_default(),
            notes: hello.map(|h| h.setup.notes.clone()).unwrap_or_default(),
            takeover: hello
                .map(|hello| hello.setup.takeover.clone())
                .unwrap_or_default(),
            stderr_tail: self.stderr_tail.clone(),
            batches,
            alerts,
            rows,
            flag_groups,
            errors,
            retained_bytes: self.retained_bytes,
            failure: self.failure.clone(),
        }
    }
}

/// Why the collector stopped on its own. `code` and `port` are present only when the collector
/// reported them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    pub code: Option<String>,
    pub message: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub state: String,
    pub message: String,
    pub endpoint: String,
    pub mode: String,
    pub tls_hosts: Vec<String>,
    pub ca_path: String,
    pub ca_sha256: String,
    pub claude_code: Vec<String>,
    pub codex: Vec<String>,
    pub notes: Vec<String>,
    pub takeover: Vec<String>,
    pub stderr_tail: String,
    pub batches: Vec<BatchView>,
    pub alerts: Vec<AlertView>,
    pub rows: Vec<FeedRow>,
    pub flag_groups: Vec<FlagGroup>,
    pub errors: Vec<ErrorView>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchView {
    pub id: u64,
    pub timestamp: String,
    pub signal: String,
    pub endpoint_path: String,
    pub catalog: String,
    pub vendor: String,
    pub service: String,
    pub bytes: u64,
    pub records: u64,
    pub not_in_catalog: u64,
    pub identity: Vec<String>,
    pub resource: Vec<String>,
    pub summary: Vec<SummaryRecordView>,
    pub raw_records: String,
    pub resources_omitted: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryRecordView {
    pub name: String,
    pub kind: String,
    pub count: u64,
    pub known: bool,
    pub what: String,
    pub attrs: Vec<SummaryAttributeView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryAttributeView {
    pub key: String,
    pub group: String,
    pub flag: String,
    pub known: bool,
}

impl From<&StoredBatch> for BatchView {
    fn from(stored: &StoredBatch) -> Self {
        let batch = &stored.batch;
        Self {
            id: batch.seq,
            timestamp: batch.ts.clone(),
            signal: batch.signal.clone(),
            endpoint_path: batch.path.clone(),
            catalog: batch.catalog.clone(),
            vendor: batch.vendor.clone(),
            service: if batch.service.version.is_empty() {
                batch.service.name.clone()
            } else {
                format!("{} {}", batch.service.name, batch.service.version)
            },
            bytes: batch.bytes,
            records: batch.records,
            not_in_catalog: batch.not_in_catalog,
            identity: batch.summary.identity.clone(),
            resource: batch.summary.resource.clone(),
            summary: batch
                .summary
                .records
                .iter()
                .map(SummaryRecordView::from)
                .collect(),
            raw_records: stored.raw_records.clone(),
            resources_omitted: batch.resources_omitted,
        }
    }
}

impl From<&SummaryRecord> for SummaryRecordView {
    fn from(record: &SummaryRecord) -> Self {
        Self {
            name: record.name.clone(),
            kind: record.kind.clone(),
            count: record.count,
            known: record.known,
            what: record.what.clone(),
            attrs: record
                .attrs
                .iter()
                .map(SummaryAttributeView::from)
                .collect(),
        }
    }
}

impl From<&SummaryAttribute> for SummaryAttributeView {
    fn from(attribute: &SummaryAttribute) -> Self {
        Self {
            key: attribute.key.clone(),
            group: attribute.group.clone().unwrap_or_default(),
            flag: attribute.flag.clone().unwrap_or_default(),
            known: attribute.known,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertView {
    pub seq: u64,
    pub timestamp: String,
    pub pattern: String,
    pub preset: bool,
    pub signal: String,
    pub event: String,
    pub attribute: String,
    pub location: String,
    pub count: u64,
    pub matched: String,
}

impl From<&StoredAlert> for AlertView {
    fn from(stored: &StoredAlert) -> Self {
        let alert = &stored.alert;
        Self {
            seq: alert.seq,
            timestamp: alert.ts.clone(),
            pattern: alert.pattern.clone(),
            preset: alert.preset,
            signal: alert.signal.clone(),
            event: alert
                .event
                .clone()
                .or_else(|| alert.events.first().cloned())
                .unwrap_or_default(),
            attribute: alert.attribute.clone(),
            location: alert.location.clone(),
            count: alert.count,
            matched: alert.matched.clone(),
        }
    }
}

/// One stable, presentation-ready row in the collector feed.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedRow {
    pub key: String,
    pub timestamp: String,
    pub time: String,
    pub size: String,
    pub source: String,
    pub signal: String,
    pub records: u64,
    pub flags: Vec<FeedFlag>,
    pub flag_details: Vec<AlertView>,
    pub not_in_catalog: u64,
    pub is_alert: bool,
    pub haystack: String,
    pub batch_id: Option<u64>,
    pub alert: Option<AlertView>,
}

/// The compact flag label shown in a feed row. Details stay on `FeedRow::flag_details`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedFlag {
    pub pattern: String,
    pub count: u64,
}

/// Red Flags tab groups, in order of the most recent alert for each pattern.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlagGroup {
    pub pattern: String,
    pub preset: bool,
    pub hits: u64,
    pub total: u64,
    pub last: String,
    pub last_time: String,
    pub events: Vec<String>,
    pub attributes: Vec<String>,
    pub signals: Vec<String>,
    pub matched: String,
}

/// Inputs used by the pure feed filter. `signals` contains the enabled signal names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedFilter {
    pub signals: HashSet<String>,
    pub flagged_only: bool,
    pub uncataloged_only: bool,
    pub search_text: String,
    pub pattern: String,
}

/// Returns whether a precomputed row passes the feed's user-controlled filters.
pub fn matches(row: &FeedRow, filter: &FeedFilter) -> bool {
    if !filter.signals.contains(&row.signal) {
        return false;
    }
    if filter.flagged_only && row.flags.is_empty() {
        return false;
    }
    if !filter.pattern.is_empty() && !row.flags.iter().any(|flag| flag.pattern == filter.pattern) {
        return false;
    }
    if filter.uncataloged_only && row.not_in_catalog == 0 {
        return false;
    }
    let search = filter.search_text.trim().to_lowercase();
    search.is_empty() || row.haystack.contains(&search)
}

fn build_feed_rows(
    batches: &[BatchView],
    alerts: &[AlertView],
    format_time: impl Fn(&str) -> String,
) -> Vec<FeedRow> {
    let mut rows = batches
        .iter()
        .map(|batch| FeedRow {
            key: format!("batch:{}", batch.id),
            timestamp: batch.timestamp.clone(),
            time: format_time(&batch.timestamp),
            size: format_size(batch.bytes),
            source: batch_source(batch),
            signal: batch.signal.clone(),
            records: batch.records,
            flags: Vec::new(),
            flag_details: Vec::new(),
            not_in_catalog: batch.not_in_catalog,
            is_alert: false,
            haystack: String::new(),
            batch_id: Some(batch.id),
            alert: None,
        })
        .collect::<Vec<_>>();
    let batch_rows = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.batch_id.map(|id| (id, index)))
        .collect::<HashMap<_, _>>();

    for alert in alerts {
        if let Some(batch_index) = linked_batch_index(alert, batches)
            && let Some(row_index) = batch_rows.get(&batches[batch_index].id)
        {
            rows[*row_index].flag_details.push(alert.clone());
            continue;
        }

        rows.push(FeedRow {
            key: alert_key(alert),
            timestamp: alert.timestamp.clone(),
            time: format_time(&alert.timestamp),
            size: String::new(),
            source: if !alert.event.is_empty() {
                alert.event.clone()
            } else if !alert.location.is_empty() {
                alert.location.clone()
            } else {
                "?".into()
            },
            signal: alert.signal.clone(),
            records: 0,
            flags: Vec::new(),
            flag_details: vec![alert.clone()],
            not_in_catalog: 0,
            is_alert: true,
            haystack: String::new(),
            batch_id: None,
            alert: Some(alert.clone()),
        });
    }

    for row in &mut rows {
        row.flags = summarize_flags(&row.flag_details);
        let batch = row
            .batch_id
            .and_then(|id| batches.iter().find(|batch| batch.id == id));
        row.haystack = row_haystack(batch, &row.flag_details);
    }
    rows.sort_by(compare_rows_newest_first);
    rows
}

fn linked_batch_index(alert: &AlertView, batches: &[BatchView]) -> Option<usize> {
    const LINK_WINDOW_NANOS: i128 = 5_000_000_000;
    let alert_time = timestamp_nanos(&alert.timestamp)?;
    let mut nearest = None;
    for (index, batch) in batches.iter().enumerate() {
        if batch.signal != alert.signal {
            continue;
        }
        let Some(batch_time) = timestamp_nanos(&batch.timestamp) else {
            continue;
        };
        let elapsed = alert_time - batch_time;
        let closer = match nearest {
            Some((nearest_time, _)) => batch_time > nearest_time,
            None => true,
        };
        if (0..=LINK_WINDOW_NANOS).contains(&elapsed) && closer {
            nearest = Some((batch_time, index));
        }
    }
    nearest.map(|(_, index)| index)
}

fn compare_rows_newest_first(left: &FeedRow, right: &FeedRow) -> Ordering {
    match (
        timestamp_nanos(&left.timestamp),
        timestamp_nanos(&right.timestamp),
    ) {
        (Some(left), Some(right)) => right.cmp(&left),
        _ => right.timestamp.cmp(&left.timestamp),
    }
}

fn timestamp_nanos(timestamp: &str) -> Option<i128> {
    let (seconds, nanos) = parse_timestamp(timestamp)?;
    Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
}

fn alert_key(alert: &AlertView) -> String {
    if alert.seq != 0 {
        format!("alert:{}", alert.seq)
    } else {
        format!(
            "alert:{}:{}:{}:{}:{}",
            alert.timestamp, alert.signal, alert.pattern, alert.event, alert.attribute
        )
    }
}

fn batch_source(batch: &BatchView) -> String {
    if !batch.catalog.is_empty() {
        return batch.catalog.clone();
    }
    let source = [batch.vendor.as_str(), batch.service.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if source.is_empty() {
        "?".into()
    } else {
        source
    }
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 {
        String::new()
    } else if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{} KB", (bytes as f64 / 1024.0).round() as u64)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_local_clock(timestamp: &str) -> String {
    let Some((seconds, _)) = parse_timestamp(timestamp) else {
        return timestamp.to_owned();
    };
    let seconds = seconds as libc::time_t;
    let mut local = MaybeUninit::<libc::tm>::uninit();
    let result = unsafe { libc::localtime_r(&seconds, local.as_mut_ptr()) };
    if result.is_null() {
        return timestamp.to_owned();
    }
    let local = unsafe { local.assume_init() };
    format_clock_parts(local.tm_hour, local.tm_min, local.tm_sec)
}

#[cfg(test)]
fn format_clock_with_offset(timestamp: &str, offset_seconds: i32) -> String {
    let Some((seconds, _)) = parse_timestamp(timestamp) else {
        return timestamp.to_owned();
    };
    let seconds = (seconds + i64::from(offset_seconds)).rem_euclid(86_400);
    format_clock_parts(
        (seconds / 3_600) as i32,
        ((seconds / 60) % 60) as i32,
        (seconds % 60) as i32,
    )
}

fn format_clock_parts(hour: i32, minute: i32, second: i32) -> String {
    format!("{hour:02}:{minute:02}:{second:02}")
}

fn parse_timestamp(timestamp: &str) -> Option<(i64, u32)> {
    let bytes = timestamp.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }

    let year = i64::from(parse_digits(bytes, 0, 4)?);
    let month = parse_digits(bytes, 5, 2)?;
    let day = parse_digits(bytes, 8, 2)?;
    let hour = parse_digits(bytes, 11, 2)?;
    let minute = parse_digits(bytes, 14, 2)?;
    let second = parse_digits(bytes, 17, 2)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut index = 19;
    let mut nanos = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return None;
        }
        let precision = (index - start).min(9);
        let fraction = parse_digits(bytes, start, precision)?;
        nanos = fraction * 10_u32.pow((9 - precision) as u32);
    }

    let offset_seconds = match bytes.get(index) {
        Some(b'Z' | b'z') if index + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if index + 6 == bytes.len() && bytes[index + 3] == b':' => {
            let hours = parse_digits(bytes, index + 1, 2)?;
            let minutes = parse_digits(bytes, index + 4, 2)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = i64::from(hours * 3_600 + minutes * 60);
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };

    let local_seconds =
        days_from_civil(year, month, day) * 86_400 + i64::from(hour * 3_600 + minute * 60 + second);
    Some((local_seconds - offset_seconds, nanos))
}

fn parse_digits(bytes: &[u8], start: usize, length: usize) -> Option<u32> {
    bytes
        .get(start..start + length)?
        .iter()
        .try_fold(0_u32, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value * 10 + u32::from(*byte - b'0'))
        })
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn row_haystack(batch: Option<&BatchView>, alerts: &[AlertView]) -> String {
    let mut parts = Vec::new();
    if let Some(batch) = batch {
        parts.extend([
            batch.signal.as_str(),
            batch.catalog.as_str(),
            batch.vendor.as_str(),
            batch.service.as_str(),
            batch.endpoint_path.as_str(),
        ]);
        for record in &batch.summary {
            parts.extend([record.name.as_str(), record.what.as_str()]);
            for attribute in &record.attrs {
                parts.extend([
                    attribute.key.as_str(),
                    attribute.group.as_str(),
                    attribute.flag.as_str(),
                ]);
            }
        }
    }
    for alert in alerts {
        parts.extend([
            alert.pattern.as_str(),
            alert.event.as_str(),
            alert.attribute.as_str(),
        ]);
    }
    parts.retain(|part| !part.is_empty());
    parts.join("\n").to_lowercase()
}

fn summarize_flags(alerts: &[AlertView]) -> Vec<FeedFlag> {
    let mut flags = Vec::<FeedFlag>::new();
    let mut by_pattern = HashMap::<&str, usize>::new();
    for alert in alerts {
        if let Some(index) = by_pattern.get(alert.pattern.as_str()) {
            flags[*index].count = flags[*index].count.saturating_add(alert.count.max(1));
        } else {
            by_pattern.insert(alert.pattern.as_str(), flags.len());
            flags.push(FeedFlag {
                pattern: alert.pattern.clone(),
                count: alert.count.max(1),
            });
        }
    }
    flags
}

fn build_flag_groups(alerts: &[AlertView], format_time: impl Fn(&str) -> String) -> Vec<FlagGroup> {
    let mut groups = Vec::<FlagGroup>::new();
    let mut by_pattern = HashMap::<&str, usize>::new();
    for alert in alerts {
        let index = if let Some(index) = by_pattern.get(alert.pattern.as_str()) {
            *index
        } else {
            let index = groups.len();
            by_pattern.insert(alert.pattern.as_str(), index);
            groups.push(FlagGroup {
                pattern: alert.pattern.clone(),
                preset: alert.preset,
                hits: 0,
                total: 0,
                last: alert.timestamp.clone(),
                last_time: format_time(&alert.timestamp),
                events: Vec::new(),
                attributes: Vec::new(),
                signals: Vec::new(),
                matched: alert.matched.clone(),
            });
            index
        };
        let group = &mut groups[index];
        group.hits = group.hits.saturating_add(1);
        group.total = group.total.saturating_add(alert.count.max(1));
        add_unique(&mut group.events, &alert.event);
        add_unique(&mut group.attributes, &alert.attribute);
        add_unique(&mut group.signals, &alert.signal);
    }
    groups
}

fn add_unique(values: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !values.iter().any(|known| known == value) {
        values.push(value.to_owned());
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorView {
    pub timestamp: String,
    pub source: String,
    pub message: String,
    pub status: Option<u16>,
}

impl From<&ErrorLine> for ErrorView {
    fn from(error: &ErrorLine) -> Self {
        Self {
            timestamp: error.ts.clone(),
            source: error.source.clone(),
            message: error.message.clone().unwrap_or_else(|| {
                error.dropped.map_or_else(
                    || "Collector reported an error".into(),
                    |n| format!("{n} errors were dropped"),
                )
            }),
            status: error.status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{CollectorPattern, CollectorPatternKind};

    fn sample(kind: &str, version: u8) -> String {
        format!(r#"{{"v":{version},"type":"{kind}","ts":"2026-11-06T12:00:00Z","futureKey":true}}"#)
    }

    #[test]
    fn a_settings_problem_is_a_failure_with_its_code() {
        let mut model = Model::default();
        model.problem("tls-no-host", "HTTPS takeover needs at least one host name.");
        assert_eq!(model.state, State::Failed);
        let failure = model.view().failure.expect("a failure");
        assert_eq!(failure.code.as_deref(), Some("tls-no-host"));
        assert_eq!(failure.port, None);
        assert_eq!(failure.message, "HTTPS takeover needs at least one host name.");
    }

    #[test]
    fn decodes_hello_batch_alert_and_open_error_source() {
        let hello = decode_line(r#"{"v":1,"type":"hello","endpoint":"http://127.0.0.1:4318","setup":{"claudeCode":["one"],"codex":["two"]},"extra":1}"#).unwrap();
        assert!(
            matches!(hello, Line::Hello(Hello { endpoint, .. }) if endpoint == "http://127.0.0.1:4318")
        );
        let batch = decode_line(r#"{"v":1,"type":"batch","seq":1,"summary":{"identity":["user.email"],"records":[{"name":"evt","attrs":[{"key":"x","group":"content","known":true,"new":1}]}]},"resources":[]}"#).unwrap();
        assert!(
            matches!(batch, Line::Batch(Batch { summary, .. }) if summary.records[0].attrs[0].group.as_deref() == Some("content"))
        );
        assert!(matches!(
            decode_line(&sample("alert", 1)),
            Ok(Line::Alert(_))
        ));
        assert!(
            matches!(decode_line(r#"{"v":1,"type":"error","source":"future-source"}"#), Ok(Line::Error(ErrorLine { source, .. })) if source == "future-source")
        );
    }

    #[test]
    fn unknown_types_are_ignored_and_other_versions_stop() {
        assert_eq!(
            decode_line(&sample("future-type", 1)).unwrap(),
            Line::Unknown
        );
        assert_eq!(
            decode_line(&sample("hello", 2)),
            Err(DecodeError::UpdateRequired)
        );
    }

    #[test]
    fn config_stdin_keeps_patterns_out_of_arguments() {
        let settings = CollectorSettings {
            patterns: vec![
                CollectorPattern {
                    name: "customer".into(),
                    kind: CollectorPatternKind::Text,
                    pattern: "acme-private-pattern".into(),
                    case_sensitive: false,
                },
                CollectorPattern {
                    name: "too-long".into(),
                    kind: CollectorPatternKind::Text,
                    pattern: "x".repeat(crate::settings::COLLECTOR_MAX_PATTERN_BYTES + 1),
                    case_sensitive: false,
                },
            ],
            ..CollectorSettings::default()
        };
        let args = child_args(&settings).unwrap();
        assert!(args.iter().all(|arg| !arg.contains("acme-private-pattern")));
        let config = config_stdin(&settings).unwrap();
        let config: Value = serde_json::from_slice(&config).unwrap();
        assert!(config.to_string().contains("acme-private-pattern"));
        assert_eq!(config["redFlags"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn tls_hello_and_child_arguments_keep_takeover_fields() {
        let hello = decode_line(
            r#"{"v":1,"type":"hello","mode":"tls-receiver","tls":{"hosts":["otel.example.com"],"ca":{"path":"/state/ca.pem","sha256":"abc"}},"setup":{"takeover":["127.0.0.1 otel.example.com"]}}"#,
        )
        .unwrap();
        assert!(
            matches!(hello, Line::Hello(Hello { mode, tls: Some(TlsInfo { hosts, ca: TlsCaInfo { path, sha256 } }), setup: Setup { takeover, .. }, .. }) if mode == "tls-receiver" && hosts == ["otel.example.com"] && path == "/state/ca.pem" && sha256 == "abc" && takeover == ["127.0.0.1 otel.example.com"])
        );

        let settings = CollectorSettings {
            tls: true,
            tls_port: 8443,
            tls_hosts: vec!["OTEL.Example.com".into(), "logs.example.com".into()],
            ..CollectorSettings::default()
        };
        let args = child_args(&settings).unwrap();
        assert_eq!(
            args,
            [
                "--json",
                "--config-stdin",
                "--tls",
                "--tls-host",
                "otel.example.com",
                "--tls-host",
                "logs.example.com",
                "--port",
                "8443"
            ]
        );
        assert!(config_stdin(&settings).unwrap().starts_with(b"{\"v\":1"));
    }

    #[test]
    fn trust_output_decodes_the_helper_fixtures_and_nullable_fields() {
        let fixtures: &[(&str, i32)] = &[
            (
                r#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:29:49Z","claudeCode":{"state":"absent","settingsPath":"<HOME>/.claude/settings.json","value":null},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"<HOME>/.local/state/cainary/otel-debug-ca.pem","caExists":false,"note":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"preview","message":"Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup. Close Claude Code before applying this, and restart it afterwards. While the HTTPS takeover is active, your organization's collector receives nothing.","settingsPath":"<HOME>/.claude/settings.json","backupPath":"<HOME>/.claude/settings.json.cainary-20261106T162949Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"<HOME>/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"applied","message":"Claude Code will trust the collector certificate once it is restarted.","settingsPath":"<HOME>/.claude/settings.json","backupPath":"<HOME>/.claude/settings.json.cainary-20261106T162949Z.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"<HOME>/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"already","message":"Claude Code already trusts the collector certificate.","settingsPath":"<HOME>/.claude/settings.json","backupPath":null,"key":"NODE_EXTRA_CA_CERTS","from":"<HOME>/.local/state/cainary/otel-debug-ca.pem","to":"<HOME>/.local/state/cainary/otel-debug-ca.pem","bundlePath":null,"command":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust-status","ts":"2026-11-06T16:29:49Z","claudeCode":{"state":"applied","settingsPath":"<HOME>/.claude/settings.json","value":"<HOME>/.local/state/cainary/otel-debug-ca.pem"},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"<HOME>/.local/state/cainary/otel-debug-ca.pem","caExists":false,"note":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"codex","action":"refused","message":"Start the takeover once (cainary-otel-debug --tls …) so the collector certificate exists, then try again.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#,
                1,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:29:49Z","target":"claude-code","action":"undone","message":"Restored your previous Claude Code setting. Close Claude Code before applying this, and restart it afterwards.","settingsPath":"<HOME>/.claude/settings.json","backupPath":"<HOME>/.claude/settings.json.cainary-20261106T162949Z-1.bak","key":"NODE_EXTRA_CA_CERTS","from":"<HOME>/.local/state/cainary/otel-debug-ca.pem","to":null,"bundlePath":null,"command":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"claude-code","action":"nothing-to-undo","message":"cAInary has not changed your Claude Code settings.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#,
                0,
            ),
            (
                r#"{"v":1,"type":"trust","ts":"2026-11-06T16:17:20Z","target":"codex","action":"nothing-to-undo","message":"No Codex certificate bundle was prepared.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#,
                0,
            ),
        ];
        for (line, exit_code) in fixtures {
            let reply = decode_trust_output(line.as_bytes()).unwrap();
            if *exit_code == 1 {
                assert!(
                    matches!(reply, TrustReply::Trust(TrustResultLine { action, command: None, .. }) if action == "refused")
                );
            } else {
                assert!(
                    !matches!(reply, TrustReply::Trust(TrustResultLine { action, .. }) if action == "refused")
                );
            }
        }

        let TrustReply::Status(status) = decode_trust_output(fixtures[0].0.as_bytes()).unwrap()
        else {
            panic!("expected status response");
        };
        assert!(!status.ca_exists);
        assert_eq!(status.note, None);

        let TrustReply::Trust(preview) = decode_trust_output(fixtures[1].0.as_bytes()).unwrap()
        else {
            panic!("expected preview response");
        };
        assert_eq!(preview.key.as_deref(), Some("NODE_EXTRA_CA_CERTS"));
        assert_eq!(preview.from, None);
        assert_eq!(
            preview.backup_path.as_deref(),
            Some("<HOME>/.claude/settings.json.cainary-20261106T162949Z.bak")
        );
        assert!(
            preview
                .message
                .contains("Close Claude Code before applying this")
        );
    }

    #[test]
    fn no_write_command_quotes_paths_for_fish_and_bash() {
        assert_eq!(
            claude_no_write_command("/home/u/ca.pem").as_deref(),
            Some("env NODE_EXTRA_CA_CERTS=/home/u/ca.pem claude")
        );
        assert_eq!(
            claude_no_write_command("/home/a b/ca's.pem").as_deref(),
            Some("env NODE_EXTRA_CA_CERTS='/home/a b/ca'\\''s.pem' claude")
        );
    }

    #[test]
    fn line_version_stops_and_retention_is_bounded() {
        let mut model = Model::default();
        let (stop, _) = model.accept(sample("hello", 2));
        assert!(stop);
        assert_eq!(model.message, "Update cAInary");

        let mut model = Model::default();
        let line = format!(
            r#"{{"v":1,"type":"unknown","padding":"{}"}}"#,
            "x".repeat(MAX_LINE / 2)
        );
        for _ in 0..5 {
            model.accept(line.clone());
        }
        assert_eq!(model.retained_bytes, 0, "unknown lines are not retained");
    }

    #[test]
    fn fifty_large_batches_stay_under_the_retained_byte_limit() {
        let padding = "x".repeat(2 << 20);
        let mut model = Model::default();
        for seq in 0..50 {
            let line = format!(
                r#"{{"v":1,"type":"batch","seq":{seq},"resources":[{{"padding":"{padding}"}}]}}"#
            );
            assert!(line.len() < MAX_LINE);
            model.accept(line);
        }

        assert!(model.retained_bytes <= MAX_RETAINED);
        assert_eq!(
            model.retained_bytes,
            model
                .batches
                .iter()
                .map(|batch| batch.line_bytes)
                .sum::<usize>()
        );
        assert_eq!(model.batches.back().unwrap().batch.seq, 49);
        assert!(model.batches.front().unwrap().batch.seq > 0);
        assert!(model.batches.len() < 50);
    }

    #[test]
    fn alerts_are_throttled_per_pattern_for_sixty_seconds() {
        let mut model = Model::default();
        let alert = Alert {
            pattern: "email".into(),
            event: Some("claude_code.tool_result".into()),
            attribute: "tool_input".into(),
            matched: "abc…(20 chars)".into(),
            ..Alert::default()
        };
        let now = Instant::now();
        assert!(model.alert_notification(&alert, true, now).is_some());
        assert!(
            model
                .alert_notification(&alert, true, now + Duration::from_secs(59))
                .is_none()
        );
        assert!(
            model
                .alert_notification(&alert, true, now + Duration::from_secs(60))
                .is_some()
        );
    }

    #[test]
    fn batch_and_alert_counts_are_capped() {
        let mut model = Model::default();
        for seq in 0..MAX_BATCHES + 5 {
            model.accept(format!(r#"{{"v":1,"type":"batch","seq":{seq}}}"#));
        }
        for _ in 0..MAX_ALERTS + 5 {
            model.accept(r#"{"v":1,"type":"alert"}"#.into());
        }
        assert_eq!(model.batches.len(), MAX_BATCHES);
        assert_eq!(model.alerts.len(), MAX_ALERTS);
        assert!(model.retained_bytes <= MAX_RETAINED);
    }
}

#[cfg(test)]
mod feed_tests {
    use super::*;

    fn batch(id: u64, timestamp: &str, signal: &str) -> BatchView {
        BatchView {
            id,
            timestamp: timestamp.into(),
            signal: signal.into(),
            endpoint_path: "/v1/logs".into(),
            catalog: "".into(),
            vendor: "Acme".into(),
            service: "worker 1.2".into(),
            bytes: 2048,
            records: 3,
            not_in_catalog: 1,
            identity: Vec::new(),
            resource: Vec::new(),
            summary: vec![SummaryRecordView {
                name: "claude-code.tool_result".into(),
                kind: "event".into(),
                count: 1,
                known: true,
                what: "A tool result".into(),
                attrs: vec![SummaryAttributeView {
                    key: "user.email".into(),
                    group: "identity".into(),
                    flag: String::new(),
                    known: true,
                }],
            }],
            raw_records: "[]".into(),
            resources_omitted: false,
        }
    }

    fn alert(seq: u64, timestamp: &str, signal: &str, pattern: &str, count: u64) -> AlertView {
        AlertView {
            seq,
            timestamp: timestamp.into(),
            pattern: pattern.into(),
            preset: true,
            signal: signal.into(),
            event: "claude-code.tool_result".into(),
            attribute: "tool_input".into(),
            location: "record".into(),
            count,
            matched: "secret".into(),
        }
    }

    #[test]
    fn feed_links_the_nearest_same_signal_batch_at_the_five_second_boundary() {
        let batches = [
            batch(1, "2026-11-07T11:59:57Z", "logs"),
            batch(2, "2026-11-07T11:59:58Z", "logs"),
        ];
        let alerts = [alert(
            7,
            "2026-11-07T12:00:03Z",
            "logs",
            "aws-access-key",
            2,
        )];
        let rows = build_feed_rows(&batches, &alerts, |_| "12:00:00".into());

        let linked = rows.iter().find(|row| row.key == "batch:2").unwrap();
        assert_eq!(linked.flag_details.len(), 1);
        assert_eq!(
            linked.flags,
            vec![FeedFlag {
                pattern: "aws-access-key".into(),
                count: 2
            }]
        );
        assert!(
            rows.iter()
                .find(|row| row.key == "batch:1")
                .unwrap()
                .flags
                .is_empty()
        );
    }

    #[test]
    fn feed_does_not_link_alerts_outside_the_five_second_window() {
        let batches = [batch(1, "2026-11-07T11:59:54Z", "logs")];
        let alerts = [alert(
            7,
            "2026-11-07T12:00:00Z",
            "logs",
            "aws-access-key",
            1,
        )];
        let rows = build_feed_rows(&batches, &alerts, |_| "12:00:00".into());

        assert_eq!(rows.len(), 2);
        let unlinked = rows.iter().find(|row| row.is_alert).unwrap();
        assert_eq!(unlinked.key, "alert:7");
        assert_eq!(unlinked.flags.len(), 1);
        assert_eq!(unlinked.flag_details, alerts.to_vec());
    }

    #[test]
    fn feed_keeps_alerts_with_no_matching_batch_as_their_own_rows() {
        let batches = [batch(1, "2026-11-07T11:59:59Z", "metrics")];
        let alerts = [alert(9, "2026-11-07T12:00:00Z", "logs", "private-value", 1)];
        let rows = build_feed_rows(&batches, &alerts, |_| "12:00:00".into());

        let unlinked = rows.iter().find(|row| row.is_alert).unwrap();
        assert_eq!(unlinked.key, "alert:9");
        assert_eq!(unlinked.source, "claude-code.tool_result");
        assert_eq!(unlinked.batch_id, None);
    }

    #[test]
    fn feed_rows_are_ordered_newest_first() {
        let batches = [
            batch(1, "2026-11-07T12:00:00Z", "logs"),
            batch(2, "2026-11-07T12:05:00Z", "metrics"),
        ];
        let alerts = [alert(
            8,
            "2026-11-07T12:03:00Z",
            "traces",
            "private-value",
            1,
        )];
        let rows = build_feed_rows(&batches, &alerts, |_| String::new());

        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            vec!["batch:2", "alert:8", "batch:1"]
        );
    }

    #[test]
    fn feed_preformats_clock_size_and_source() {
        let row = build_feed_rows(
            &[batch(1, "2026-11-07T12:34:56Z", "logs")],
            &[],
            |timestamp| format_clock_with_offset(timestamp, 2 * 60 * 60),
        )
        .remove(0);

        assert_eq!(row.time, "14:34:56");
        assert_eq!(row.size, "2 KB");
        assert_eq!(row.source, "Acme worker 1.2");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1_048_576), "1.0 MB");
        assert_eq!(format_clock_with_offset("unreadable", 0), "unreadable");
    }

    #[test]
    fn feed_filter_matches_each_enabled_condition() {
        let batches = [batch(1, "2026-11-07T12:00:00Z", "logs")];
        let alerts = [alert(
            7,
            "2026-11-07T12:00:01Z",
            "logs",
            "aws-access-key",
            2,
        )];
        let row = build_feed_rows(&batches, &alerts, |_| String::new())
            .into_iter()
            .find(|row| row.key == "batch:1")
            .unwrap();
        let mut filter = FeedFilter {
            signals: HashSet::from(["logs".into()]),
            flagged_only: true,
            uncataloged_only: true,
            search_text: "  USER.EMAIL  ".into(),
            pattern: "aws-access-key".into(),
        };

        assert!(matches(&row, &filter));
        filter.signals.clear();
        assert!(!matches(&row, &filter));
        filter.signals.insert("logs".into());
        filter.flagged_only = false;
        filter.pattern.clear();
        filter.uncataloged_only = false;
        filter.search_text = "missing".into();
        assert!(!matches(&row, &filter));
        filter.search_text.clear();
        filter.pattern = "another-pattern".into();
        assert!(!matches(&row, &filter));
        filter.pattern.clear();
        filter.uncataloged_only = true;
        let mut cataloged = row.clone();
        cataloged.not_in_catalog = 0;
        assert!(!matches(&cataloged, &filter));
        filter.uncataloged_only = false;
        filter.flagged_only = true;
        let mut unflagged = row;
        unflagged.flags.clear();
        assert!(!matches(&unflagged, &filter));
    }

    #[test]
    fn flag_groups_keep_recent_pattern_order_and_totals() {
        let alerts = [
            alert(3, "2026-11-07T12:02:00Z", "logs", "aws-access-key", 2),
            alert(2, "2026-11-07T12:01:00Z", "metrics", "aws-access-key", 1),
            alert(1, "2026-11-07T12:00:00Z", "traces", "private-value", 3),
        ];
        let groups = build_flag_groups(&alerts, |_| "12:00:00".into());

        assert_eq!(groups[0].pattern, "aws-access-key");
        assert_eq!(groups[0].hits, 2);
        assert_eq!(groups[0].total, 3);
        assert_eq!(groups[0].last, "2026-11-07T12:02:00Z");
        assert_eq!(groups[0].last_time, "12:00:00");
        assert_eq!(groups[0].signals, vec!["logs", "metrics"]);
        assert_eq!(groups[1].pattern, "private-value");
    }

    #[test]
    fn clear_empties_feed_rows_and_red_flag_groups_without_stopping_collector() {
        let mut model = Model {
            state: State::Listening,
            ..Model::default()
        };
        model.accept(r#"{"v":1,"type":"batch","seq":1,"ts":"2026-11-07T12:00:00Z"}"#.into());
        model.accept(r#"{"v":1,"type":"alert","seq":2,"ts":"2026-11-07T12:00:01Z","pattern":"private-value"}"#.into());
        assert!(!model.view().flag_groups.is_empty());

        model.clear();

        let view = model.view();
        assert_eq!(model.state, State::Listening);
        assert_eq!(model.retained_bytes, 0);
        assert!(view.batches.is_empty());
        assert!(view.alerts.is_empty());
        assert!(view.rows.is_empty());
        assert!(view.flag_groups.is_empty());
    }
}
