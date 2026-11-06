//! Pure decoder and bounded view model for `cainary-otel-debug` JSON-lines v1.

use std::collections::{HashMap, VecDeque};
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
    if !settings.valid() {
        return Err("check the collector port and red-flag patterns".into());
    }
    let mut args = vec![
        "--json".to_owned(),
        "--config-stdin".to_owned(),
        "--port".to_owned(),
        settings.port.to_string(),
    ];
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
    if !settings.valid() {
        return Err("check the collector port and red-flag patterns".into());
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

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub generator: String,
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
    pub setup: Setup,
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
    batches: VecDeque<StoredBatch>,
    alerts: VecDeque<StoredAlert>,
    errors: VecDeque<ErrorLine>,
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

    pub fn failed(&mut self, reason: impl Into<String>) {
        self.state = State::Failed;
        self.message = reason.into();
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
            claude_code: hello
                .map(|h| h.setup.claude_code.clone())
                .unwrap_or_default(),
            codex: hello.map(|h| h.setup.codex.clone()).unwrap_or_default(),
            notes: hello.map(|h| h.setup.notes.clone()).unwrap_or_default(),
            batches,
            alerts,
            errors,
            retained_bytes: self.retained_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub state: String,
    pub message: String,
    pub endpoint: String,
    pub claude_code: Vec<String>,
    pub codex: Vec<String>,
    pub notes: Vec<String>,
    pub batches: Vec<BatchView>,
    pub alerts: Vec<AlertView>,
    pub errors: Vec<ErrorView>,
    pub retained_bytes: usize,
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertView {
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
