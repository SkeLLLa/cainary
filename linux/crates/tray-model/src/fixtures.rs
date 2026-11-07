//! The scenarios the self-test, the dev harness and `SampleView.js` share. Each one is a core
//! golden report, unmodified except for the change records of `details-changes`, in a scan state
//! and with the settings a window is shown with. Reports are never merged, so every view is
//! internally consistent.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use crate::collector::Model as CollectorModel;
use crate::portaccess::{self, Access, Inputs};
use crate::report::Report;
use crate::runner::ScanError;
use crate::settings::{CollectorPattern, CollectorPatternKind, Settings};
use crate::store::{ScanState, Snapshot};

const CLAUDE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crates/cainary-core/tests/golden/claude-code-linux.json"
));
const DEVICE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crates/cainary-core/tests/golden/device-linux.json"
));
const EMPTY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crates/cainary-core/tests/golden/empty-linux.json"
));

/// 2026-01-01T14:05:00Z, the time every fixture snapshot was taken.
const AT: Duration = Duration::from_secs(1_767_276_300);

#[derive(Clone, Debug)]
pub struct Scenario {
    /// Also the snapshot file name (`<name>.png`) and the `SampleView` variant.
    pub name: &'static str,
    /// The window shown: `popup`, `details` or `about`.
    pub window: &'static str,
    /// What Details selects: `""`, `":changes"`, `":sources"`, `":settings"`, `":collector"` or
    /// `":collector:<tab or pattern>"`.
    pub selection: &'static str,
    pub state: ScanState,
    pub settings: Settings,
    pub dark: bool,
    /// Builds the collector view JSON shown with this scenario; `None` leaves the collector off.
    pub collector: Option<fn() -> String>,
}

impl Scenario {
    /// The collector view JSON this scenario shows, if any. The self-test and the QML harness
    /// (`qml/dev/SampleView.js`) both read it.
    pub fn collector(&self) -> Option<String> {
        self.collector.map(|build| build())
    }
}

/// A change record as the core prints it.
pub fn change_record(id: &str, entry: &str, text: &str) -> Value {
    json!({
        "id": id, "scope": "finding", "entry": entry, "key": "k", "kind": "added",
        "from": null, "to": "medium", "notify": true, "text": text,
    })
}

/// `raw` with `since` and `changes` added, as a `--since` scan prints it.
pub fn with_changes(raw: &[u8], changes: Vec<Value>, since_error: Option<&str>) -> Vec<u8> {
    let mut report: Value = serde_json::from_slice(raw).expect("a golden is JSON");
    report["since"] = json!({"scannedAt": "2026-01-01T00:00:00Z", "error": since_error});
    report["changes"] = Value::Array(changes);
    serde_json::to_vec(&report).expect("a report serializes")
}

/// A synthetic collector stream for the Feed / Red flags / Setup prototypes: twelve batches over
/// a few minutes from Claude Code and Codex, and six alerts over four patterns. The first five
/// share `ts`, `signal` and `event` with a batch (the first two with the same one); the last
/// matches none.
#[allow(clippy::type_complexity)]
pub fn collector_sample() -> String {
    let mut model = CollectorModel::default();
    let mut feed = |line: Value| {
        model.accept(line.to_string());
    };
    feed(json!({
        "v": 1, "type": "hello", "ts": "2026-01-01T14:00:00Z",
        "generator": "cainary-otel-debug 0.6.0", "mode": "receiver",
        "endpoint": "http://127.0.0.1:4318", "listen": ["127.0.0.1:4318"],
        "redFlags": [
            {"name": "aws-access-key", "kind": "regex", "preset": true, "caseSensitive": true},
            {"name": "email", "kind": "regex", "preset": true, "caseSensitive": false},
            {"name": "github-token", "kind": "regex", "preset": true, "caseSensitive": true},
            {"name": "acme-project", "kind": "text", "preset": false, "caseSensitive": false},
        ],
        "setup": {
            "claudeCode": [
                "CLAUDE_CODE_ENABLE_TELEMETRY=1",
                "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318",
            ],
            "codex": ["otel.exporter={otlp-http={…}}"],
            "notes": ["Use a local endpoint in the tool configuration."],
        },
    }));
    // (ts, signal, vendor, service version, bytes, records, notInCatalog, record name, kind, what, attrs)
    type Attr = (
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        bool,
    );
    let batches: [(
        &str,
        &str,
        &str,
        &str,
        u64,
        u64,
        u64,
        &str,
        &str,
        &str,
        Vec<Attr>,
    ); 12] = [
        (
            "14:00:12",
            "logs",
            "claude-code",
            "2.1.316",
            18_204,
            9,
            0,
            "claude_code.user_prompt",
            "event",
            "A prompt was submitted",
            vec![
                ("prompt_length", None, None, true),
                (
                    "prompt",
                    Some("content"),
                    Some("OTEL_LOG_USER_PROMPTS"),
                    true,
                ),
            ],
        ),
        (
            "14:00:41",
            "metrics",
            "claude-code",
            "2.1.316",
            6_310,
            14,
            0,
            "claude_code.token.usage",
            "metric",
            "Tokens used",
            vec![("type", None, None, true), ("model", None, None, true)],
        ),
        (
            "14:01:03",
            "logs",
            "claude-code",
            "2.1.316",
            20_431,
            12,
            1,
            "claude_code.tool_result",
            "event",
            "A tool finished",
            vec![
                (
                    "tool_parameters",
                    Some("content"),
                    Some("OTEL_LOG_TOOL_DETAILS"),
                    true,
                ),
                ("foo", None, None, false),
            ],
        ),
        (
            "14:01:30",
            "traces",
            "claude-code",
            "2.1.316",
            9_872,
            6,
            2,
            "claude_code.tool",
            "span",
            "One tool call",
            vec![
                ("tool_name", None, None, true),
                ("span.extra", None, None, false),
                (
                    "tool_input",
                    Some("content"),
                    Some("OTEL_LOG_TOOL_DETAILS"),
                    true,
                ),
            ],
        ),
        (
            "14:01:58",
            "logs",
            "codex",
            "0.58.0",
            7_015,
            5,
            0,
            "codex.conversation_starts",
            "event",
            "A conversation began",
            vec![
                ("model", None, None, true),
                ("approval_policy", None, None, true),
            ],
        ),
        (
            "14:02:20",
            "logs",
            "codex",
            "0.58.0",
            11_640,
            8,
            3,
            "codex.tool_result",
            "event",
            "A tool finished",
            vec![
                ("arguments", Some("content"), None, true),
                ("output", Some("content"), None, true),
                ("sandbox_note", None, None, false),
            ],
        ),
        (
            "14:02:47",
            "metrics",
            "codex",
            "0.58.0",
            4_218,
            7,
            0,
            "codex.api_request",
            "metric",
            "A model request was made",
            vec![
                ("status", None, None, true),
                ("duration_ms", None, None, true),
            ],
        ),
        (
            "14:03:10",
            "logs",
            "claude-code",
            "2.1.316",
            15_902,
            10,
            0,
            "claude_code.api_request",
            "event",
            "A model request finished",
            vec![("model", None, None, true), ("cost_usd", None, None, true)],
        ),
        (
            "14:03:36",
            "logs",
            "claude-code",
            "2.1.316",
            22_760,
            13,
            1,
            "claude_code.tool_result",
            "event",
            "A tool finished",
            vec![
                (
                    "tool_parameters",
                    Some("content"),
                    Some("OTEL_LOG_TOOL_DETAILS"),
                    true,
                ),
                ("bar", None, None, false),
            ],
        ),
        (
            "14:04:02",
            "traces",
            "codex",
            "0.58.0",
            8_431,
            4,
            1,
            "codex.turn",
            "span",
            "One agent turn",
            vec![
                ("turn_id", None, None, true),
                ("thread.hint", None, None, false),
            ],
        ),
        (
            "14:04:29",
            "logs",
            "codex",
            "0.58.0",
            9_377,
            6,
            0,
            "codex.user_prompt",
            "event",
            "A prompt was submitted",
            vec![
                ("prompt", Some("content"), None, true),
                ("prompt_length", None, None, true),
            ],
        ),
        (
            "14:04:55",
            "metrics",
            "claude-code",
            "2.1.316",
            6_944,
            15,
            0,
            "claude_code.cost.usage",
            "metric",
            "Money spent",
            vec![("model", None, None, true)],
        ),
    ];
    for (i, (time, signal, vendor, version, bytes, records, missing, name, kind, what, attrs)) in
        batches.into_iter().enumerate()
    {
        let service = if vendor == "codex" {
            "codex_cli_rs"
        } else {
            "claude-code"
        };
        let attrs: Vec<Value> = attrs
            .into_iter()
            .map(|(key, group, flag, known)| json!({"key": key, "group": group, "flag": flag, "known": known}))
            .collect();
        feed(json!({
            "v": 1, "type": "batch", "ts": format!("2026-01-01T14:{}Z", &time[3..]),
            "seq": i + 1, "signal": signal, "path": format!("/v1/{signal}"), "bytes": bytes,
            "vendor": vendor, "service": {"name": service, "version": version},
            "catalog": format!("{vendor} {version}"), "records": records, "notInCatalog": missing,
            "summary": {
                "identity": if vendor == "codex" { json!(["user.account_id"]) } else { json!(["user.email"]) },
                "resource": ["host.arch", "os.type"],
                "records": [{"name": name, "kind": kind, "count": records.min(4), "known": true, "what": what, "attrs": attrs}],
            },
            "resources": [],
        }));
    }
    // (ts, pattern, preset, signal, event, attribute, where, count, match)
    let alerts = [
        (
            "14:01:03",
            "aws-access-key",
            true,
            "logs",
            "claude_code.tool_result",
            "tool_parameters",
            "value",
            2,
            "AKI…(20 chars)",
        ),
        (
            "14:01:03",
            "email",
            true,
            "logs",
            "claude_code.tool_result",
            "tool_parameters",
            "value",
            1,
            "a…@example.com",
        ),
        (
            "14:02:20",
            "github-token",
            true,
            "logs",
            "codex.tool_result",
            "output",
            "value",
            1,
            "ghp_…(40 chars)",
        ),
        (
            "14:03:36",
            "aws-access-key",
            true,
            "logs",
            "claude_code.tool_result",
            "tool_parameters",
            "value",
            1,
            "AKI…(20 chars)",
        ),
        (
            "14:04:29",
            "acme-project",
            false,
            "logs",
            "codex.user_prompt",
            "prompt",
            "value",
            3,
            "acme-project",
        ),
        (
            "14:04:40",
            "email",
            true,
            "traces",
            "claude_code.tool",
            "tool_input",
            "value",
            1,
            "d…@example.org",
        ),
    ];
    for (i, (time, pattern, preset, signal, event, attribute, location, count, matched)) in
        alerts.into_iter().enumerate()
    {
        feed(json!({
            "v": 1, "type": "alert", "ts": format!("2026-01-01T14:{}Z", &time[3..]),
            "seq": i + 1, "pattern": pattern, "preset": preset, "signal": signal, "event": event,
            "attribute": attribute, "where": location, "count": count, "match": matched,
        }));
    }
    feed(json!({
        "v": 1, "type": "error", "ts": "2026-01-01T14:03:50Z", "source": "receiver",
        "status": 415, "method": "POST", "path": "/v1/logs",
        "message": "Unsupported content type application/x-protobuf-text",
    }));
    feed(json!({
        "v": 1, "type": "error", "ts": "2026-01-01T14:04:12Z", "source": "stderr",
        "message": "dropped 2 oversized records", "dropped": 2,
    }));
    serde_json::to_string(&model.view()).expect("collector sample serializes")
}

/// A TLS takeover with a pending Claude Code preview, for the confirmation dialog snapshot.
pub fn collector_trust_preview_sample() -> String {
    let mut model = CollectorModel::default();
    // Neutral UI-only paths: real settings and backup paths always come from helper JSON.
    let claude_settings = "/home/demo/claude-settings.json";
    let claude_backup = "/home/demo/claude-settings.json.cainary-20261106T161720Z.bak";
    model.accept(
        r#"{"v":1,"type":"hello","mode":"tls-receiver","endpoint":"https://127.0.0.1:8443","tls":{"hosts":["otel.example-corp.com"],"ca":{"path":"/home/demo/.local/state/cainary/otel-debug-ca.pem","sha256":"0123456789abcdef"}},"setup":{"takeover":["127.0.0.1 otel.example-corp.com","::1 otel.example-corp.com","NODE_EXTRA_CA_CERTS=/home/demo/.local/state/cainary/otel-debug-ca.pem"],"notes":["Your organization's collector receives nothing while the takeover is active."]}}"#.into(),
    );
    let mut view = serde_json::to_value(model.view()).expect("collector view serializes");
    view["trust"] = json!({
        "busy": false,
        "message": "",
        "status": {
            "claudeCode": {"state": "absent", "settingsPath": claude_settings, "value": null},
            "codex": {"state": "absent", "bundlePath": null, "command": null},
            "caPath": "/home/demo/.local/state/cainary/otel-debug-ca.pem",
            "caExists": true,
            "note": null
        },
        "preview": {
            "target": "claude-code",
            "action": "preview",
            "message": "Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup.",
            "settingsPath": claude_settings,
            "backupPath": claude_backup,
            "key": "NODE_EXTRA_CA_CERTS",
            "from": null,
            "to": "/home/demo/.local/state/cainary/otel-debug-claude-bundle.pem",
            "bundlePath": "/home/demo/.local/state/cainary/otel-debug-claude-bundle.pem",
            "command": null
        },
        "result": null,
        "noWriteAvailable": true,
        "noWriteCommand": "env NODE_EXTRA_CA_CERTS=/home/demo/.local/state/cainary/otel-debug-ca.pem claude"
    });
    serde_json::to_string(&view).expect("trust preview serializes")
}

const FIXTURE_HELLO: &str = r#"{"v":1,"type":"hello","ts":"2026-01-01T14:00:00Z","mode":"receiver","endpoint":"http://127.0.0.1:443","listen":["127.0.0.1:443"],"setup":{"claudeCode":["OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:443"],"codex":[],"notes":[]}}"#;

fn startup_error(code: &str, port: u16, message: &str) -> String {
    json!({
        "v": 1, "type": "error", "source": "listen", "code": code, "port": port,
        "message": message,
    })
    .to_string()
}

/// A collector view with the `privilege` object the app adds when it publishes.
fn collector_view(model: &CollectorModel, access: &Access, held: bool, running: bool) -> String {
    collector_view_for(model, access, held, running, true)
}

fn collector_view_for(
    model: &CollectorModel,
    access: &Access,
    held: bool,
    running: bool,
    enabled: bool,
) -> String {
    let privilege = portaccess::view(&Inputs {
        port: 443,
        access,
        held,
        running,
        enabled,
        opening: false,
        dev: false,
        error: None,
        notice: None,
    });
    let mut view = serde_json::to_value(model.view()).expect("collector view serializes");
    view["privilege"] = serde_json::to_value(privilege).expect("privilege serializes");
    serde_json::to_string(&view).expect("collector view serializes")
}

fn blocked_model() -> CollectorModel {
    let mut model = CollectorModel::default();
    model.blocked("port-privileged", 443, portaccess::needs_message(443));
    model
}

/// Port 443 needs the root helper and it isn't installed.
pub fn collector_priv_no_helper() -> String {
    let access = Access::NoHelper("the port helper isn't installed".into());
    collector_view(&blocked_model(), &access, false, false)
}

pub fn collector_priv_ready() -> String {
    collector_view(&blocked_model(), &Access::Ready, false, false)
}

pub fn collector_priv_mismatch() -> String {
    let access = Access::Mismatch("the helper is version 0.4.0, this app is 0.5.2".into());
    collector_view(&blocked_model(), &access, false, false)
}

/// The collector crashed after it started; the tray still holds port 443.
pub fn collector_priv_held_stopped() -> String {
    let mut model = CollectorModel::default();
    model.starting();
    model.accept(FIXTURE_HELLO.into());
    model.exited(Some(137), "");
    collector_view(&model, &Access::Ready, true, false)
}

/// Listening on a port the tray opened.
pub fn collector_priv_held() -> String {
    let mut model = CollectorModel::default();
    model.starting();
    model.accept(FIXTURE_HELLO.into());
    collector_view(&model, &Access::Ready, true, true)
}

/// Privileged port, collector switched off: the note under the port field says what is needed.
pub fn collector_priv_off() -> String {
    collector_view_for(
        &CollectorModel::default(),
        &Access::Ready,
        false,
        false,
        false,
    )
}

pub fn collector_fail_tls_no_host() -> String {
    let mut model = CollectorModel::default();
    model.problem(
        "tls-no-host",
        "HTTPS takeover needs at least one host name.",
    );
    collector_view(&model, &Access::NotNeeded, false, false)
}

pub fn collector_fail_port_in_use() -> String {
    let mut model = CollectorModel::default();
    model.starting();
    model.accept(startup_error(
        "port-in-use",
        4318,
        "can't listen on 127.0.0.1:4318: address already in use",
    ));
    model.exited(Some(1), "");
    collector_view(&model, &Access::NotNeeded, false, false)
}

/// The collector refused the sockets it was handed; the tray gave the port back.
pub fn collector_fail_listen_fd() -> String {
    let mut model = CollectorModel::default();
    model.starting();
    model.accept(startup_error(
        "listen-fd",
        443,
        "--listen-fd 3 isn't a listening socket on 127.0.0.1:443",
    ));
    model.exited(Some(2), "");
    collector_view(&model, &Access::Ready, false, false)
}

pub fn collector_fail_other() -> String {
    let mut model = CollectorModel::default();
    model.starting();
    model.exited(Some(1), "cainary-otel-debug: out of memory\n");
    collector_view(&model, &Access::NotNeeded, false, false)
}

fn snapshot(raw: &[u8]) -> Arc<Snapshot> {
    Arc::new(Snapshot {
        report: Report::decode(raw).expect("a golden decodes"),
        raw: raw.to_vec(),
        at: SystemTime::UNIX_EPOCH + AT,
    })
}

fn ready(raw: &[u8]) -> ScanState {
    ScanState::Ready(snapshot(raw))
}

pub fn scenarios() -> Vec<Scenario> {
    let defaults = Settings::default();
    let expanded = Settings {
        not_installed_expanded: true,
        ..defaults.clone()
    };
    let mut https_takeover = defaults.clone();
    https_takeover.collector.enabled = true;
    https_takeover.collector.tls = true;
    https_takeover.collector.tls_hosts = vec!["otel.example-corp.com".into()];
    let changed = with_changes(
        CLAUDE,
        vec![
            change_record("c1", "claude", "Bedrock routing was turned on"),
            change_record("c2", "claude", "Telemetry export was turned on"),
        ],
        None,
    );
    let scenario =
        |name, window, selection, state: ScanState, settings: &Settings, dark| Scenario {
            name,
            window,
            selection,
            state,
            settings: settings.clone(),
            dark,
            collector: None,
        };
    let live = |mut s: Scenario, build: fn() -> String| {
        s.collector = Some(build);
        s
    };
    let mut live_settings = defaults.clone();
    live_settings.collector.enabled = true;
    live_settings.collector.notify = true;
    live_settings.collector.patterns = vec![CollectorPattern {
        name: "acme-project".into(),
        kind: CollectorPatternKind::Text,
        pattern: "acme-project".into(),
        case_sensitive: false,
    }];
    let mut priv_settings = defaults.clone();
    priv_settings.collector.enabled = true;
    priv_settings.collector.port = 443;
    let mut priv_off_settings = priv_settings.clone();
    priv_off_settings.collector.enabled = false;
    let mut no_host_settings = defaults.clone();
    no_host_settings.collector.enabled = true;
    no_host_settings.collector.tls = true;
    let mut in_use_settings = defaults.clone();
    in_use_settings.collector.enabled = true;
    let mut off_settings = defaults.clone();
    off_settings.collector.enabled = false;
    let details = |name, selection, settings: &Settings, dark| {
        scenario(name, "details", selection, ready(CLAUDE), settings, dark)
    };
    vec![
        scenario("popup", "popup", "", ready(CLAUDE), &defaults, false),
        scenario(
            "popup-expanded",
            "popup",
            "",
            ready(CLAUDE),
            &expanded,
            false,
        ),
        scenario(
            "popup-failed",
            "popup",
            "",
            ScanState::Failed {
                error: ScanError::TimedOut,
                last: Some(snapshot(CLAUDE)),
            },
            &defaults,
            false,
        ),
        scenario(
            "popup-scanning",
            "popup",
            "",
            ScanState::Scanning { last: None },
            &defaults,
            false,
        ),
        scenario("popup-empty", "popup", "", ready(EMPTY), &defaults, false),
        scenario("details", "details", "", ready(CLAUDE), &defaults, false),
        live(
            details("details-collector", ":collector", &live_settings, false),
            collector_sample,
        ),
        live(
            details(
                "details-collector-trust-preview",
                ":collector:trust-preview",
                &https_takeover,
                false,
            ),
            collector_trust_preview_sample,
        ),
        live(
            details(
                "details-collector-feed",
                ":collector:feed",
                &live_settings,
                false,
            ),
            collector_sample,
        ),
        live(
            details(
                "details-collector-flags",
                ":collector:flags",
                &live_settings,
                false,
            ),
            collector_sample,
        ),
        live(
            details(
                "details-collector-setup",
                ":collector:setup",
                &https_takeover,
                false,
            ),
            collector_sample,
        ),
        details(
            "details-collector-off",
            ":collector:feed",
            &off_settings,
            false,
        ),
        live(
            details(
                "details-collector-pattern",
                ":collector:aws-access-key",
                &live_settings,
                false,
            ),
            collector_sample,
        ),
        live(
            details(
                "details-collector-priv-no-helper",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_priv_no_helper,
        ),
        live(
            details(
                "details-collector-priv-ready",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_priv_ready,
        ),
        live(
            details(
                "details-collector-priv-ready-dark",
                ":collector:setup",
                &priv_settings,
                true,
            ),
            collector_priv_ready,
        ),
        live(
            details(
                "details-collector-priv-mismatch",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_priv_mismatch,
        ),
        live(
            details(
                "details-collector-priv-held-stopped",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_priv_held_stopped,
        ),
        live(
            details(
                "details-collector-priv-held",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_priv_held,
        ),
        live(
            details(
                "details-collector-priv-off",
                ":collector:setup",
                &priv_off_settings,
                false,
            ),
            collector_priv_off,
        ),
        live(
            details(
                "details-collector-fail-tls-no-host",
                ":collector:setup",
                &no_host_settings,
                false,
            ),
            collector_fail_tls_no_host,
        ),
        live(
            details(
                "details-collector-fail-port-in-use",
                ":collector:setup",
                &in_use_settings,
                false,
            ),
            collector_fail_port_in_use,
        ),
        live(
            details(
                "details-collector-fail-port-in-use-dark",
                ":collector:setup",
                &in_use_settings,
                true,
            ),
            collector_fail_port_in_use,
        ),
        live(
            details(
                "details-collector-fail-listen-fd",
                ":collector:setup",
                &priv_settings,
                false,
            ),
            collector_fail_listen_fd,
        ),
        live(
            details(
                "details-collector-fail-other",
                ":collector:setup",
                &in_use_settings,
                false,
            ),
            collector_fail_other,
        ),
        details("details-settings", ":settings", &defaults, false),
        live(
            details(
                "details-collector-dark",
                ":collector:feed",
                &live_settings,
                true,
            ),
            collector_sample,
        ),
        live(
            scenario(
                "popup-live",
                "popup",
                "",
                ready(CLAUDE),
                &live_settings,
                false,
            ),
            collector_sample,
        ),
        scenario(
            "details-changes",
            "details",
            ":changes",
            ready(&changed),
            &defaults,
            false,
        ),
        scenario(
            "details-sources",
            "details",
            ":sources",
            ready(DEVICE),
            &defaults,
            false,
        ),
        scenario(
            "about",
            "about",
            "",
            ScanState::Scanning { last: None },
            &defaults,
            false,
        ),
        scenario("popup-dark", "popup", "", ready(CLAUDE), &defaults, true),
        scenario(
            "details-dark",
            "details",
            "",
            ready(CLAUDE),
            &defaults,
            true,
        ),
    ]
}
