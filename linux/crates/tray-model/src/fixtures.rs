//! The scenarios the self-test, the dev harness and `SampleView.js` share. Each one is a core
//! golden report, unmodified except for the change records of `details-changes`, in a scan state
//! and with the settings a window is shown with. Reports are never merged, so every view is
//! internally consistent.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use crate::collector::Model as CollectorModel;
use crate::report::Report;
use crate::runner::ScanError;
use crate::settings::Settings;
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
    /// The window shown: `popup`, `details`, `settings` or `about`.
    pub window: &'static str,
    /// What Details selects: `""`, `":changes"`, `":sources"` or `":collector"`.
    pub selection: &'static str,
    pub state: ScanState,
    pub settings: Settings,
    pub dark: bool,
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

/// A synthetic collector stream for the Details offscreen snapshot.
pub fn collector_sample() -> String {
    let mut model = CollectorModel::default();
    model.accept(
        r#"{"v":1,"type":"hello","ts":"2026-01-01T14:05:00Z","generator":"cainary-otel-debug 0.6.0","endpoint":"http://127.0.0.1:4318","setup":{"claudeCode":["CLAUDE_CODE_ENABLE_TELEMETRY=1","OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318"],"codex":["otel.exporter={otlp-http={…}}"],"notes":["Use a local endpoint in the tool configuration."]}}"#.into(),
    );
    model.accept(
        r#"{"v":1,"type":"batch","ts":"2026-01-01T14:05:01Z","seq":1,"signal":"logs","path":"/v1/logs","bytes":20431,"vendor":"claude-code","service":{"name":"claude-code","version":"2.1.316"},"catalog":"claude-code 2.1.316","records":12,"notInCatalog":1,"summary":{"identity":["user.email"],"resource":["host.arch"],"records":[{"name":"claude_code.tool_result","kind":"event","count":3,"known":true,"what":"A tool finished","attrs":[{"key":"tool_parameters","group":"content","flag":"OTEL_LOG_TOOL_DETAILS","known":true},{"key":"foo","group":null,"known":false}]}]},"resources":[]}"#.into(),
    );
    model.accept(
        r#"{"v":1,"type":"alert","ts":"2026-01-01T14:05:02Z","seq":1,"pattern":"aws-access-key","preset":true,"signal":"logs","event":"claude_code.tool_result","attribute":"tool_input","where":"value","count":2,"match":"AKI…(20 chars)"}"#.into(),
    );
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
            "to": "/home/demo/.local/state/cainary/otel-debug-ca.pem",
            "bundlePath": null,
            "command": null
        },
        "result": null,
        "noWriteAvailable": true,
        "noWriteCommand": "env NODE_EXTRA_CA_CERTS=/home/demo/.local/state/cainary/otel-debug-ca.pem claude"
    });
    serde_json::to_string(&view).expect("trust preview serializes")
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
        scenario(
            "details-collector",
            "details",
            ":collector",
            ready(CLAUDE),
            &defaults,
            false,
        ),
        scenario(
            "details-collector-trust-preview",
            "details",
            ":collector:trust-preview",
            ready(CLAUDE),
            &defaults,
            false,
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
            "settings",
            "settings",
            "",
            ScanState::Scanning { last: None },
            &defaults,
            false,
        ),
        scenario(
            "settings-https-takeover",
            "settings",
            "",
            ready(CLAUDE),
            &https_takeover,
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
