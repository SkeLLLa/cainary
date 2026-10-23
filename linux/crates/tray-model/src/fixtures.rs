//! The scenarios the self-test, the dev harness and `SampleView.js` share. Each one is a core
//! golden report, unmodified except for the change records of `details-changes`, in a scan state
//! and with the settings a window is shown with. Reports are never merged, so every view is
//! internally consistent.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

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
    /// What Details selects: `""` (the default entry), `":changes"` or `":sources"`.
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
