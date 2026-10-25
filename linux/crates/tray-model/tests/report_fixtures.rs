//! Every core golden report decodes, and the summaries built from them hold together.

mod common;

use std::time::SystemTime;

use cainary_tray_model::level::Level;
use cainary_tray_model::report::{DecodeError, Report};
use cainary_tray_model::settings::Settings;
use cainary_tray_model::store::{ScanState, Snapshot};
use cainary_tray_model::summary::summarize;
use cainary_tray_model::tray_icon::{Badge, IconStyle, Look, TrayIcon};
use cainary_tray_model::view;
use serde_json::json;

fn ready(report: Report) -> ScanState {
    ScanState::Ready(std::sync::Arc::new(Snapshot {
        raw: Vec::new(),
        report,
        at: SystemTime::now(),
    }))
}

#[test]
fn every_golden_report_decodes() {
    let dir = common::repo().join("crates/cainary-core/tests/golden");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let report = Report::decode(&bytes).unwrap_or_else(|e| panic!("{path:?}: {e:?}"));
        let findings: usize = report.entries().map(|e| e.findings.len()).sum();
        let state = ready(report);
        let built = view::build_view(
            &state,
            &Settings::default(),
            false,
            |_| String::new(),
            |_, _| String::new(),
        );
        let shown: usize = built
            .entries
            .values()
            .map(|e| {
                e["active"].as_array().unwrap().len() + e["inactive"].as_array().unwrap().len()
            })
            .sum();
        assert_eq!(shown, findings, "{path:?}");
        seen += 1;
    }
    assert!(seen > 10, "only {seen} goldens");
}

#[test]
fn a_medium_report_is_a_warning_with_a_count() {
    let bytes = std::fs::read(common::golden("claude-code-linux.json")).unwrap();
    let report = Report::decode(&bytes).unwrap();
    assert_eq!(report.status.level, Level::Medium);
    assert_eq!(report.entries().next().unwrap().id, "claude");
    let s = summarize(&ready(report));
    assert_eq!(
        s.icon,
        TrayIcon {
            look: Look::Orange,
            badge: Badge::Count(1)
        }
    );
    assert_eq!(s.count, 1);
    assert!(s.tooltip_body.starts_with("MEDIUM · "));
    assert_eq!(s.menu_rows[0], "Claude: MEDIUM");
}

#[test]
fn unknown_levels_and_incomplete_scans_show_a_question_mark() {
    let mut v = common::golden_json("claude-code-linux.json");
    v["status"]["level"] = json!("critical");
    let report = Report::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(report.status.level, Level::Unknown("critical".into()));
    assert!(report.status.level < Level::NotInstalled);
    assert_eq!(summarize(&ready(report)).icon, UNKNOWN);

    let mut v = common::golden_json("empty-linux.json");
    v["complete"] = json!(false);
    let report = Report::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(report.status.level < Level::Low);
    assert_eq!(summarize(&ready(report)).icon, UNKNOWN);
}

#[test]
fn schema_is_checked_before_shape() {
    assert_eq!(
        Report::decode(br#"{"schema":4,"whatever":true}"#),
        Err(DecodeError::UnsupportedSchema(4))
    );
    assert!(matches!(
        Report::decode(br#"{"schema":3}"#),
        Err(DecodeError::BadJson(_))
    ));
    assert!(matches!(
        Report::decode(b"nope"),
        Err(DecodeError::BadJson(_))
    ));
}

#[test]
fn first_scan_and_failures_have_their_own_looks() {
    let s = summarize(&ScanState::Scanning { last: None });
    assert_eq!(
        s.icon,
        TrayIcon {
            look: Look::Template,
            badge: Badge::None
        }
    );
    let s = summarize(&ScanState::Failed {
        error: cainary_tray_model::runner::ScanError::TimedOut,
        last: None,
    });
    assert_eq!(s.icon, UNKNOWN);
    assert_eq!(s.menu_rows, ["Couldn't scan: the scanner took too long"]);
}

const UNKNOWN: TrayIcon = TrayIcon {
    look: Look::Template,
    badge: Badge::Unknown,
};

#[test]
fn icon_names_follow_the_theme_convention() {
    let medium = TrayIcon {
        look: Look::Orange,
        badge: Badge::Count(3),
    };
    assert_eq!(
        medium.name(IconStyle::Monochrome),
        "ua.SkeLLLa.cAInary.tray-plain-orange3-symbolic"
    );
    assert_eq!(
        medium.name(IconStyle::Color),
        "ua.SkeLLLa.cAInary.tray-color-orange3"
    );
    assert_eq!(
        UNKNOWN.name(IconStyle::Color),
        "ua.SkeLLLa.cAInary.tray-plain-unknown-symbolic"
    );
}

/// The wire's `alert` is the core's alert mode (what counts toward alerts), not a level, so the
/// tray ignores it. What the tray does read as the overall level is `status.level`: for every
/// golden the badge must be that level's look (`unknown` when the scan can't be trusted), and
/// `alert` must stay a mode the tray knows to ignore. A core change to either shows up here.
#[test]
fn the_wire_alert_and_overall_level_agree_with_the_tray_summary() {
    let dir = common::repo().join("crates/cainary-core/tests/golden");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let alert = wire["alert"].as_str().unwrap_or_default();
        assert!(
            ["org", "org-unknown", "everything"].contains(&alert),
            "{path:?}: unknown alert mode {alert:?}"
        );
        let level = Level::from_slug(wire["status"]["level"].as_str().unwrap());
        let report = Report::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
        assert_eq!(report.status.level, level, "{path:?}");
        let untrusted = level.is_unknown() || (!report.complete && level < Level::Low);
        let icon = summarize(&ready(report)).icon;
        if untrusted {
            assert_eq!(icon, UNKNOWN, "{path:?}");
        } else {
            let look = match level {
                Level::NotInstalled => Look::TemplateDimmed,
                Level::Ok => Look::Green,
                Level::OptedOut => Look::Blue,
                Level::High => Look::Red,
                Level::Medium => Look::Orange,
                _ => Look::Yellow,
            };
            assert_eq!(icon.look, look, "{path:?}");
        }
        seen += 1;
    }
    assert!(seen > 10, "only {seen} goldens");
}
