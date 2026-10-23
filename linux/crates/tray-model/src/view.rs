//! Pure JSON view model for the Linux QML UI. The core report remains the source of labels,
//! levels, summaries, finding text and changes; this module only shapes those values.
//!
//! The view is a tree of `Serialize` structs (the §4.4 contract); the key names are what the QML
//! reads. What changes on every scan event rather than with the report (`busy`, `phase`, the
//! last-checked time) is not in it: see [`status`].

use serde::Serialize;

use crate::level::Level;
use crate::report::{Change, Entry, Finding, PROBLEM_STATES, Report, SourceRecord};
use crate::settings::Settings;
use crate::store::ScanState;
use crate::strings::{self, ENVIRONMENT_NOTE};
use crate::summary;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub has_report: bool,
    pub trusted: bool,
    pub can_copy: bool,
    pub header: Header,
    pub failure: Option<FailureView>,
    pub changes: ChangesView,
    pub apps: Vec<MenuRow>,
    pub others: Vec<MenuRow>,
    pub not_installed_count: usize,
    pub not_installed_expanded: bool,
    pub entries: serde_json::Map<String, serde_json::Value>,
    pub default_selection: String,
    pub sources: Vec<SourceGroup>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub level: String,
    pub label: String,
    pub summary: String,
    pub scan_line: Vec<ScanLinePart>,
}

#[derive(Debug, Serialize)]
pub struct ScanLinePart {
    pub text: String,
    pub tone: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureView {
    pub reason: String,
    pub last_scan: String,
    pub banner: String,
}

#[derive(Debug, Serialize)]
pub struct ChangesView {
    pub title: String,
    pub rows: Vec<ChangeView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeView {
    pub marker: &'static str,
    pub subject: String,
    pub text: String,
    pub from_to: String,
}

/// A row of the popup list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MenuRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub icon_key: &'static str,
    pub level: String,
    pub label: String,
    pub summary: String,
    pub installed: bool,
    pub a11y: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub icon_key: &'static str,
    pub level: String,
    pub label: String,
    pub summary: String,
    pub installed: bool,
    pub reach: String,
    pub empty_text: String,
    pub active: Vec<FindingView>,
    pub inactive: Vec<FindingView>,
    pub notes: Vec<String>,
    pub environment_note: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingView {
    pub id: String,
    pub level: String,
    pub chip: String,
    pub tags: Vec<&'static str>,
    pub title: String,
    pub detail: String,
    pub sends: String,
    pub set_by: String,
    pub path: String,
    pub evidence: String,
    pub reveal_path: String,
    pub docs: String,
}

#[derive(Debug, Serialize)]
pub struct SourceGroup {
    pub surface: String,
    pub rows: Vec<SourceView>,
}

#[derive(Debug, Serialize)]
pub struct SourceView {
    pub path: String,
    pub icon: &'static str,
    pub status: String,
}

/// What the scan is doing, apart from the report: published as its own properties so that a
/// scan starting or ending doesn't rewrite the view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewStatus {
    pub busy: bool,
    /// `failed`, `ready` (there is a report, possibly stale) or `scanning`.
    pub phase: &'static str,
    /// The last good scan's time, as `format_time` renders it; empty with none.
    pub last_checked: String,
}

pub fn status(state: &ScanState, format_time: impl Fn(&str) -> String) -> ViewStatus {
    let report = state.last_good().map(|snapshot| &snapshot.report);
    let phase = if matches!(state, ScanState::Failed { .. }) {
        "failed"
    } else if report.is_some() {
        "ready"
    } else {
        "scanning"
    };
    ViewStatus {
        busy: state.is_scanning(),
        phase,
        last_checked: report
            .map(|report| formatted_time(&report.scanned_at, &format_time))
            .unwrap_or_default(),
    }
}

/// Builds the §4.4 JSON contract. `format_time` converts the report timestamp into the system
/// locale's short time; tests can use a stable formatter.
pub fn build(
    state: &ScanState,
    settings: &Settings,
    tracking_unavailable: bool,
    format_time: impl Fn(&str) -> String,
    resolve_reveal_path: impl Fn(&str, &str) -> String,
) -> String {
    let view = build_view(
        state,
        settings,
        tracking_unavailable,
        format_time,
        resolve_reveal_path,
    );
    serde_json::to_string(&view).expect("a view serializes")
}

/// [`build`], before it is turned into JSON.
pub fn build_view(
    state: &ScanState,
    settings: &Settings,
    tracking_unavailable: bool,
    format_time: impl Fn(&str) -> String,
    resolve_reveal_path: impl Fn(&str, &str) -> String,
) -> View {
    let snapshot = state.last_good().map(AsRef::as_ref);
    let report = snapshot.map(|snapshot| &snapshot.report);
    let failed = matches!(state, ScanState::Failed { .. });

    let failure = match state {
        ScanState::Failed { error, last } => {
            let time = last
                .as_ref()
                .map(|snapshot| formatted_time(&snapshot.report.scanned_at, &format_time))
                .unwrap_or_default();
            let banner = if time.is_empty() {
                "Couldn't scan".to_owned()
            } else {
                format!("Couldn't scan — showing results from {time}")
            };
            Some(FailureView {
                reason: error.reason(),
                last_scan: if time.is_empty() {
                    String::new()
                } else {
                    format!("Last scan at {time}")
                },
                banner,
            })
        }
        _ => None,
    };

    let header = if let Some(report) = report {
        let level = &report.status.level;
        let report_trusted = summary::is_trusted(report);
        let (header_level, label) = if !report_trusted && !report.complete {
            ("unknown".to_owned(), "Scan incomplete".to_owned())
        } else {
            (
                level.slug().to_owned(),
                summary::level_label(&report.status.label, level),
            )
        };
        let mut scan_line = Vec::new();
        let scanned = formatted_time(&report.scanned_at, &format_time);
        if !scanned.is_empty() {
            scan_line.push(ScanLinePart {
                text: format!("Scanned {scanned}"),
                tone: "secondary",
            });
        }
        let problem_count = report.problem_sources().count();
        if problem_count > 0 {
            let noun = if problem_count == 1 {
                "location"
            } else {
                "locations"
            };
            scan_line.push(ScanLinePart {
                text: format!("⚠ {problem_count} {noun} couldn't be read"),
                tone: "warning",
            });
        }
        if tracking_unavailable {
            scan_line.push(ScanLinePart {
                text: "Change tracking unavailable".into(),
                tone: "secondary",
            });
        }
        Header {
            level: header_level,
            label,
            summary: report.status.summary.clone(),
            scan_line,
        }
    } else {
        Header {
            level: "unknown".into(),
            label: if failed {
                "Couldn't scan"
            } else {
                "Scanning…"
            }
            .into(),
            summary: match state {
                ScanState::Failed { error, .. } => error.reason(),
                _ => String::new(),
            },
            scan_line: Vec::new(),
        }
    };

    let apps = report
        .map(|r| r.apps.iter().map(row).collect::<Vec<_>>())
        .unwrap_or_default();
    let others = report
        .map(|r| r.others.iter().map(row).collect::<Vec<_>>())
        .unwrap_or_default();
    let not_installed_count = report
        .map(|r| r.apps.iter().filter(|entry| !entry.installed).count())
        .unwrap_or_default();
    let default_selection = report
        .and_then(|r| {
            r.apps
                .iter()
                .find(|entry| entry.installed)
                .or_else(|| r.entries().next())
        })
        .map(|entry| entry.id.clone())
        .unwrap_or_default();

    let entries = report
        .map(|r| {
            r.entries()
                .map(|entry| {
                    let view = entry_view(entry, &resolve_reveal_path);
                    (
                        entry.id.clone(),
                        serde_json::to_value(view).expect("an entry serializes"),
                    )
                })
                .collect::<serde_json::Map<_, _>>()
        })
        .unwrap_or_default();

    let changes = report
        .map(|r| changes_view(r, &format_time))
        .unwrap_or_else(|| ChangesView {
            title: "Changes".into(),
            rows: Vec::new(),
        });
    let sources = report.map(sources_view).unwrap_or_default();
    let trusted = report.is_some_and(summary::is_trusted);

    View {
        has_report: report.is_some(),
        trusted,
        can_copy: report.is_some(),
        header,
        failure,
        changes,
        apps,
        others,
        not_installed_count,
        not_installed_expanded: settings.not_installed_expanded,
        entries,
        default_selection,
        sources,
    }
}

fn row(entry: &Entry) -> MenuRow {
    let label = summary::level_label(&entry.status.label, &entry.status.level);
    MenuRow {
        id: entry.id.clone(),
        name: entry.name.clone(),
        kind: entry.kind.clone(),
        icon_key: icon_key(entry),
        level: entry.status.level.slug().to_owned(),
        a11y: format!("{}: {}. {}", entry.name, label, entry.status.summary),
        label,
        summary: entry.status.summary.clone(),
        installed: entry.installed,
    }
}

fn entry_view(entry: &Entry, resolve_reveal_path: &impl Fn(&str, &str) -> String) -> EntryView {
    let active = entry
        .findings
        .iter()
        .filter(|finding| finding.in_effect)
        .map(|finding| finding_view(entry, finding, resolve_reveal_path))
        .collect::<Vec<_>>();
    let inactive = entry
        .findings
        .iter()
        .filter(|finding| !finding.in_effect)
        .map(|finding| finding_view(entry, finding, resolve_reveal_path))
        .collect::<Vec<_>>();
    let surfaces = entry
        .surfaces
        .iter()
        .map(|surface| strings::surface_name(surface))
        .collect::<Vec<_>>();
    let sends = entry
        .sends
        .iter()
        .map(|signal| strings::signal_name(signal))
        .collect::<Vec<_>>();
    let reach = match (surfaces.is_empty(), sends.is_empty()) {
        (false, false) => format!("{} · sends: {}", surfaces.join(", "), sends.join(", ")),
        (false, true) => surfaces.join(", "),
        (true, false) => format!("sends: {}", sends.join(", ")),
        (true, true) => String::new(),
    };
    let empty_text = if !entry.installed {
        format!("{} isn't on this computer.", entry.name)
    } else if entry.findings.is_empty() {
        format!("Nothing found for {} on this computer.", entry.name)
    } else {
        String::new()
    };
    // As on macOS: every installed app, since the tray always scans the session's environment.
    let environment_note = if entry.kind == "app" && entry.installed {
        ENVIRONMENT_NOTE
    } else {
        ""
    };

    EntryView {
        id: entry.id.clone(),
        name: entry.name.clone(),
        kind: entry.kind.clone(),
        icon_key: icon_key(entry),
        level: entry.status.level.slug().to_owned(),
        label: summary::level_label(&entry.status.label, &entry.status.level),
        summary: entry.status.summary.clone(),
        installed: entry.installed,
        reach,
        empty_text,
        active,
        inactive,
        notes: entry.notes.clone(),
        environment_note,
    }
}

fn finding_view(
    entry: &Entry,
    finding: &Finding,
    resolve_reveal_path: &impl Fn(&str, &str) -> String,
) -> FindingView {
    let mut title = finding.title.clone();
    if entry.surfaces.len() > 1 && !finding.surface.is_empty() {
        title = format!("{}: {title}", strings::surface_name(&finding.surface));
    }
    let mut tags = Vec::new();
    if finding.maybe {
        tags.push("may");
    }
    if finding.set_by == "user" {
        tags.push("set by you");
    }
    let sends = finding
        .sends
        .iter()
        .map(|signal| strings::signal_name(signal))
        .collect::<Vec<_>>();
    let set_by = if finding.set_by.is_empty() {
        String::new()
    } else {
        format!("Set by: {}", strings::origin_phrase(&finding.set_by))
    };
    let chip = if !finding.in_effect && finding.level == Level::Ok {
        "inactive".to_owned()
    } else {
        summary::level_label("", &finding.level)
    };
    let evidence = finding.config.evidence.join("\n");
    let docs = finding
        .docs
        .as_deref()
        .filter(|url| is_web_url(url))
        .unwrap_or("");

    FindingView {
        id: finding.id.clone(),
        level: finding.level.slug().to_owned(),
        chip,
        tags,
        title,
        detail: finding.detail.clone(),
        sends: if sends.is_empty() {
            String::new()
        } else {
            format!("Sends: {}", sends.join(", "))
        },
        set_by,
        path: finding.config.path.clone(),
        evidence,
        reveal_path: resolve_reveal_path(&finding.config.kind, &finding.config.path),
        docs: docs.to_owned(),
    }
}

fn changes_view(report: &Report, format_time: &impl Fn(&str) -> String) -> ChangesView {
    let since = report
        .since
        .as_ref()
        .map(|since| since.scanned_at.as_str())
        .map(|at| formatted_time(at, format_time))
        .filter(|at| !at.is_empty());
    let title = since
        .as_deref()
        .map(|at| format!("Changes since {at}"))
        .unwrap_or_else(|| "Changes".to_owned());
    let rows = report
        .changes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|change| change_view(report, change))
        .collect::<Vec<_>>();
    ChangesView { title, rows }
}

fn change_view(report: &Report, change: &Change) -> ChangeView {
    let subject = if change.scope == "report" {
        "Scan"
    } else {
        change
            .entry
            .as_deref()
            .and_then(|id| report.entry(id))
            .map(|entry| entry.name.as_str())
            .unwrap_or("Scan")
    };
    let from_to = match (change.from.as_deref(), change.to.as_deref()) {
        (Some(from), Some(to)) => format!(
            "{} → {}",
            strings::level_title(from),
            strings::level_title(to)
        ),
        _ => String::new(),
    };
    let marker = match change.kind.as_str() {
        "added" => "+",
        "removed" => "−",
        "raised" => "↑",
        "lowered" => "↓",
        "changed" => "~",
        _ => "•",
    };
    ChangeView {
        marker,
        subject: subject.to_owned(),
        text: change.text.clone(),
        from_to,
    }
}

fn sources_view(report: &Report) -> Vec<SourceGroup> {
    let mut groups: Vec<SourceGroup> = Vec::new();
    for source in &report.sources {
        let surface = strings::surface_name(&source.tool);
        let row = source_view(source);
        if let Some(group) = groups.iter_mut().find(|group| group.surface == surface) {
            group.rows.push(row);
        } else {
            groups.push(SourceGroup {
                surface,
                rows: vec![row],
            });
        }
    }
    groups
}

/// A source row, as macOS `DetailView` draws it: a warning for problem states, a check for
/// `present`, a dashed circle for everything else; the status is the state slug and its note.
fn source_view(source: &SourceRecord) -> SourceView {
    let state = source.state.as_str();
    let icon = if PROBLEM_STATES.contains(&state) {
        "problem"
    } else if state == "present" {
        "present"
    } else {
        "neutral"
    };
    let mut chars = state.chars();
    let mut status: String = chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    if let Some(note) = source.note.as_deref().filter(|note| !note.is_empty()) {
        status = format!("{status}: {note}");
    }
    SourceView {
        path: source.source.path.clone(),
        icon,
        status,
    }
}

fn icon_key(entry: &Entry) -> &'static str {
    match entry.id.as_str() {
        "claude" => "claude",
        "openai" => "openai",
        "cursor" => "cursor",
        "copilot" => "copilot",
        "device" => "device",
        "device-management" => "device-management",
        "network-proxy" => "network-proxy",
        _ => "shield",
    }
}

fn formatted_time(timestamp: &str, format_time: &impl Fn(&str) -> String) -> String {
    if timestamp.is_empty() {
        return String::new();
    }
    format_time(timestamp)
}

fn is_web_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::report::Report;
    use crate::store::Snapshot;

    /// `build`, parsed back: the tests read the keys the QML reads.
    fn built(
        state: &ScanState,
        settings: &Settings,
        tracking_unavailable: bool,
        format_time: impl Fn(&str) -> String,
    ) -> serde_json::Value {
        let json = build(
            state,
            settings,
            tracking_unavailable,
            format_time,
            |_, _| String::new(),
        );
        serde_json::from_str(&json).unwrap()
    }

    fn settings() -> Settings {
        Settings::default()
    }

    fn state(name: &str) -> ScanState {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../crates/cainary-core/tests/golden")
            .join(name);
        let raw = std::fs::read(path).unwrap();
        let report = Report::decode(&raw).unwrap();
        ScanState::Ready(Arc::new(Snapshot {
            report,
            raw,
            at: SystemTime::UNIX_EPOCH,
        }))
    }

    #[test]
    fn claude_golden_shapes_the_popup_and_entry_contract() {
        let v = built(&state("claude-code-linux.json"), &settings(), false, |_| {
            "14:05".into()
        });
        assert_eq!(v["apps"][0]["label"], "MEDIUM");
        assert!(v["notInstalledCount"].as_u64().unwrap() >= 1);
        assert_eq!(v["defaultSelection"], "claude");
        assert_eq!(
            v["entries"]["openai"]["emptyText"],
            "ChatGPT & Codex isn't on this computer."
        );
        assert_eq!(v["header"]["scanLine"][0]["text"], "Scanned 14:05");
        assert_eq!(
            v["entries"]["claude"]["active"][0]["sends"],
            "Sends: traffic"
        );
    }

    #[test]
    fn empty_and_device_goldens_keep_their_entry_and_source_shapes() {
        let empty = built(&state("empty-linux.json"), &settings(), false, |_| {
            "10:30".into()
        });
        assert!(empty["hasReport"].as_bool().unwrap());
        assert!(empty.get("phase").is_none() && empty.get("busy").is_none());
        assert_eq!(empty["changes"]["rows"].as_array().unwrap().len(), 0);
        let device = built(&state("device-linux.json"), &settings(), false, |_| {
            "10:30".into()
        });
        assert!(device["entries"]["device"].is_object());
        assert_eq!(device["entries"]["device"]["iconKey"], "device");
        assert!(device["sources"].is_array());
    }

    #[test]
    fn unknown_scope_and_kind_have_safe_change_presentation() {
        let change = Change {
            id: "x".into(),
            scope: "future".into(),
            entry: None,
            key: None,
            kind: "future-kind".into(),
            from: None,
            to: None,
            notify: false,
            text: "New change".into(),
        };
        let report = Report::decode(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../crates/cainary-core/tests/golden/empty-linux.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(change_view(&report, &change).marker, "•");
        assert_eq!(change_view(&report, &change).subject, "Scan");
    }

    fn source(state: &str, note: Option<&str>) -> SourceRecord {
        serde_json::from_value(serde_json::json!({
            "tool": "claude-code",
            "source": {"path": "/x"},
            "state": state,
            "note": note,
        }))
        .unwrap()
    }

    #[test]
    fn source_rows_follow_the_macos_detail_view() {
        for (state, note, icon, status) in [
            ("absent", None, "neutral", "Absent"),
            ("quarantined", None, "neutral", "Quarantined"),
            ("error", Some("x"), "problem", "Error: x"),
            ("refused", None, "problem", "Refused"),
            ("capped", Some(""), "problem", "Capped"),
            ("present", None, "present", "Present"),
        ] {
            let row = source_view(&source(state, note));
            assert_eq!(row.icon, icon, "{state}");
            assert_eq!(row.status, status, "{state}");
        }
    }

    #[test]
    fn the_environment_note_is_on_installed_apps_only() {
        let report = Report::decode(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../crates/cainary-core/tests/golden/claude-code-linux.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut entry = report
            .apps
            .iter()
            .find(|e| e.installed)
            .expect("an installed app")
            .clone();
        entry.kind = "app".into();
        entry.findings.clear();
        let note = |entry: &Entry| entry_view(entry, &|_, _| String::new()).environment_note;
        assert_eq!(note(&entry), ENVIRONMENT_NOTE);
        let mut absent = entry.clone();
        absent.installed = false;
        assert_eq!(note(&absent), "");
        let mut other = entry;
        other.kind = "device".into();
        assert_eq!(note(&other), "");
    }

    #[test]
    fn status_splits_scan_activity_from_the_view() {
        let ready = state("claude-code-linux.json");
        let s = status(&ready, |_| "14:05".into());
        assert_eq!(
            s,
            ViewStatus {
                busy: false,
                phase: "ready",
                last_checked: "14:05".into()
            }
        );
        let ScanState::Ready(snapshot) = ready else {
            unreachable!()
        };
        let scanning = ScanState::Scanning {
            last: Some(snapshot.clone()),
        };
        assert!(status(&scanning, |_| "x".into()).busy);
        let first = ScanState::Scanning { last: None };
        let s = status(&first, |_| "x".into());
        assert_eq!(
            (s.busy, s.phase, s.last_checked.as_str()),
            (true, "scanning", "")
        );
        let failed = ScanState::Failed {
            error: crate::runner::ScanError::TimedOut,
            last: Some(snapshot),
        };
        assert_eq!(status(&failed, |_| "x".into()).phase, "failed");
    }
}
