//! What the tray icon, its tooltip and menu, the popup and the Details window show for a scan
//! state. Pure functions of the report: the core already decided every level and summary.

use std::time::SystemTime;

use crate::level::Level;
use crate::report::Report;
use crate::store::ScanState;
use crate::strings;
use crate::tray_icon::{Badge, Look, TrayIcon};

/// The tray-wide view of a state.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub icon: TrayIcon,
    /// Entries at `low` or above, for the tooltip.
    pub count: usize,
    /// SNI tooltip body. The title is always `cAInary` on Linux.
    pub tooltip_body: String,
    /// One disabled menu row per entry: `Name: LABEL`.
    pub menu_rows: Vec<String>,
    pub can_copy: bool,
    pub scanning: bool,
}

pub fn summarize(state: &ScanState) -> Summary {
    let last = state.last_good();
    let mut s = match last {
        Some(snap) => from_report(&snap.report),
        None => Summary {
            icon: TrayIcon {
                look: Look::Template,
                badge: Badge::None,
            },
            count: 0,
            tooltip_body: "Scanning…".into(),
            menu_rows: vec!["Scanning…".into()],
            can_copy: false,
            scanning: false,
        },
    };
    s.scanning = state.is_scanning();
    if let ScanState::Failed { error, last } = state {
        s.icon = TrayIcon {
            look: Look::Template,
            badge: Badge::Unknown,
        };
        s.tooltip_body = format!("Couldn't scan: {}", error.reason());
        if last.is_none() {
            s.menu_rows = vec![format!("Couldn't scan: {}", error.reason())];
        }
    }
    s
}

fn from_report(report: &Report) -> Summary {
    let count = report
        .entries()
        .filter(|e| e.status.level >= Level::Low)
        .count();
    let icon = tray_icon(report, count);
    let mut tooltip_body = format!("{} · {}", report.status.label, report.status.summary);
    if count > 0 {
        let noun = if count == 1 { "tool" } else { "tools" };
        tooltip_body.push_str(&format!(" ({count} {noun} to review)"));
    }
    Summary {
        icon,
        count,
        tooltip_body,
        menu_rows: report
            .apps
            .iter()
            .filter(|e| e.installed)
            .chain(report.others.iter())
            .map(|e| {
                format!(
                    "{}: {}",
                    e.name,
                    level_label(&e.status.label, &e.status.level)
                )
            })
            .collect(),
        can_copy: true,
        scanning: false,
    }
}

/// The bird and badge for a report, as macOS's `MenuState(report:)`.
fn tray_icon(report: &Report, count: usize) -> TrayIcon {
    let (look, badge) = if !is_trusted(report) {
        (Look::Template, Badge::Unknown)
    } else {
        match report.status.level {
            Level::NotInstalled => (Look::TemplateDimmed, Badge::None),
            Level::Ok => (Look::Green, Badge::None),
            Level::OptedOut => (Look::Blue, Badge::None),
            ref level => {
                let look = match level {
                    Level::High => Look::Red,
                    Level::Medium => Look::Orange,
                    _ => Look::Yellow,
                };
                let badge = match count.min(9) {
                    0 => Badge::None,
                    n => Badge::Count(n as u8),
                };
                (look, badge)
            }
        }
    };
    TrayIcon { look, badge }
}

/// An incomplete scan below `low`, or any unknown level, cannot claim a trusted status.
pub fn is_trusted(report: &Report) -> bool {
    !report.status.level.is_unknown() && (report.complete || report.status.level >= Level::Low)
}

/// The display label shared by the tray summary and the QML view model.
pub fn level_label(label: &str, level: &Level) -> String {
    if label.is_empty() {
        strings::level_title(level.slug())
    } else {
        label.to_owned()
    }
}

/// "just now", "5 min ago", "2 h ago", "3 days ago".
pub fn ago(at: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(at).map(|d| d.as_secs()).unwrap_or(0);
    match secs {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86400 => format!("{} h ago", secs / 3600),
        _ => {
            let days = secs / 86400;
            format!("{days} day{} ago", if days == 1 { "" } else { "s" })
        }
    }
}
