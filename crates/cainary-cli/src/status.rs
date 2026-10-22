//! Status-line renderer (architecture.md §8.2). It only renders the `Report`'s overall level.

use cainary_core::model::{Entry, Level, Report};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Emoji,
    Text,
    Nerd,
    Json,
}

// Nerd Font Material Design glyphs (docs/integrations.md, "Nerd Font glyphs").
const NERD_HIGH: char = '\u{F0208}'; // nf-md-eye
const NERD_MEDIUM: char = '\u{F018D}'; // nf-md-console
const NERD_LOW: char = '\u{F0128}'; // nf-md-chart_bar
const NERD_OK: char = '\u{F05E0}'; // nf-md-check_circle
const NERD_NONE: char = '\u{F0130}'; // nf-md-checkbox_blank_circle_outline
const NERD_WARN: char = '\u{F0028}'; // nf-md-alert_circle
const NERD_INCOMPLETE: char = '\u{F02D7}'; // nf-md-help_circle

fn entries(report: &Report) -> impl Iterator<Item = &Entry> {
    report.apps.iter().chain(&report.others)
}

/// Nothing is sent and the scan is incomplete: it can't vouch for "OK" or "not installed".
fn only_incomplete(report: &Report) -> bool {
    !report.complete && report.status.level < Level::Low
}

/// The one-line word for the emoji form.
fn word(report: &Report) -> &'static str {
    if only_incomplete(report) {
        return "INCOMPLETE";
    }
    match report.status.level {
        Level::High => "HIGH",
        Level::Medium => "MEDIUM",
        Level::Low => "LOW",
        Level::OptedOut => "OPTED OUT",
        Level::Ok => "OK",
        Level::NotInstalled => "NO AI APPS",
    }
}

/// The number of entries at `low` or above.
fn badge(report: &Report) -> usize {
    entries(report)
        .filter(|e| e.status.level >= Level::Low)
        .count()
}

/// The entry count, shown only when two or more entries are at `low` or above.
fn count(report: &Report) -> Option<usize> {
    Some(badge(report)).filter(|&n| n >= 2)
}

pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Emoji => emoji(report),
        Format::Text => text(report),
        Format::Nerd => nerd(report),
        Format::Json => json(report),
    }
}

fn emoji(report: &Report) -> String {
    if only_incomplete(report) {
        return "❔ INCOMPLETE".to_string();
    }
    let icon = match report.status.level {
        Level::High => "🔴",
        Level::Medium => "🟠",
        Level::Low => "🟡",
        Level::OptedOut => "🔵",
        Level::Ok => "🟢",
        Level::NotInstalled => "⚪",
    };
    let mut line = format!("{icon} {}", word(report));
    if let Some(n) = count(report) {
        line.push_str(&format!(" ({n})"));
    }
    if !report.complete {
        line.push_str(" ⚠");
    }
    line
}

fn text(report: &Report) -> String {
    if only_incomplete(report) {
        return "ai:incomplete".to_string();
    }
    let mut line = format!("ai:{}", report.status.level.slug());
    if let Some(n) = count(report) {
        line.push_str(&format!(":{n}"));
    }
    if !report.complete {
        line.push_str(" !incomplete");
    }
    line
}

fn nerd(report: &Report) -> String {
    if only_incomplete(report) {
        return NERD_INCOMPLETE.to_string();
    }
    let glyph = match report.status.level {
        Level::High => NERD_HIGH,
        Level::Medium => NERD_MEDIUM,
        Level::Low => NERD_LOW,
        Level::OptedOut | Level::Ok => NERD_OK,
        Level::NotInstalled => NERD_NONE,
    };
    let mut line = glyph.to_string();
    if let Some(n) = count(report) {
        line.push_str(&format!(" {n}"));
    }
    if !report.complete {
        line.push(' ');
        line.push(NERD_WARN);
    }
    line
}

/// One line: `{"schema":3,"level","label","badge","complete","entries":{id:{"level","installed"}}}`.
/// The entries map holds every app and monitor entry in the report.
fn json(report: &Report) -> String {
    let mut map = Map::new();
    for e in entries(report) {
        map.insert(
            e.id.clone(),
            json!({"level": e.status.level.slug(), "installed": e.installed}),
        );
    }
    let mut doc = Map::new();
    doc.insert("schema".into(), json!(cainary_core::model::SCHEMA));
    doc.insert("level".into(), json!(report.status.level.slug()));
    doc.insert("label".into(), json!(report.status.label));
    doc.insert("badge".into(), json!(badge(report)));
    doc.insert("complete".into(), json!(report.complete));
    doc.insert("entries".into(), Value::Object(map));
    Value::Object(doc).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cainary_core::harness::platform::{EnvKind, Os};
    use cainary_core::model::{AlertMode, App, EntryKind, Status};

    fn status(level: Level) -> Status {
        Status {
            level,
            label: level.label().into(),
            summary: String::new(),
        }
    }

    fn entry(id: &str, kind: EntryKind, level: Level) -> Entry {
        Entry {
            id: id.into(),
            name: id.into(),
            kind,
            installed: level != Level::NotInstalled,
            status: status(level),
            sends: vec![],
            surfaces: vec![],
            findings: vec![],
            notes: vec![],
        }
    }

    /// `badge` app entries at `level` (when it is `low` or above), the rest not installed.
    fn report(level: Level, badge: usize, complete: bool) -> Report {
        let apps = App::ALL
            .iter()
            .filter(|&&a| a != App::Device)
            .enumerate()
            .map(|(i, a)| {
                let l = if i < badge {
                    level
                } else {
                    Level::NotInstalled
                };
                entry(a.slug(), EntryKind::App, l)
            })
            .collect();
        Report {
            schema: 3,
            generator: "cainary 0.1.0".into(),
            scanned_at: "2026-10-21T12:00:00Z".into(),
            os: Os::Macos,
            env_kind: EnvKind::Shell,
            alert: AlertMode::OrgUnknown,
            complete,
            status: status(level),
            apps,
            others: vec![],
            sources: vec![],
            since: None,
            changes: None,
        }
    }

    fn lines(r: &Report) -> [String; 3] {
        [
            render(r, Format::Emoji),
            render(r, Format::Text),
            render(r, Format::Nerd),
        ]
    }

    #[test]
    fn every_level_complete() {
        let cases = [
            (Level::High, "🔴 HIGH", "ai:high", "\u{F0208}"),
            (Level::Medium, "🟠 MEDIUM", "ai:medium", "\u{F018D}"),
            (Level::Low, "🟡 LOW", "ai:low", "\u{F0128}"),
            (Level::OptedOut, "🔵 OPTED OUT", "ai:opted-out", "\u{F05E0}"),
            (Level::Ok, "🟢 OK", "ai:ok", "\u{F05E0}"),
            (
                Level::NotInstalled,
                "⚪ NO AI APPS",
                "ai:not-installed",
                "\u{F0130}",
            ),
        ];
        for (l, emoji, text, nerd) in cases {
            let badge = usize::from(l >= Level::Low);
            assert_eq!(lines(&report(l, badge, true)), [emoji, text, nerd], "{l:?}");
        }
    }

    #[test]
    fn badge_one_versus_three() {
        let one = report(Level::Medium, 1, true);
        assert_eq!(lines(&one), ["🟠 MEDIUM", "ai:medium", "\u{F018D}"]);
        let three = report(Level::Medium, 3, true);
        assert_eq!(
            lines(&three),
            ["🟠 MEDIUM (3)", "ai:medium:3", "\u{F018D} 3"]
        );
    }

    #[test]
    fn badge_counts_monitors_too() {
        let mut r = report(Level::High, 1, true);
        r.others
            .push(entry("zscaler", EntryKind::Monitor, Level::Medium));
        r.others
            .push(entry("device", EntryKind::Monitor, Level::Ok));
        assert_eq!(badge(&r), 2);
    }

    #[test]
    fn incomplete_with_nothing_sent() {
        for l in [Level::Ok, Level::OptedOut, Level::NotInstalled] {
            assert_eq!(
                lines(&report(l, 0, false)),
                ["❔ INCOMPLETE", "ai:incomplete", "\u{F02D7}"],
                "{l:?}"
            );
        }
    }

    #[test]
    fn incomplete_with_alerts() {
        assert_eq!(
            lines(&report(Level::High, 1, false)),
            ["🔴 HIGH ⚠", "ai:high !incomplete", "\u{F0208} \u{F0028}"]
        );
        assert_eq!(
            render(&report(Level::Low, 1, false), Format::Emoji),
            "🟡 LOW ⚠"
        );
    }

    #[test]
    fn json_is_one_line_with_ordered_keys() {
        let mut r = report(Level::Medium, 1, false);
        r.others
            .push(entry("zscaler", EntryKind::Monitor, Level::Medium));
        let s = render(&r, Format::Json);
        assert!(!s.contains('\n'));
        let expected = concat!(
            r#"{"schema":3,"level":"medium","label":"MEDIUM","badge":2,"complete":false,"#,
            r#""entries":{"#,
            r#""claude":{"level":"medium","installed":true},"#,
            r#""openai":{"level":"not-installed","installed":false},"#,
            r#""cursor":{"level":"not-installed","installed":false},"#,
            r#""copilot":{"level":"not-installed","installed":false},"#,
            r#""zscaler":{"level":"medium","installed":true}}}"#,
        );
        assert_eq!(s, expected);
    }
}
