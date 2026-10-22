//! Text report renderer (architecture.md §8.1): the `scan` text layout and the `sources` TSV.

use cainary_core::model::{
    ChangeKind, ChangeScope, Entry, Finding, Level, Origin, Report, ScannedSource, SourceState,
};

/// `NOT INSTALLED`, the longest level label.
const LEVEL_W: usize = 13;
/// `OPTED OUT`, the longest label in a finding line.
const FINDING_W: usize = 9;

struct Paint(bool);

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }

    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }

    fn level(&self, l: Level, s: &str) -> String {
        let code = match l {
            Level::High => "31",
            Level::Medium => "38;5;208",
            Level::Low => "33",
            Level::OptedOut => "34",
            Level::Ok => "32",
            Level::NotInstalled => "2",
        };
        self.wrap(code, s)
    }
}

/// The `scan` text report; ANSI colour only when `color` is true. `summary_only` stops after
/// the level-1 tables.
pub fn render(report: &Report, color: bool, summary_only: bool, width: usize) -> String {
    let p = Paint(color);
    let mut out = String::new();

    out.push_str(&format!(
        "cAInary · {} · {} · {}\n\n",
        match report.os {
            cainary_core::harness::platform::Os::Macos => "macOS",
            cainary_core::harness::platform::Os::Linux => "Linux",
        },
        timestamp(&report.scanned_at),
        if report.complete {
            "complete"
        } else {
            "incomplete"
        }
    ));
    let st = &report.status;
    out.push_str(&format!(
        "{}  {}\n",
        p.bold(&p.level(st.level, &st.label)),
        st.summary
    ));
    let unreadable: Vec<&ScannedSource> =
        report.sources.iter().filter(|s| is_unreadable(s)).collect();
    if !unreadable.is_empty() {
        let n = unreadable.len();
        let noun = if n == 1 { "source" } else { "sources" };
        out.push_str(&p.wrap("33", &format!("⚠ {n} {noun} unreadable")));
        out.push('\n');
    }

    changes_block(&mut out, report, &p);

    let name_w = report
        .apps
        .iter()
        .chain(&report.others)
        .map(|e| e.name.chars().count())
        .max()
        .unwrap_or(0);
    out.push_str(&format!("\n{}\n", p.bold("AI apps")));
    for e in &report.apps {
        out.push_str(&row(e, name_w, width, &p));
    }
    if !report.others.is_empty() {
        out.push_str(&format!(
            "\n{}\n",
            p.bold("Other monitoring on this device")
        ));
        for e in &report.others {
            out.push_str(&row(e, name_w, width, &p));
        }
    }
    if summary_only {
        return out;
    }

    let installed: Vec<&Entry> = report
        .apps
        .iter()
        .chain(&report.others)
        .filter(|e| e.installed && !e.findings.is_empty())
        .collect();
    if !installed.is_empty() {
        out.push_str(&format!("\n{}\n", "─".repeat(40)));
    }
    for (i, e) in installed.into_iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        block(&mut out, e, &p);
    }

    if !unreadable.is_empty() {
        out.push('\n');
        out.push_str(&p.bold("Unreadable sources"));
        out.push('\n');
        for s in unreadable {
            out.push_str(&format!(
                "  {} · {} — {}\n",
                s.tool.name(),
                s.source.path,
                unreadable_reason(s)
            ));
        }
    }
    out
}

/// The "Changes since" block of `--since` (architecture.md §8.1); nothing without `--since`.
fn changes_block(out: &mut String, report: &Report, p: &Paint) {
    let (Some(since), Some(changes)) = (&report.since, &report.changes) else {
        return;
    };
    if let Some(e) = &since.error {
        out.push_str(&format!("\nCan't compare with the baseline: {e}\n"));
        return;
    }
    let when = timestamp(&since.scanned_at);
    if changes.is_empty() {
        out.push_str(&format!("\nNo changes since {when}\n"));
        return;
    }
    out.push_str(&format!("\n{}\n", p.bold(&format!("Changes since {when}"))));
    let name_of = |id: &Option<String>| -> String {
        let Some(id) = id else { return String::new() };
        let entry = report
            .apps
            .iter()
            .chain(&report.others)
            .find(|e| e.id == *id);
        entry.map_or(id.clone(), |e| e.name.clone())
    };
    let level_of = |s: &Option<String>| s.as_deref().and_then(Level::from_slug);
    // marker, entry name, "FROM → TO" (levels only), line
    let rows: Vec<_> = changes
        .iter()
        .map(|c| {
            let marker = match c.kind {
                ChangeKind::Added => "+",
                ChangeKind::Removed => "-",
                ChangeKind::Raised => "↑",
                ChangeKind::Lowered => "↓",
                ChangeKind::Changed => "~",
            };
            let (from, to) = (level_of(&c.from), level_of(&c.to));
            let levels = match (c.scope, from, to) {
                (ChangeScope::Entry | ChangeScope::Finding, Some(f), Some(t)) => {
                    format!("{} → {}", f.label(), t.label())
                }
                (ChangeScope::Entry | ChangeScope::Finding, None, Some(t)) => t.label().into(),
                (ChangeScope::Entry | ChangeScope::Finding, Some(f), None) => f.label().into(),
                _ => String::new(),
            };
            let colour = to.or(from).filter(|_| !levels.is_empty());
            (marker, name_of(&c.entry), levels, colour, c.text.as_str())
        })
        .collect();
    let name_w = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0);
    let level_w = rows.iter().map(|r| r.2.chars().count()).max().unwrap_or(0);
    for (marker, name, levels, colour, text) in rows {
        let padded = format!("{levels:level_w$}");
        let levels = colour.map_or(padded.clone(), |l| p.level(l, &padded));
        let line = format!("  {marker} {name:name_w$}  {levels}  {text}");
        out.push_str(&format!("{}\n", line.trim_end()));
    }
}

/// `2026-10-21T16:40:00Z` → `2026-10-21 16:40 UTC`.
fn timestamp(rfc3339: &str) -> String {
    match rfc3339.get(..16) {
        Some(s) => format!("{} UTC", s.replace('T', " ")),
        None => rfc3339.to_string(),
    }
}

/// One line of the level-1 table.
fn row(e: &Entry, name_w: usize, width: usize, p: &Paint) -> String {
    let level = e.status.level;
    let label = p.level(level, &format!("{:LEVEL_W$}", e.status.label));
    let summary = if level == Level::NotInstalled {
        ""
    } else {
        &e.status.summary
    };
    // Indent, level, gap, name, gap: what the summary column starts after.
    let room = width.saturating_sub(2 + LEVEL_W + 2 + name_w + 2).max(10);
    let summary = if summary.chars().count() > room {
        let cut: String = summary.chars().take(room - 1).collect();
        format!("{}…", cut.trim_end())
    } else {
        summary.to_string()
    };
    format!("  {label}  {:name_w$}  {summary}\n", e.name)
        .trim_end()
        .to_string()
        + "\n"
}

/// One entry's level-2 and level-3 detail.
fn block(out: &mut String, e: &Entry, p: &Paint) {
    let level = e.status.level;
    let head = format!("{} — {} · {}", e.name, e.status.label, level.short());
    out.push_str(&p.bold(&p.level(level, &head)));
    out.push('\n');
    let mut about = Vec::new();
    if !e.surfaces.is_empty() {
        let names: Vec<&str> = e.surfaces.iter().map(|t| t.name()).collect();
        about.push(names.join(", "));
    }
    if !e.sends.is_empty() {
        let sends: Vec<&str> = e.sends.iter().map(|s| s.slug()).collect();
        about.push(format!("sends {}", sends.join(", ")));
    }
    if !about.is_empty() {
        out.push_str(&format!("  {}\n", about.join(" · ")));
    }
    // Findings from more than one surface: say which one each came from.
    let mut tools: Vec<_> = e.findings.iter().map(|f| f.tool).collect();
    tools.sort_by_key(|t| t.slug());
    tools.dedup();
    let multi = tools.len() > 1;
    for f in &e.findings {
        out.push('\n');
        finding(out, f, multi, p);
    }
    if !e.notes.is_empty() {
        out.push_str("\n  notes:\n");
        for n in &e.notes {
            out.push_str(&format!("    • {n}\n"));
        }
    }
}

fn set_by(o: Origin) -> &'static str {
    match o {
        Origin::Server => "organization (server-managed)",
        Origin::Mdm => "organization (MDM profile)",
        Origin::System => "organization (system config file)",
        Origin::OrgInstalled => "organization (installed by admin)",
        Origin::Unattributed => "unknown",
        Origin::Environment => "environment variable",
        Origin::User => "you",
        Origin::VendorDefault => "vendor default",
    }
}

fn finding(out: &mut String, f: &Finding, multi: bool, p: &Paint) {
    let level = f.level();
    let may = if f.best_effort { " (may)" } else { "" };
    let surface = if multi {
        format!("{}: ", f.tool.name())
    } else {
        String::new()
    };
    let label = if f.in_effect || level == Level::OptedOut {
        level.label()
    } else {
        "inactive"
    };
    let pad = " ".repeat(FINDING_W + 4);
    out.push_str(&format!(
        "  {}  {surface}{}{may}\n",
        p.level(level, &format!("{label:FINDING_W$}")),
        f.title
    ));
    if !f.detail.is_empty() {
        out.push_str(&format!("{pad}{}\n", f.detail));
    }
    let mut line = Vec::new();
    if !f.signals.is_empty() {
        let sends: Vec<&str> = f.signals.iter().map(|s| s.slug()).collect();
        line.push(format!("sends: {}", sends.join(", ")));
    }
    line.push(format!("set by: {}", set_by(f.source.origin)));
    out.push_str(&format!("{pad}{}\n", line.join(" · ")));
    out.push_str(&format!("{pad}config: {}\n", f.source.path));
    for e in &f.evidence {
        out.push_str(&format!("{pad}  {}\n", p.dim(e)));
    }
    if let Some(r) = &f.reference {
        out.push_str(&format!("{pad}docs: {r}\n"));
    }
}

/// `tool<TAB>origin<TAB>state<TAB>path` per source.
pub fn sources_tsv(report: &Report) -> String {
    let mut out = String::new();
    for s in &report.sources {
        let path = s.source.path.replace(['\t', '\n', '\r'], " ");
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            s.tool.slug(),
            s.source.origin.slug(),
            s.state.slug(),
            path
        ));
    }
    out
}

fn is_unreadable(s: &ScannedSource) -> bool {
    matches!(
        s.state,
        SourceState::Error | SourceState::Refused | SourceState::Capped
    )
}

fn unreadable_reason(s: &ScannedSource) -> String {
    let (label, default) = match s.state {
        SourceState::Refused => ("not read", "deliberately not read"),
        SourceState::Capped => (
            "capped",
            "listing too long; only the first entries were scanned",
        ),
        _ => ("error", "couldn't be read"),
    };
    match &s.note {
        Some(n) => format!("{label}: {n}"),
        None => format!("{label}: {default}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cainary_core::harness::platform::{EnvKind, Os};
    use cainary_core::model::{AlertMode, EntryKind, Signal, Source, SourceKind, Status, Tool};

    fn status(level: Level, summary: &str) -> Status {
        Status {
            level,
            label: level.label().into(),
            summary: summary.into(),
        }
    }

    fn finding_of(tool: Tool, title: &str, origin: Origin, signals: &[Signal]) -> Finding {
        let mut f = Finding {
            id: "x-1".into(),
            key: "x-1".into(),
            app: tool.app(),
            tool,
            agent: None,
            signals: signals.to_vec(),
            exposure: cainary_core::model::Exposure::Clear,
            title: title.into(),
            detail: String::new(),
            source: Source::new("~/.example/settings.json", origin, SourceKind::File),
            evidence: vec![],
            reference: None,
            best_effort: false,
            in_effect: true,
            counts: false,
        };
        f.finish();
        f
    }

    fn entry(id: &str, name: &str, kind: EntryKind, level: Level, summary: &str) -> Entry {
        Entry {
            id: id.into(),
            name: name.into(),
            kind,
            installed: level != Level::NotInstalled,
            status: status(level, summary),
            sends: vec![],
            surfaces: vec![],
            findings: vec![],
            notes: vec![],
        }
    }

    fn report() -> Report {
        let mut claude = entry(
            "claude",
            "Claude",
            EntryKind::App,
            Level::High,
            "hook gets prompts",
        );
        let mut hook = finding_of(
            Tool::ClaudeCode,
            "hook gets prompts",
            Origin::Mdm,
            &[Signal::Prompts],
        );
        hook.evidence = vec!["hooks.UserPromptSubmit = acme".into()];
        hook.reference = Some("https://example.com/hooks".into());
        let mut shadowed = finding_of(Tool::ClaudeDesktop, "shadowed", Origin::User, &[]);
        shadowed.in_effect = false;
        claude.findings = vec![hook, shadowed];
        claude.surfaces = vec![Tool::ClaudeCode, Tool::ClaudeDesktop];
        claude.sends = vec![Signal::Prompts];
        claude.notes = vec!["Server-managed settings can't be seen.".into()];
        let others = vec![entry(
            "acmecollector",
            "AcmeCollector",
            EntryKind::Monitor,
            Level::Medium,
            "can read all your files",
        )];
        Report {
            schema: 3,
            generator: "cainary 0.1.0".into(),
            scanned_at: "2026-10-21T16:40:00Z".into(),
            os: Os::Macos,
            env_kind: EnvKind::Shell,
            alert: AlertMode::OrgUnknown,
            complete: true,
            status: status(Level::High, "hook gets prompts"),
            apps: vec![
                claude,
                entry(
                    "openai",
                    "ChatGPT & Codex",
                    EntryKind::App,
                    Level::NotInstalled,
                    "",
                ),
            ],
            others,
            sources: vec![],
            since: None,
            changes: None,
        }
    }

    #[test]
    fn summary_has_both_tables() {
        let expected = "\
cAInary · macOS · 2026-10-21 16:40 UTC · complete

HIGH  hook gets prompts

AI apps
  HIGH           Claude           hook gets prompts
  NOT INSTALLED  ChatGPT & Codex

Other monitoring on this device
  MEDIUM         AcmeCollector    can read all your files
";
        assert_eq!(render(&report(), false, true, 100), expected);
    }

    #[test]
    fn details_follow_the_tables() {
        let out = render(&report(), false, false, 100);
        assert!(out.contains("Claude — HIGH · Conversations are sent\n"));
        assert!(out.contains("  Claude Code, Claude Desktop · sends prompts\n"));
        assert!(out.contains("  HIGH       Claude Code: hook gets prompts\n"));
        assert!(out.contains("             sends: prompts · set by: organization (MDM profile)\n"));
        assert!(out.contains("             config: ~/.example/settings.json\n"));
        assert!(out.contains("               hooks.UserPromptSubmit = acme\n"));
        assert!(out.contains("             docs: https://example.com/hooks\n"));
        assert!(out.contains("  inactive   Claude Desktop: shadowed\n"));
        assert!(out.contains("  notes:\n    • Server-managed settings can't be seen.\n"));
        // An entry with no findings gets no detail block.
        assert!(!out.contains("AcmeCollector —"));
        assert!(!out.contains("ChatGPT & Codex —"));
    }

    #[test]
    fn long_summaries_are_cut_to_the_width() {
        let out = render(&report(), false, true, 50);
        let line = out.lines().find(|l| l.contains("Claude  ")).unwrap();
        assert!(line.ends_with('…'));
        assert!(line.chars().count() <= 50);
        assert!(!render(&report(), false, true, 100).contains('…'));
    }

    #[test]
    fn set_by_uses_plain_words() {
        assert_eq!(set_by(Origin::Server), "organization (server-managed)");
        assert_eq!(set_by(Origin::System), "organization (system config file)");
        assert_eq!(
            set_by(Origin::OrgInstalled),
            "organization (installed by admin)"
        );
        assert_eq!(set_by(Origin::Environment), "environment variable");
    }

    #[test]
    fn colour_adds_ansi_only_when_asked() {
        let r = report();
        assert!(!render(&r, false, false, 100).contains('\x1b'));
        let c = render(&r, true, false, 100);
        assert!(c.contains("\x1b[31mHIGH         \x1b[0m"));
        assert!(c.contains("\x1b[38;5;208mMEDIUM       \x1b[0m"));
        assert!(c.contains("\x1b[2mNOT INSTALLED\x1b[0m"));
        // Stripping the escapes gives the plain report back.
        let mut plain = String::new();
        let mut chars = c.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                for n in chars.by_ref() {
                    if n == 'm' {
                        break;
                    }
                }
            } else {
                plain.push(ch);
            }
        }
        assert_eq!(plain, render(&r, false, false, 100));
    }

    #[test]
    fn unreadable_states_each_have_a_note() {
        let mut r = report();
        let mk = |state, note: Option<&str>| ScannedSource {
            tool: Tool::Cursor,
            source: Source::new("~/.cursor/a", Origin::User, SourceKind::File),
            state,
            note: note.map(String::from),
        };
        r.sources = vec![
            mk(SourceState::Error, None),
            mk(SourceState::Refused, Some("policy helper is never run")),
            mk(SourceState::Refused, None),
            mk(SourceState::Capped, Some("first 200 of 900")),
            mk(SourceState::Absent, None),
        ];
        let out = render(&r, false, false, 100);
        assert!(out.contains("⚠ 4 sources unreadable\n"));
        assert!(out.contains("  Cursor · ~/.cursor/a — error: couldn't be read\n"));
        assert!(out.contains("— not read: policy helper is never run\n"));
        assert!(out.contains("— not read: deliberately not read\n"));
        assert!(out.contains("— capped: first 200 of 900\n"));
        r.sources.truncate(1);
        assert!(render(&r, false, false, 100).contains("⚠ 1 source unreadable\n"));
    }

    #[test]
    fn tsv_lists_every_source() {
        let mut r = report();
        r.sources = vec![ScannedSource {
            tool: Tool::ClaudeCode,
            source: Source::new("~/.claude/settings.json", Origin::User, SourceKind::File),
            state: SourceState::Error,
            note: None,
        }];
        assert_eq!(
            sources_tsv(&r),
            "claude-code\tuser\terror\t~/.claude/settings.json\n"
        );
        assert_eq!(sources_tsv(&report()), "");
    }
}
