//! What changed between two reports (architecture.md §4.2).

use crate::model::{
    Change, ChangeKind, ChangeScope, Entry, EntryKind, Finding, Level, Report, SCHEMA,
    ScannedSource, Since, SourceState, Tool,
};
use crate::redact;
use std::collections::{HashMap, HashSet};

/// Diff `new` against the baseline `old`: notifying changes first, then report entry order,
/// then scope (entry, finding, source, report).
pub fn diff(old: &Report, new: &Report) -> Vec<Change> {
    let new_entries: Vec<&Entry> = new.apps.iter().chain(&new.others).collect();
    let old_entries: Vec<&Entry> = old.apps.iter().chain(&old.others).collect();
    let pos = |id: &str| {
        new_entries
            .iter()
            .position(|e| e.id == id)
            .unwrap_or(new_entries.len())
    };
    // (position, change); position only orders, scope rank is derived from the change.
    let mut out: Vec<(usize, Change)> = Vec::new();

    for (i, n) in new_entries.iter().enumerate() {
        match old_entries.iter().find(|o| o.id == n.id) {
            Some(o) => {
                entry_change(o, n, &mut out, i);
                findings_change(o, n, new, &mut out, i);
            }
            None if n.kind == EntryKind::Monitor => {
                let to = n.status.level;
                out.push((
                    i,
                    change(
                        ChangeScope::Entry,
                        Some(&n.id),
                        None,
                        ChangeKind::Added,
                        None,
                        Some(to.slug()),
                        to >= Level::Low,
                        format!("New monitor {}: {}", n.name, n.status.summary),
                    ),
                ));
            }
            None => {}
        }
    }
    for (i, o) in old_entries.iter().enumerate() {
        if o.kind == EntryKind::Monitor && !new_entries.iter().any(|n| n.id == o.id) {
            out.push((
                new_entries.len() + i,
                change(
                    ChangeScope::Entry,
                    Some(&o.id),
                    None,
                    ChangeKind::Removed,
                    Some(o.status.level.slug()),
                    None,
                    false,
                    format!("Monitor gone: {}", o.name),
                ),
            ));
        }
    }

    sources_change(old, new, &pos, &mut out);

    if old.complete != new.complete {
        let (to, text) = if new.complete {
            ("complete", "The scan is complete again")
        } else {
            (
                "incomplete",
                "The scan is incomplete: some sources could not be read",
            )
        };
        let from = if old.complete {
            "complete"
        } else {
            "incomplete"
        };
        out.push((
            usize::MAX,
            change(
                ChangeScope::Report,
                None,
                None,
                ChangeKind::Changed,
                Some(from),
                Some(to),
                false,
                text.to_string(),
            ),
        ));
    }

    let rank = |c: &Change| match c.scope {
        ChangeScope::Entry => 0,
        ChangeScope::Finding => 1,
        ChangeScope::Source => 2,
        ChangeScope::Report => 3,
    };
    out.sort_by_key(|(p, c)| (!c.notify, *p, rank(c)));
    out.into_iter().map(|(_, c)| c).collect()
}

/// Decode `baseline`, check its schema, and set `report.since` and `report.changes`. A baseline
/// that is missing, unreadable or of another schema gives `since.error` and no changes.
pub fn apply_since(report: &mut Report, baseline: Result<&[u8], String>) {
    match decode(baseline) {
        Ok(old) => {
            report.changes = Some(diff(&old, report));
            report.since = Some(Since {
                scanned_at: old.scanned_at,
                error: None,
            });
        }
        Err(e) => {
            report.since = Some(Since {
                scanned_at: String::new(),
                error: Some(redact::text(&e)),
            });
            report.changes = Some(Vec::new());
        }
    }
}

fn decode(baseline: Result<&[u8], String>) -> Result<Report, String> {
    let bytes = baseline?;
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "baseline is not valid JSON".to_string())?;
    match v.get("schema").and_then(|s| s.as_u64()) {
        Some(s) if s == u64::from(SCHEMA) => {}
        Some(s) => return Err(format!("baseline has schema {s}, expected {SCHEMA}")),
        None => return Err("baseline is not a cAInary report".to_string()),
    }
    serde_json::from_value(v).map_err(|_| "baseline is not a readable cAInary report".to_string())
}

#[allow(clippy::too_many_arguments)]
fn change(
    scope: ChangeScope,
    entry: Option<&str>,
    key: Option<&str>,
    kind: ChangeKind,
    from: Option<&str>,
    to: Option<&str>,
    notify: bool,
    text: String,
) -> Change {
    Change {
        id: format!(
            "{}:{}:{}:{}:{}",
            scope.slug(),
            entry.unwrap_or("-"),
            key.unwrap_or("-"),
            kind.slug(),
            to.unwrap_or("-")
        ),
        scope,
        entry: entry.map(str::to_string),
        key: match scope {
            ChangeScope::Finding => key.map(str::to_string),
            _ => None,
        },
        kind,
        from: from.map(str::to_string),
        to: to.map(str::to_string),
        notify,
        text: redact::text(&text),
    }
}

fn entry_change(o: &Entry, n: &Entry, out: &mut Vec<(usize, Change)>, pos: usize) {
    let (from, to) = (o.status.level, n.status.level);
    if from == to {
        return;
    }
    let raised = to > from;
    // A fresh install with vendor defaults is not news.
    let notify = raised && to >= Level::Low && !(from == Level::NotInstalled && to == Level::Low);
    out.push((
        pos,
        change(
            ChangeScope::Entry,
            Some(&n.id),
            None,
            if raised {
                ChangeKind::Raised
            } else {
                ChangeKind::Lowered
            },
            Some(from.slug()),
            Some(to.slug()),
            notify,
            format!("{} is now {}: {}", n.name, to.label(), n.status.summary),
        ),
    ));
}

fn findings_change(o: &Entry, n: &Entry, new: &Report, out: &mut Vec<(usize, Change)>, pos: usize) {
    let old: HashMap<&str, &Finding> = o.findings.iter().map(|f| (f.key.as_str(), f)).collect();
    let cur: HashMap<&str, &Finding> = n.findings.iter().map(|f| (f.key.as_str(), f)).collect();
    let mut push = |f: &Finding, kind, from: Option<Level>, to: Option<Level>, notify, text| {
        out.push((
            pos,
            change(
                ChangeScope::Finding,
                Some(&n.id),
                Some(&f.key),
                kind,
                from.map(Level::slug),
                to.map(Level::slug),
                notify,
                text,
            ),
        ));
    };

    // A finding whose key moved (a path spelled another way, say) but whose title didn't is the
    // same finding: pair it with an old one that lost its match, not "Gone" plus "New".
    let mut paired: HashSet<&str> = HashSet::new();
    for f in &n.findings {
        let to = f.level();
        let prev = old.get(f.key.as_str()).copied().or_else(|| {
            let p = o.findings.iter().find(|p| {
                p.title == f.title
                    && !cur.contains_key(p.key.as_str())
                    && !paired.contains(p.key.as_str())
            })?;
            paired.insert(p.key.as_str());
            Some(p)
        });
        match prev {
            None => push(
                f,
                ChangeKind::Added,
                None,
                Some(to),
                to >= Level::Medium,
                format!("New: {}", f.title),
            ),
            Some(p) => {
                let from = p.level();
                if from != to {
                    let raised = to > from;
                    let (kind, text) = if raised {
                        (
                            ChangeKind::Raised,
                            format!("Raised to {}: {}", to.label(), f.title),
                        )
                    } else {
                        (
                            ChangeKind::Lowered,
                            format!("Lowered to {}: {}", to.label(), f.title),
                        )
                    };
                    push(
                        f,
                        kind,
                        Some(from),
                        Some(to),
                        raised && to >= Level::Medium,
                        text,
                    );
                } else if p.signals != f.signals
                    || p.source.origin != f.source.origin
                    || p.in_effect != f.in_effect
                    || p.title != f.title
                    || p.evidence != f.evidence
                {
                    push(
                        f,
                        ChangeKind::Changed,
                        Some(from),
                        Some(to),
                        false,
                        format!("Changed: {}", f.title),
                    );
                }
            }
        }
    }
    for f in &o.findings {
        if cur.contains_key(f.key.as_str())
            || paired.contains(f.key.as_str())
            || unreadable(new, &f.source.path)
        {
            continue;
        }
        push(
            f,
            ChangeKind::Removed,
            Some(f.level()),
            None,
            false,
            format!("Gone: {}", f.title),
        );
    }
}

fn is_bad(state: SourceState) -> bool {
    matches!(
        state,
        SourceState::Error | SourceState::Refused | SourceState::Capped
    )
}

/// Is `path` a source the new scan could not fully read?
fn unreadable(new: &Report, path: &str) -> bool {
    new.sources
        .iter()
        .any(|s| s.source.path == path && is_bad(s.state))
}

fn sources_change(
    old: &Report,
    new: &Report,
    pos: &dyn Fn(&str) -> usize,
    out: &mut Vec<(usize, Change)>,
) {
    let key = |s: &ScannedSource| (s.tool, s.source.path.clone());
    let before: HashMap<(Tool, String), &ScannedSource> =
        old.sources.iter().map(|s| (key(s), s)).collect();
    let after: HashMap<(Tool, String), &ScannedSource> =
        new.sources.iter().map(|s| (key(s), s)).collect();

    let mut push = |s: &ScannedSource, kind, from: Option<SourceState>, to: Option<SourceState>| {
        let entry = s.tool.app().slug();
        let path = &s.source.path;
        let name = s.tool.name();
        let text = match to {
            Some(t) if is_bad(t) => format!(
                "{name} config could not be fully read ({}): {path}",
                t.slug()
            ),
            Some(SourceState::Present) => format!("{name} config appeared: {path}"),
            None | Some(SourceState::Absent) => format!("{name} config disappeared: {path}"),
            Some(t) => format!("{name} config is now {}: {path}", t.slug()),
        };
        out.push((
            pos(entry),
            change(
                ChangeScope::Source,
                Some(entry),
                Some(path),
                kind,
                from.map(SourceState::slug),
                to.map(SourceState::slug),
                false,
                text,
            ),
        ));
    };

    for s in &new.sources {
        let interesting = s.source.origin.is_org() || is_bad(s.state);
        match before.get(&key(s)) {
            None if interesting && (s.state != SourceState::Absent || is_bad(s.state)) => {
                push(s, ChangeKind::Added, None, Some(s.state))
            }
            Some(p) if p.state != s.state && interesting => {
                push(s, ChangeKind::Changed, Some(p.state), Some(s.state))
            }
            _ => {}
        }
    }
    for s in &old.sources {
        if s.source.origin.is_org()
            && s.state != SourceState::Absent
            && !after.contains_key(&key(s))
        {
            push(s, ChangeKind::Removed, Some(s.state), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyze, sort_and_number};
    use crate::harness::platform::{EnvKind, Os};
    use crate::model::{AlertMode, Origin, Signal, Source, SourceKind};
    use std::collections::BTreeSet;

    /// A finding on `tool` named by `title`, evidence key `title`, sending `signals`.
    fn finding(tool: Tool, title: &str, origin: Origin, signals: &[Signal]) -> Finding {
        let mut b = crate::model::FindingBuilder::new(title)
            .signals(signals)
            .source(Source::new("~/a.json", origin, SourceKind::File))
            .evidence([format!("{title} = 1")]);
        if tool == Tool::Device {
            b = b.agent("Acme Guard");
        }
        b.build(tool)
    }

    fn src(tool: Tool, path: &str, origin: Origin, state: SourceState) -> ScannedSource {
        ScannedSource {
            tool,
            source: Source::new(path, origin, SourceKind::File),
            state,
            note: None,
        }
    }

    fn report(
        mut findings: Vec<Finding>,
        installed: &[Tool],
        sources: Vec<ScannedSource>,
    ) -> Report {
        sort_and_number(&mut findings);
        let installed: BTreeSet<Tool> = installed.iter().copied().collect();
        let a = analyze(findings, &sources, &installed, &[], AlertMode::Everything);
        Report {
            schema: SCHEMA,
            generator: "cainary test".into(),
            scanned_at: "2026-10-20T09:00:00Z".into(),
            os: Os::Macos,
            env_kind: EnvKind::Shell,
            alert: AlertMode::Everything,
            complete: a.complete,
            status: a.status,
            apps: a.apps,
            others: a.others,
            sources,
            since: None,
            changes: None,
        }
    }

    fn kinds(cs: &[Change]) -> Vec<(ChangeScope, ChangeKind, bool)> {
        cs.iter().map(|c| (c.scope, c.kind, c.notify)).collect()
    }

    use ChangeKind::*;
    use ChangeScope::{Entry as E, Finding as F, Report as R, Source as S};

    fn usage(t: &str) -> Finding {
        finding(Tool::ClaudeCode, t, Origin::User, &[Signal::Usage])
    }

    #[test]
    fn identical_reports_have_no_changes() {
        let r = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        assert!(diff(&r, &r).is_empty());
    }

    #[test]
    fn a_moved_key_with_the_same_title_is_not_gone_and_new() {
        let at = |path: &str, value: &str| {
            crate::model::FindingBuilder::new("x")
                .signals(&[Signal::Usage])
                .source(Source::new(path, Origin::User, SourceKind::File))
                .evidence([format!("x = {value}")])
                .build(Tool::ClaudeCode)
        };
        let tilde = report(vec![at("~/a.json", "1")], &[Tool::ClaudeCode], vec![]);
        let abs = report(
            vec![at("/Users/alice/a.json", "1")],
            &[Tool::ClaudeCode],
            vec![],
        );
        assert!(diff(&tilde, &abs).is_empty());
        let edited = report(
            vec![at("/Users/alice/a.json", "2")],
            &[Tool::ClaudeCode],
            vec![],
        );
        assert_eq!(kinds(&diff(&tilde, &edited)), [(F, Changed, false)]);
    }

    #[test]
    fn entry_raised_notifies_and_lowered_does_not() {
        let low = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let high = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Prompts],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        let up = diff(&low, &high);
        let entry: Vec<_> = up.iter().filter(|c| c.scope == E).collect();
        assert_eq!(entry.len(), 1);
        assert_eq!((entry[0].kind, entry[0].notify), (Raised, true));
        assert_eq!(entry[0].entry.as_deref(), Some("claude"));
        assert_eq!(entry[0].id, "entry:claude:-:raised:high");
        assert!(entry[0].text.starts_with("Claude is now HIGH: "));
        let down = diff(&high, &low);
        let entry: Vec<_> = down.iter().filter(|c| c.scope == E).collect();
        assert_eq!((entry[0].kind, entry[0].notify), (Lowered, false));
    }

    #[test]
    fn raised_to_not_installed_exception_and_below_low() {
        // not-installed -> low is a fresh install: raised, no notify.
        let none = report(vec![], &[], vec![]);
        let fresh = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let cs = diff(&none, &fresh);
        let e: Vec<_> = cs.iter().filter(|c| c.scope == E).collect();
        assert_eq!((e[0].kind, e[0].notify), (Raised, false));
        // not-installed -> medium still notifies.
        let work = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Traffic],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        let e: Vec<_> = diff(&none, &work)
            .into_iter()
            .filter(|c| c.scope == E)
            .collect();
        assert!(e[0].notify);
        // not-installed -> ok never notifies.
        let ok = report(vec![], &[Tool::ClaudeCode], vec![]);
        let e: Vec<_> = diff(&none, &ok)
            .into_iter()
            .filter(|c| c.scope == E)
            .collect();
        assert_eq!((e[0].kind, e[0].notify), (Raised, false));
    }

    #[test]
    fn monitor_added_notifies_at_low_and_removed_does_not() {
        let none = report(vec![], &[], vec![]);
        let mon = report(
            vec![finding(
                Tool::Device,
                "sees apps",
                Origin::Mdm,
                &[Signal::Traffic],
            )],
            &[],
            vec![],
        );
        let cs = diff(&none, &mon);
        assert_eq!(kinds(&cs), [(E, Added, true)]);
        assert_eq!(cs[0].entry.as_deref(), Some("acme-guard"));
        assert_eq!(
            (cs[0].from.as_deref(), cs[0].to.as_deref()),
            (None, Some("medium"))
        );
        let cs = diff(&mon, &none);
        assert_eq!(kinds(&cs), [(E, Removed, false)]);
        assert_eq!(cs[0].to, None);
    }

    #[test]
    fn finding_added_and_raised_notify_at_medium_plus() {
        let base = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let with_work = report(
            vec![
                usage("x"),
                finding(Tool::ClaudeCode, "y", Origin::User, &[Signal::Traffic]),
            ],
            &[Tool::ClaudeCode],
            vec![],
        );
        let cs = diff(&base, &with_work);
        let f: Vec<_> = cs.iter().filter(|c| c.scope == F).collect();
        assert_eq!((f[0].kind, f[0].notify), (Added, true));
        assert_eq!(f[0].text, "New: y");
        assert!(f[0].key.is_some());
        assert_eq!(f[0].to.as_deref(), Some("medium"));

        // A low finding added: not notifying.
        let with_low = report(vec![usage("x"), usage("z")], &[Tool::ClaudeCode], vec![]);
        let f: Vec<_> = diff(&base, &with_low)
            .into_iter()
            .filter(|c| c.scope == F)
            .collect();
        assert_eq!((f[0].kind, f[0].notify), (Added, false));

        // Same key (same path and evidence name), new signals: raised to high.
        let high = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Prompts],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        let f: Vec<_> = diff(&base, &high)
            .into_iter()
            .filter(|c| c.scope == F)
            .collect();
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].kind, f[0].notify), (Raised, true));
        assert_eq!(f[0].from.as_deref(), Some("low"));
    }

    #[test]
    fn finding_removed_and_lowered_do_not_notify() {
        let high = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Prompts],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        let low = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let f: Vec<_> = diff(&high, &low)
            .into_iter()
            .filter(|c| c.scope == F)
            .collect();
        assert_eq!((f[0].kind, f[0].notify), (Lowered, false));
        let gone = report(vec![], &[Tool::ClaudeCode], vec![]);
        let f: Vec<_> = diff(&high, &gone)
            .into_iter()
            .filter(|c| c.scope == F)
            .collect();
        assert_eq!((f[0].kind, f[0].notify), (Removed, false));
        assert_eq!(f[0].to, None);
    }

    #[test]
    fn finding_changed_at_same_level() {
        let a = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let mut b = a.clone();
        b.apps[0].findings[0].evidence = vec!["x = 2".into()];
        let cs = diff(&a, &b);
        assert_eq!(kinds(&cs), [(F, Changed, false)]);
        assert_eq!(cs[0].from, cs[0].to);
        // A different set-by at the same level also counts.
        let mut c = a.clone();
        c.apps[0].findings[0].source.origin = Origin::Environment;
        assert_eq!(kinds(&diff(&a, &c)), [(F, Changed, false)]);
    }

    #[test]
    fn source_changes_never_notify_and_only_org_or_bad() {
        let managed = "mdm:com.anthropic.claudecode";
        let before = report(
            vec![],
            &[Tool::ClaudeCode],
            vec![
                src(Tool::ClaudeCode, managed, Origin::Mdm, SourceState::Absent),
                src(
                    Tool::ClaudeCode,
                    "~/.claude/settings.json",
                    Origin::User,
                    SourceState::Absent,
                ),
            ],
        );
        let after = report(
            vec![],
            &[Tool::ClaudeCode],
            vec![
                src(Tool::ClaudeCode, managed, Origin::Mdm, SourceState::Present),
                src(
                    Tool::ClaudeCode,
                    "~/.claude/settings.json",
                    Origin::User,
                    SourceState::Present,
                ),
            ],
        );
        let cs = diff(&before, &after);
        assert_eq!(kinds(&cs), [(S, Changed, false)]);
        assert_eq!(
            cs[0].text,
            format!("Claude Code config appeared: {managed}")
        );
        assert_eq!(cs[0].entry.as_deref(), Some("claude"));
        assert_eq!(cs[0].key, None);
        // Added and removed org sources.
        let empty = report(vec![], &[Tool::ClaudeCode], vec![]);
        assert_eq!(kinds(&diff(&empty, &after)), [(S, Added, false)]);
        assert_eq!(kinds(&diff(&after, &empty)), [(S, Removed, false)]);
        // A user source turning bad is worth a line, plus the report change.
        let bad = report(
            vec![],
            &[Tool::ClaudeCode],
            vec![src(
                Tool::ClaudeCode,
                "~/.claude/settings.json",
                Origin::User,
                SourceState::Error,
            )],
        );
        assert_eq!(
            kinds(&diff(&after, &bad)),
            [
                (S, Changed, false),
                (S, Removed, false),
                (R, Changed, false)
            ]
        );
    }

    #[test]
    fn report_completeness_change() {
        let ok = report(vec![], &[], vec![]);
        let bad = report(
            vec![],
            &[],
            vec![src(
                Tool::Codex,
                "~/.codex/config.toml",
                Origin::User,
                SourceState::Error,
            )],
        );
        let cs = diff(&ok, &bad);
        let r: Vec<_> = cs.iter().filter(|c| c.scope == R).collect();
        assert_eq!((r[0].kind, r[0].notify), (Changed, false));
        assert_eq!(
            (
                r[0].from.as_deref(),
                r[0].to.as_deref(),
                r[0].entry.as_deref()
            ),
            (Some("complete"), Some("incomplete"), None)
        );
        assert_eq!(r[0].id, "report:-:-:changed:incomplete");
        // Order: report is last.
        assert_eq!(cs.last().unwrap().scope, R);
    }

    #[test]
    fn no_false_good_news_when_the_source_could_not_be_read() {
        let before = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Prompts],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        for state in [
            SourceState::Error,
            SourceState::Refused,
            SourceState::Capped,
        ] {
            let after = report(
                vec![],
                &[Tool::ClaudeCode],
                vec![src(Tool::ClaudeCode, "~/a.json", Origin::User, state)],
            );
            let cs = diff(&before, &after);
            assert!(
                !cs.iter().any(|c| c.scope == F && c.kind == Removed),
                "{state:?}"
            );
        }
        // Read fine and absent: the removal is real.
        let after = report(
            vec![],
            &[Tool::ClaudeCode],
            vec![src(
                Tool::ClaudeCode,
                "~/a.json",
                Origin::User,
                SourceState::Absent,
            )],
        );
        assert!(
            diff(&before, &after)
                .iter()
                .any(|c| c.scope == F && c.kind == Removed)
        );
    }

    #[test]
    fn order_is_notifying_first_then_entry_then_scope() {
        let before = report(vec![usage("x")], &[Tool::ClaudeCode, Tool::Cursor], vec![]);
        let after = report(
            vec![
                finding(Tool::ClaudeCode, "x", Origin::User, &[Signal::Prompts]),
                finding(Tool::Cursor, "c", Origin::User, &[Signal::Traffic]),
            ],
            &[Tool::ClaudeCode, Tool::Cursor],
            vec![src(
                Tool::ClaudeCode,
                "~/a.json",
                Origin::Mdm,
                SourceState::Present,
            )],
        );
        let cs = diff(&before, &after);
        let ids: Vec<_> = cs
            .iter()
            .map(|c| (c.entry.as_deref().unwrap(), c.scope, c.notify))
            .collect();
        assert_eq!(
            ids,
            [
                ("claude", E, true),
                ("claude", F, true),
                ("cursor", E, true),
                ("cursor", F, true),
                ("claude", S, false),
            ]
        );
    }

    #[test]
    fn text_is_redacted() {
        let mut before = report(vec![], &[Tool::ClaudeCode], vec![]);
        before.apps[0].status.summary = String::new();
        let mut after = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        after.apps[0].findings[0].title = "posts with ghp_EXAMPLE0123456789abcdef".into();
        after.apps[0].status.summary = after.apps[0].findings[0].title.clone();
        let cs = diff(&before, &after);
        let text = cs.iter().map(|c| c.text.as_str()).collect::<String>();
        assert!(!text.contains("EXAMPLE0123456789"), "{text}");
    }

    #[test]
    fn apply_since_sets_changes_and_handles_bad_baselines() {
        let old = report(vec![usage("x")], &[Tool::ClaudeCode], vec![]);
        let json = serde_json::to_vec(&old).unwrap();
        // Round trip: the decoded baseline equals the original.
        let mut same = old.clone();
        apply_since(&mut same, Ok(&json));
        assert_eq!(same.changes, Some(vec![]));
        let since = same.since.unwrap();
        assert_eq!(
            (since.scanned_at.as_str(), since.error),
            ("2026-10-20T09:00:00Z", None)
        );

        let mut now = report(
            vec![finding(
                Tool::ClaudeCode,
                "x",
                Origin::User,
                &[Signal::Prompts],
            )],
            &[Tool::ClaudeCode],
            vec![],
        );
        apply_since(&mut now, Ok(&json));
        assert!(now.changes.as_ref().unwrap().iter().any(|c| c.notify));

        for bad in [
            Err("missing".to_string()),
            Ok(&b"not json"[..]),
            Ok(&br#"{"schema":2}"#[..]),
            Ok(&br#"{"foo":1}"#[..]),
            Ok(&br#"{"schema":3}"#[..]),
        ] {
            let mut r = old.clone();
            apply_since(&mut r, bad);
            assert_eq!(r.changes, Some(vec![]));
            assert!(r.since.unwrap().error.is_some());
        }
    }
}
