//! Levels, entries and the overall status (architecture.md §3.2, §3.4).

use crate::model::{
    AlertMode, App, Entry, EntryKind, Finding, Level, Origin, ScannedSource, Signal, SourceState,
    Status, Tool,
};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

/// The monitor entry for device findings that name no agent.
const DEVICE_NAME: &str = "This device";

/// What `analyze` computes: the app and monitor entries, the overall status, and
/// `Report::complete`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub apps: Vec<Entry>,
    pub others: Vec<Entry>,
    pub status: Status,
    pub complete: bool,
}

/// Does the finding count at `mode`? Only the `status` subcommand's badge uses this.
pub fn counts(f: &Finding, mode: AlertMode) -> bool {
    if !f.in_effect || f.signals.is_empty() {
        return false;
    }
    let o = f.source.origin;
    match mode {
        AlertMode::Org => o.is_org(),
        AlertMode::OrgUnknown => {
            o.is_org() || matches!(o, Origin::Unattributed | Origin::Environment)
        }
        AlertMode::Everything => true,
    }
}

/// Sort findings by (app, tool, exposure desc, in_effect desc, origin, title, source.path) and assign
/// `<app>-<n>` ids, `n` counting from 1 within each app. Detail and evidence break any
/// remaining tie so the numbering never depends on the input order.
pub fn sort_and_number(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.app
            .cmp(&b.app)
            .then(a.tool.cmp(&b.tool))
            .then(b.exposure.cmp(&a.exposure))
            .then(b.in_effect.cmp(&a.in_effect))
            .then(a.source.origin.cmp(&b.source.origin))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.source.path.cmp(&b.source.path))
            .then_with(|| a.detail.cmp(&b.detail))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    let mut current: Option<App> = None;
    let mut n = 0;
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings.iter_mut() {
        if current != Some(f.app) {
            current = Some(f.app);
            n = 0;
        }
        n += 1;
        f.id = format!("{}-{n}", f.app.slug());
        let key = finding_key(f);
        let count = seen.entry(key.clone()).or_insert(0);
        *count += 1;
        f.key = if *count == 1 {
            key
        } else {
            format!("{key}-{count}")
        };
    }
}

/// FNV-1a-64 over `surface \0 config.path \0 anchor`, as 16 hex digits (architecture.md §4.1). The
/// anchor is the sorted evidence key names, or the title when there is no evidence. Values are
/// left out so a changed value keeps the key.
fn finding_key(f: &Finding) -> String {
    let anchor = if f.evidence.is_empty() {
        f.title.clone()
    } else {
        let mut names: Vec<&str> = f
            .evidence
            .iter()
            .map(|e| e.split_once(" = ").map_or(e.as_str(), |(k, _)| k))
            .collect();
        names.sort();
        names.join("\n")
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in f
        .tool
        .slug()
        .bytes()
        .chain([0])
        .chain(f.source.path.bytes())
        .chain([0])
        .chain(anchor.bytes())
    {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Compute `counts` on every finding, then group them into the four app entries and the
/// monitor entries. `installed` holds the surfaces a scanner reported installed; `notes` are
/// per-surface notes. `findings` must already be through [`sort_and_number`].
pub fn analyze(
    mut findings: Vec<Finding>,
    sources: &[ScannedSource],
    installed: &BTreeSet<Tool>,
    notes: &[(Tool, String)],
    mode: AlertMode,
) -> Analysis {
    for f in findings.iter_mut() {
        f.counts = counts(f, mode);
    }

    let complete = !sources.iter().any(|s| {
        matches!(
            s.state,
            SourceState::Error | SourceState::Refused | SourceState::Capped
        )
    });

    let apps: Vec<Entry> = App::ALL
        .iter()
        .filter(|&&app| app != App::Device)
        .map(|&app| app_entry(app, &findings, installed, notes))
        .collect();
    let others = monitor_entries(&findings, notes);

    // The first entry at the worst level: apps before monitors. A monitor
    // with only notes does not count.
    let worst = apps
        .iter()
        .chain(&others)
        .filter(|e| e.kind == EntryKind::App || !e.findings.is_empty())
        .rev()
        .max_by_key(|e| e.status.level)
        .expect("there are always app entries");
    let status = worst.status.clone();
    Analysis {
        apps,
        others,
        status,
        complete,
    }
}

fn app_entry(
    app: App,
    findings: &[Finding],
    installed: &BTreeSet<Tool>,
    notes: &[(Tool, String)],
) -> Entry {
    let mine: Vec<Finding> = findings.iter().filter(|f| f.app == app).cloned().collect();
    let is_installed = installed.iter().any(|t| t.app() == app) || mine.iter().any(|f| f.in_effect);
    let surfaces = app
        .tools()
        .into_iter()
        .filter(|&t| installed.contains(&t) || mine.iter().any(|f| f.tool == t))
        .collect();
    let notes = notes
        .iter()
        .filter(|(t, _)| t.app() == app)
        .map(|(_, n)| n.clone())
        .collect();
    entry(
        app.slug().to_string(),
        app.name(),
        EntryKind::App,
        is_installed,
        mine,
        surfaces,
        notes,
    )
}

/// Device findings grouped by `Finding::agent`; those with none share the "This device" entry,
/// which exists when it has findings or device notes. Ordered by level descending, then name.
fn monitor_entries(findings: &[Finding], notes: &[(Tool, String)]) -> Vec<Entry> {
    let mut groups: BTreeMap<&str, Vec<Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.tool == Tool::Device) {
        let name = f.agent.as_deref().unwrap_or(DEVICE_NAME);
        groups.entry(name).or_default().push(f.clone());
    }
    // Device notes (root certificates, TCC) keep the "This device" entry alive without findings,
    // but only next to other monitors, so a clean machine has no device row.
    if !groups.is_empty() && notes.iter().any(|(t, _)| *t == Tool::Device) {
        groups.entry(DEVICE_NAME).or_default();
    }
    let mut entries: Vec<Entry> = groups
        .into_iter()
        .map(|(name, mine)| {
            let device = name == DEVICE_NAME;
            let notes = notes
                .iter()
                .filter(|(t, _)| device && *t == Tool::Device)
                .map(|(_, n)| n.clone())
                .collect();
            let id = if device {
                "device".to_string()
            } else {
                slugify(name)
            };
            entry(id, name, EntryKind::Monitor, true, mine, Vec::new(), notes)
        })
        .collect();
    entries.sort_by(|a, b| {
        (Reverse(a.status.level), &a.name).cmp(&(Reverse(b.status.level), &b.name))
    });
    entries
}

/// Lower-case, runs of non-alphanumerics become one `-`, none at the ends.
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn entry(
    id: String,
    name: &str,
    kind: EntryKind,
    installed: bool,
    mut findings: Vec<Finding>,
    surfaces: Vec<Tool>,
    notes: Vec<String>,
) -> Entry {
    // Stable: ties keep the `sort_and_number` order.
    findings.sort_by_key(|f| Reverse(f.level()));
    let level = if installed {
        findings
            .iter()
            .map(Finding::level)
            .max()
            .unwrap_or(Level::Ok)
    } else {
        Level::NotInstalled
    };
    let sends: BTreeSet<Signal> = findings
        .iter()
        .flat_map(|f| f.signals.iter().copied())
        .collect();
    Entry {
        id,
        name: name.to_string(),
        kind,
        installed,
        status: Status {
            level,
            label: level.label().to_string(),
            summary: summary(level, &findings),
        },
        sends: sends.into_iter().collect(),
        surfaces,
        findings,
        notes,
    }
}

/// The worst finding's title plus " (+N more)" for the others at its level, or the level's
/// short phrase when nothing is sent. `findings` is sorted by level descending.
fn summary(level: Level, findings: &[Finding]) -> String {
    if level < Level::Low {
        return level.short().to_string();
    }
    let at_level = findings.iter().filter(|f| f.level() == level).count();
    let title = &findings[0].title;
    match at_level {
        0 | 1 => title.clone(),
        n => format!("{title} (+{} more)", n - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Exposure, Source, SourceKind};

    fn finding(tool: Tool, origin: Origin, signals: &[Signal]) -> Finding {
        let mut f = Finding {
            id: String::new(),
            key: String::new(),
            app: tool.app(),
            tool,
            agent: None,
            signals: signals.to_vec(),
            exposure: Exposure::Clear,
            title: "AcmeCollector receives data".into(),
            detail: String::new(),
            source: Source::new("~/x.json", origin, SourceKind::File),
            evidence: vec![],
            reference: None,
            best_effort: false,
            in_effect: true,
            counts: false,
        };
        f.finish();
        f
    }

    fn agent(name: &str, signals: &[Signal]) -> Finding {
        let mut f = finding(Tool::Device, Origin::Mdm, signals);
        f.agent = Some(name.into());
        f
    }

    fn opted_out(tool: Tool) -> Finding {
        let mut f = finding(tool, Origin::VendorDefault, &[]);
        f.in_effect = false;
        f
    }

    fn src(state: SourceState) -> ScannedSource {
        ScannedSource {
            tool: Tool::Codex,
            source: Source::new("~/c.toml", Origin::User, SourceKind::File),
            state,
            note: None,
        }
    }

    fn run(mut fs: Vec<Finding>, sources: &[ScannedSource], mode: AlertMode) -> Analysis {
        sort_and_number(&mut fs);
        analyze(fs, sources, &BTreeSet::new(), &[], mode)
    }

    fn entry_of<'a>(a: &'a Analysis, id: &str) -> &'a Entry {
        a.apps
            .iter()
            .chain(&a.others)
            .find(|e| e.id == id)
            .unwrap_or_else(|| panic!("no entry {id}"))
    }

    #[test]
    fn modes_by_origins() {
        use AlertMode::*;
        // (origin, Org, OrgUnknown, Everything)
        let table = [
            (Origin::Server, true, true, true),
            (Origin::Mdm, true, true, true),
            (Origin::System, true, true, true),
            (Origin::OrgInstalled, true, true, true),
            (Origin::Unattributed, false, true, true),
            (Origin::Environment, false, true, true),
            (Origin::User, false, false, true),
            (Origin::VendorDefault, false, false, true),
        ];
        assert_eq!(table.len(), Origin::ALL.len());
        for (o, org, unk, all) in table {
            let f = finding(Tool::Codex, o, &[Signal::Prompts]);
            assert_eq!(counts(&f, Org), org, "{o:?} org");
            assert_eq!(counts(&f, OrgUnknown), unk, "{o:?} org-unknown");
            assert_eq!(counts(&f, Everything), all, "{o:?} everything");
        }
    }

    #[test]
    fn not_in_effect_never_counts() {
        let mut f = finding(Tool::Codex, Origin::Mdm, &[Signal::Prompts]);
        f.in_effect = false;
        f.signals.clear();
        f.finish();
        for m in AlertMode::ALL {
            assert!(!counts(&f, *m));
        }
        let a = run(vec![f], &[], AlertMode::Everything);
        let e = entry_of(&a, "openai");
        assert!(!e.installed);
        assert_eq!(e.status.level, Level::NotInstalled);
        assert!(!e.findings[0].counts);
    }

    #[test]
    fn levels_follow_exposure_and_ignore_alert_mode() {
        for mode in AlertMode::ALL {
            let a = run(
                vec![
                    finding(Tool::Codex, Origin::User, &[Signal::Vendor]),
                    finding(Tool::Cursor, Origin::User, &[Signal::Identity]),
                    finding(Tool::Copilot, Origin::User, &[Signal::Traffic]),
                    finding(Tool::ClaudeCode, Origin::User, &[Signal::Prompts]),
                ],
                &[],
                *mode,
            );
            let level = |id| entry_of(&a, id).status.level;
            assert_eq!(level("openai"), Level::Low, "{mode:?}");
            assert_eq!(level("cursor"), Level::Low, "{mode:?}");
            assert_eq!(level("copilot"), Level::Medium, "{mode:?}");
            assert_eq!(level("claude"), Level::High, "{mode:?}");
            assert_eq!(a.status.level, Level::High);
        }
    }

    #[test]
    fn opted_out_beats_ok_and_loses_to_low() {
        let cursor = |mut fs: Vec<Finding>| {
            sort_and_number(&mut fs);
            let installed: BTreeSet<Tool> = [Tool::Cursor].into();
            let a = analyze(fs, &[], &installed, &[], AlertMode::Org);
            entry_of(&a, "cursor").clone()
        };
        // An opt-out alone: opted-out.
        let e = cursor(vec![opted_out(Tool::Cursor)]);
        assert_eq!(e.status.level, Level::OptedOut);
        assert_eq!(e.status.summary, "Standard telemetry is off");
        // Opted out plus an inactive shadowed finding: still opted-out.
        let mut shadowed = finding(Tool::Cursor, Origin::Mdm, &[]);
        shadowed.in_effect = false;
        let e = cursor(vec![opted_out(Tool::Cursor), shadowed]);
        assert_eq!(e.status.level, Level::OptedOut);
        // Plus a low finding: low.
        let low = finding(Tool::Cursor, Origin::User, &[Signal::Usage]);
        assert_eq!(
            cursor(vec![opted_out(Tool::Cursor), low]).status.level,
            Level::Low
        );
    }

    #[test]
    fn inactive_findings_count_as_ok() {
        let mut f = finding(Tool::Codex, Origin::Mdm, &[Signal::Prompts]);
        f.in_effect = false;
        f.signals.clear();
        f.finish();
        let installed: BTreeSet<Tool> = [Tool::Codex].into();
        let mut fs = vec![f];
        sort_and_number(&mut fs);
        let a = analyze(fs, &[], &installed, &[], AlertMode::Org);
        let e = entry_of(&a, "openai");
        assert_eq!(e.status.level, Level::Ok);
        assert_eq!(e.status.summary, "Nothing sent");
        assert!(e.sends.is_empty());
    }

    #[test]
    fn summary_names_the_worst_finding() {
        let mut one = finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]);
        one.title = "hook gets prompts".into();
        let mut two = finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Transcript]);
        two.title = "other hook gets transcripts".into();
        let low = finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Usage]);
        let a = run(vec![low, two, one], &[], AlertMode::Org);
        let e = entry_of(&a, "claude");
        assert_eq!(e.status.summary, "hook gets prompts (+1 more)");
        assert_eq!(a.status.summary, e.status.summary);
        assert_eq!(a.status.label, "HIGH");
        // Findings are sorted by level, high first.
        let levels: Vec<_> = e.findings.iter().map(Finding::level).collect();
        assert_eq!(levels, [Level::High, Level::High, Level::Low]);
        assert_eq!(
            e.sends,
            [Signal::Prompts, Signal::Transcript, Signal::Usage]
        );
    }

    #[test]
    fn all_not_installed() {
        let a = analyze(vec![], &[], &BTreeSet::new(), &[], AlertMode::OrgUnknown);
        let ids: Vec<_> = a.apps.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["claude", "openai", "cursor", "copilot"]);
        assert!(a.others.is_empty());
        assert!(a.complete);
        assert_eq!(a.status.level, Level::NotInstalled);
        assert_eq!(a.status.summary, "Not installed");
        for e in &a.apps {
            assert!(!e.installed);
            assert_eq!(e.kind, EntryKind::App);
            assert!(e.surfaces.is_empty());
        }
    }

    #[test]
    fn installed_from_scanner_or_finding() {
        let installed: BTreeSet<Tool> = [Tool::Cursor].into();
        let mut fs = vec![finding(Tool::Codex, Origin::User, &[Signal::Usage])];
        sort_and_number(&mut fs);
        let a = analyze(fs, &[], &installed, &[], AlertMode::Org);
        let cursor = entry_of(&a, "cursor");
        assert!(cursor.installed);
        assert_eq!(cursor.status.level, Level::Ok);
        assert_eq!(cursor.surfaces, [Tool::Cursor]);
        let codex = entry_of(&a, "openai");
        assert!(codex.installed);
        assert_eq!(codex.status.level, Level::Low);
        assert_eq!(codex.surfaces, [Tool::Codex]);
    }

    #[test]
    fn monitors_group_by_agent_and_order_by_level_then_name() {
        let a = run(
            vec![
                agent("Zscaler", &[Signal::Traffic]),
                agent("CrowdStrike Falcon", &[Signal::DeviceAccess]),
                agent("CrowdStrike Falcon", &[Signal::Traffic]),
                agent("Network proxy", &[Signal::Usage]),
                finding(Tool::Device, Origin::Mdm, &[Signal::Usage]),
            ],
            &[],
            AlertMode::Org,
        );
        let got: Vec<_> = a.others.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            got,
            ["crowdstrike-falcon", "zscaler", "network-proxy", "device"]
        );
        let cs = entry_of(&a, "crowdstrike-falcon");
        assert_eq!(cs.findings.len(), 2);
        assert_eq!(cs.kind, EntryKind::Monitor);
        assert!(cs.installed && cs.surfaces.is_empty());
        assert_eq!(cs.status.summary, "AcmeCollector receives data (+1 more)");
        assert_eq!(entry_of(&a, "device").name, "This device");
        // No device findings with no agent: no "This device" entry.
        let a = run(
            vec![agent("Zscaler", &[Signal::Traffic])],
            &[],
            AlertMode::Org,
        );
        assert!(a.others.iter().all(|e| e.id != "device"));
        // Monitors take part in the overall status; apps win ties.
        assert_eq!(a.status.level, Level::Medium);
    }

    #[test]
    fn device_notes_ride_on_this_device() {
        let notes = [(Tool::Device, "n".to_string())];
        let mut fs = vec![finding(Tool::Device, Origin::Mdm, &[Signal::Usage])];
        sort_and_number(&mut fs);
        let a = analyze(fs, &[], &BTreeSet::new(), &notes, AlertMode::Org);
        assert_eq!(entry_of(&a, "device").notes, ["n"]);
    }

    #[test]
    fn slugs() {
        assert_eq!(
            slugify("Palo Alto GlobalProtect"),
            "palo-alto-globalprotect"
        );
        assert_eq!(slugify("Acme (Collector)!"), "acme-collector");
    }

    #[test]
    fn incomplete_sources_clear_complete() {
        for state in [
            SourceState::Refused,
            SourceState::Capped,
            SourceState::Error,
        ] {
            let a = analyze(
                vec![],
                &[src(SourceState::Present), src(state)],
                &BTreeSet::new(),
                &[],
                AlertMode::OrgUnknown,
            );
            assert!(!a.complete);
        }
        let a = analyze(
            vec![],
            &[src(SourceState::Absent), src(SourceState::Present)],
            &BTreeSet::new(),
            &[],
            AlertMode::Org,
        );
        assert!(a.complete);
    }

    #[test]
    fn numbering_is_stable_under_shuffle() {
        let mk = |tool, origin, title: &str, sig, path: &str| {
            let mut f = finding(tool, origin, &[sig]);
            f.title = title.into();
            f.source.path = path.into();
            f
        };
        let base = vec![
            mk(Tool::Codex, Origin::User, "b", Signal::Usage, "~/a"),
            mk(Tool::Codex, Origin::Mdm, "z", Signal::Prompts, "~/a"),
            mk(Tool::Codex, Origin::Mdm, "a", Signal::Usage, "~/b"),
            mk(Tool::Codex, Origin::Mdm, "a", Signal::Usage, "~/a"),
            mk(
                Tool::ClaudeCode,
                Origin::System,
                "q",
                Signal::Traffic,
                "~/a",
            ),
            mk(Tool::Cursor, Origin::User, "q", Signal::Traffic, "~/a"),
        ];
        let mut want = base.clone();
        sort_and_number(&mut want);
        let ids: Vec<_> = want.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "claude-1", "openai-1", "openai-2", "openai-3", "openai-4", "cursor-1"
            ]
        );
        // exposure desc first within a tool, then origin, title, path.
        assert_eq!(want[1].title, "z");
        assert_eq!(want[2].source.path, "~/a");
        assert_eq!(want[3].source.path, "~/b");
        for rot in 1..base.len() {
            let mut v = base.clone();
            v.rotate_left(rot);
            v.reverse();
            sort_and_number(&mut v);
            assert_eq!(v, want, "rotation {rot}");
        }
    }

    #[test]
    fn in_effect_sorts_before_shadowed() {
        let mut shadowed = finding(Tool::Codex, Origin::Mdm, &[Signal::Prompts]);
        shadowed.in_effect = false;
        shadowed.signals.clear();
        shadowed.finish();
        let live = finding(Tool::Codex, Origin::User, &[Signal::Usage]);
        let mut fs = [shadowed, live];
        sort_and_number(&mut fs);
        // Exposure desc comes first, so the live Usage finding leads the Clear shadowed one.
        assert_eq!(fs[0].id, "openai-1");
        assert!(fs[0].in_effect);
    }

    #[test]
    fn surfaces_share_one_app_entry() {
        let installed: BTreeSet<Tool> = [Tool::ClaudeDesktop].into();
        let mut fs = vec![
            finding(Tool::ClaudeDesktop, Origin::Mdm, &[Signal::Traffic]),
            finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]),
        ];
        sort_and_number(&mut fs);
        let a = analyze(fs, &[], &installed, &[], AlertMode::Org);
        let e = entry_of(&a, "claude");
        let ids: Vec<_> = e.findings.iter().map(|f| (f.id.as_str(), f.tool)).collect();
        assert_eq!(
            ids,
            [
                ("claude-1", Tool::ClaudeCode),
                ("claude-2", Tool::ClaudeDesktop)
            ]
        );
        assert_eq!(e.surfaces, [Tool::ClaudeCode, Tool::ClaudeDesktop]);
        assert_eq!(e.status.level, Level::High);
        assert!(!entry_of(&a, "openai").installed);
    }

    #[test]
    fn notes_are_routed_per_app() {
        let notes = [
            (Tool::Cursor, "n1".to_string()),
            (Tool::Codex, "n2".to_string()),
            (Tool::Cursor, "n3".to_string()),
        ];
        let a = analyze(vec![], &[], &BTreeSet::new(), &notes, AlertMode::Org);
        assert_eq!(entry_of(&a, "cursor").notes, ["n1", "n3"]);
        assert_eq!(entry_of(&a, "openai").notes, ["n2"]);
    }

    #[test]
    fn device_notes_keep_the_device_entry() {
        let notes = [(Tool::Device, "root certificate installed".to_string())];
        // Alone, the notes add no row: a clean machine stays clean.
        let a = analyze(vec![], &[], &BTreeSet::new(), &notes, AlertMode::Org);
        assert!(a.others.is_empty());
        assert_eq!(a.status.level, Level::NotInstalled);
        // Next to another monitor, they keep a "This device" row.
        let mut f = finding(Tool::Device, Origin::Mdm, &[Signal::Traffic]);
        f.agent = Some("Network proxy".into());
        let a = analyze(vec![f], &[], &BTreeSet::new(), &notes, AlertMode::Org);
        let device = a
            .others
            .iter()
            .find(|e| e.id == "device")
            .expect("device row");
        assert_eq!(device.notes, ["root certificate installed"]);
    }

    #[test]
    fn keys_are_stable_and_ignore_values() {
        let mk = |title: &str, ev: &[&str]| {
            let mut f = finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]);
            f.title = title.into();
            f.evidence = ev.iter().map(|s| s.to_string()).collect();
            f
        };
        let mut a = vec![mk("one", &["A = 1", "B = 2"]), mk("two", &["C = 3"])];
        let mut b = vec![mk("two", &["C = 9"]), mk("one", &["B = 5", "A = 6"])];
        sort_and_number(&mut a);
        sort_and_number(&mut b);
        let key = |fs: &[Finding], t: &str| fs.iter().find(|f| f.title == t).unwrap().key.clone();
        assert_eq!(key(&a, "one"), key(&b, "one"));
        assert_eq!(key(&a, "two"), key(&b, "two"));
        assert_ne!(key(&a, "one"), key(&a, "two"));
        assert_eq!(key(&a, "one").len(), 16);
        // New key names are a different finding.
        let mut c = vec![mk("one", &["A = 1", "B = 2", "D = 4"])];
        sort_and_number(&mut c);
        assert_ne!(key(&a, "one"), key(&c, "one"));
        // No evidence: the title is the anchor.
        let mut d = vec![mk("one", &[]), mk("two", &[])];
        sort_and_number(&mut d);
        assert_ne!(d[0].key, d[1].key);
    }

    #[test]
    fn clashing_keys_get_numeric_suffixes() {
        let mut fs = vec![
            finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]),
            finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]),
            finding(Tool::ClaudeCode, Origin::Mdm, &[Signal::Prompts]),
        ];
        sort_and_number(&mut fs);
        let base = fs[0].key.clone();
        assert_eq!(base.len(), 16);
        assert_eq!(fs[1].key, format!("{base}-2"));
        assert_eq!(fs[2].key, format!("{base}-3"));
    }
}
