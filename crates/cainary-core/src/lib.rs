//! cAInary core. Read-only, no network. See `docs/architecture.md`.

pub mod analysis;
pub mod diff;
pub mod harness;
pub mod model;
pub mod redact;
pub mod rules;
pub mod scanners;
pub mod value;

use analysis::{analyze, sort_and_number};
use harness::{Harness, ScanCtx};
use model::{AlertMode, Report, Tool};
use std::collections::BTreeSet;

/// Options for [`scan`].
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub alert: AlertMode,
    /// Empty = all tools.
    pub tools: Vec<Tool>,
}

/// Run every registered scanner and build the report.
///
/// The scanners that run are `opts.tools` ∩ the fixture's `tools`: a filter can only narrow,
/// never widen. Either one alone applies; with neither, every scanner runs.
pub fn scan(h: &Harness, opts: &ScanOptions) -> Report {
    let wanted = |tool: Tool| {
        (opts.tools.is_empty() || opts.tools.contains(&tool))
            && (h.fixture_tools().is_empty() || h.fixture_tools().contains(&tool))
    };

    let mut findings = Vec::new();
    let mut sources = Vec::new();
    let mut installed = BTreeSet::new();
    let mut notes = Vec::new();
    for (tool, run) in scanners::REGISTRY {
        if !wanted(tool) {
            continue;
        }
        let mut ctx = ScanCtx::new(h, tool);
        run(&mut ctx);
        let out = ctx.finish();
        findings.extend(out.findings);
        sources.extend(out.sources);
        if out.installed {
            installed.insert(tool);
        }
        notes.extend(out.notes.into_iter().map(|n| (tool, n)));
    }

    sort_and_number(&mut findings);
    sources.sort_by(|a, b| (a.tool, &a.source.path).cmp(&(b.tool, &b.source.path)));
    let analysis = analyze(findings, &sources, &installed, &notes, opts.alert);

    Report {
        schema: model::SCHEMA,
        generator: format!("cainary {}", env!("CARGO_PKG_VERSION")),
        scanned_at: value::rfc3339(h.now()),
        os: h.os,
        env_kind: h.env_kind,
        alert: opts.alert,
        complete: analysis.complete,
        status: analysis.status,
        apps: analysis.apps,
        others: analysis.others,
        sources,
        since: None,
        changes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_tools_and_cli_tools_intersect() {
        let dir = std::env::temp_dir().join(format!("cainary-scan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("fixture.json"),
            r#"{"os":"macos","tools":["codex"]}"#,
        )
        .unwrap();
        let h = Harness::from_fixture(&dir).unwrap();
        let opts = ScanOptions {
            tools: vec![Tool::Cursor],
            ..ScanOptions::default()
        };
        let r = scan(&h, &opts);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(r.sources.is_empty());
        assert_eq!(r.apps.len(), 4);
        assert!(r.others.is_empty());
    }
}
