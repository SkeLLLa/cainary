//! chatgpt scanner (rules.md §CG), macOS only: the merged app's own markers and the in-app
//! browser's Chromium policies. Stat-only: `memories/` is never listed or opened.

use crate::harness::platform::Os;
use crate::harness::{Probe, ScanCtx, ToolHome};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind};
use crate::redact;
use crate::value::{self, Format, Value};

const DOMAIN: &str = "com.openai.codex";
const REF: &str = "https://help.openai.com/en/articles/20001535";
const REF_COMPUTER_USE: &str = "https://learn.chatgpt.com/docs/computer-use";
const REF_HISTORY: &str = "https://learn.chatgpt.com/docs/customization/computer-history";
/// Codex owns these two; they are not browser policies.
const CODEX_KEYS: [&str; 2] = ["requirements_toml_base64", "config_toml_base64"];

pub fn scan(ctx: &mut ScanCtx) {
    if ctx.h().os != Os::Macos {
        return;
    }
    if app_installed(ctx) {
        ctx.installed();
        ctx.note("Workspace restrictions, Memory and Compliance API are server-side.");
    }
    browser_policies(ctx);

    let codex_home = ctx.h().tool_home(ToolHome::CodexHome);
    let cu = codex_home.join("computer-use/Codex Computer Use.app");
    if ctx.marker(&cu, Origin::Unattributed) == Probe::Dir {
        ctx.emit(
            FindingBuilder::new("Computer Use is set up")
                .detail("Its grants live in TCC.db, which cAInary can't read.")
                .source(Source::new(
                    cu.shown,
                    Origin::Unattributed,
                    SourceKind::Marker,
                ))
                .reference(REF_COMPUTER_USE),
        );
    }

    let plugin = ctx
        .h()
        .sys("/Library/Security/SecurityAgentPlugins/CodexComputerUseAuthorizationPlugin.bundle");
    if ctx.marker(&plugin, Origin::Unattributed) != Probe::Missing {
        ctx.emit(
            FindingBuilder::new("ChatGPT can unlock this Mac")
                .signals(&[Signal::DeviceAccess])
                .source(Source::new(
                    plugin.shown,
                    Origin::Unattributed,
                    SourceKind::Marker,
                ))
                .reference(REF_COMPUTER_USE),
        );
    }

    let history = codex_home.join("memories/extensions/skysight");
    if ctx.marker(&history, Origin::Unattributed) != Probe::Missing {
        ctx.emit(
            FindingBuilder::new("Computer History is on")
                .signals(&[Signal::ToolDetails])
                .source(Source::new(
                    history.shown,
                    Origin::Unattributed,
                    SourceKind::Marker,
                ))
                .reference(REF_HISTORY),
        );
    }
}

/// The merged app has bundle id `com.openai.codex`; the Classic app only counts as installed.
fn app_installed(ctx: &mut ScanCtx) -> bool {
    let mut found = false;
    for loc in [
        ctx.h().sys("/Applications/ChatGPT.app/Contents/Info.plist"),
        ctx.h().home("Applications/ChatGPT.app/Contents/Info.plist"),
    ] {
        if let Some(plist) = ctx.read(&loc, Origin::Unattributed, Format::Plist) {
            found |= plist.get("CFBundleIdentifier").and_then(Value::as_str) == Some(DOMAIN);
        }
    }
    found
        || [
            ctx.h().sys("/Applications/ChatGPT Classic.app"),
            ctx.h().home("Applications/ChatGPT Classic.app"),
        ]
        .iter()
        .any(|l| ctx.probe(l) == Probe::Dir)
}

/// A proxy host from `host:port`, `scheme://host:port` or `scheme=host:port;…`.
fn proxy_hosts(s: &str) -> Vec<String> {
    s.split(';')
        .filter_map(|part| {
            let part = part.rsplit('=').next().unwrap_or(part).trim();
            redact::url_host(part).or_else(|| {
                let host = part.rsplit_once(':').map_or(part, |(h, _)| h);
                (!host.is_empty()).then(|| host.to_string())
            })
        })
        .collect()
}

fn browser_policies(ctx: &mut ScanCtx) {
    // Per-user plist first: it wins per key.
    let mut keys: Vec<(String, Value, crate::harness::Loc)> = Vec::new();
    for (loc, v) in ctx.read_mdm(DOMAIN) {
        for (k, val) in v.as_object().into_iter().flatten() {
            if !CODEX_KEYS.contains(&k.as_str()) && !keys.iter().any(|(n, ..)| n == k) {
                keys.push((k.clone(), val.clone(), loc.clone()));
            }
        }
    }
    let find = |n: &str| keys.iter().find(|(k, ..)| k == n);
    let source =
        |loc: &crate::harness::Loc| Source::new(loc.shown.clone(), Origin::Mdm, SourceKind::File);
    let mut used: Vec<&str> = Vec::new();

    let mut evidence = Vec::new();
    let mut first = None;
    let mut hosts = Vec::new();
    if let Some((_, v, loc)) = find("ProxyMode") {
        used.push("ProxyMode");
        let mode = v.as_str().unwrap_or_default();
        if !mode.is_empty() && !["direct", "system"].contains(&mode) {
            evidence.push(format!("ProxyMode = {mode}"));
            first.get_or_insert(loc);
        }
    }
    for name in ["ProxyServer", "ProxyPacUrl"] {
        if let Some((_, v, loc)) = find(name) {
            used.push(name);
            let s = v.as_str().unwrap_or_default();
            if !s.is_empty() {
                let h = if name == "ProxyPacUrl" {
                    redact::url_host(s).into_iter().collect()
                } else {
                    proxy_hosts(s)
                };
                evidence.extend(h.iter().map(|h| format!("{name} host = {h}")));
                hosts.extend(h);
                first.get_or_insert(loc);
            }
        }
    }
    if let Some(loc) = first {
        ctx.emit(
            FindingBuilder::new("The built-in browser goes through your organization's proxy")
                .signals(&[Signal::Traffic])
                .evidence(evidence)
                .source(source(loc))
                .reference(REF),
        );
    }
    if let Some((_, _, loc)) = find("ExtensionInstallForcelist") {
        used.push("ExtensionInstallForcelist");
        ctx.emit(
            FindingBuilder::new("Your organization force-installs browser extensions")
                .signals(&[Signal::Traffic])
                .best_effort(true)
                .source(source(loc))
                .reference(REF),
        );
    }
    for name in ["BrowserSignin", "RestrictSigninToPattern"] {
        if let Some((_, v, loc)) = find(name) {
            used.push(name);
            ctx.emit(
                FindingBuilder::new("Your organization restricts browser sign-in")
                    .signals(&[Signal::Policy])
                    .evidence([format!("{name} = {}", redact::value(name, v))])
                    .source(source(loc))
                    .reference(REF),
            );
        }
    }
    let reports = find("CloudReportingEnabled").filter(|(_, v, _)| value::truthy(v));
    let reports = reports.or_else(|| find("ReportingPolicies"));
    if let Some((_, _, loc)) = reports {
        used.extend(["CloudReportingEnabled", "ReportingPolicies"]);
        ctx.emit(
            FindingBuilder::new("A browser reporting policy is set; it may be inert")
                .signals(&[Signal::Usage])
                .best_effort(true)
                .source(source(loc))
                .reference(REF),
        );
    }
    let other: Vec<&(String, Value, crate::harness::Loc)> = keys
        .iter()
        .filter(|(k, ..)| !used.contains(&k.as_str()))
        .collect();
    if let Some((_, _, loc)) = other.first() {
        ctx.emit(
            FindingBuilder::new(format!(
                "Your organization sets {} other browser polic{}",
                other.len(),
                if other.len() == 1 { "y" } else { "ies" }
            ))
            .signals(&[Signal::Policy])
            .evidence(other.iter().map(|(k, ..)| format!("key = {k}")))
            .source(source(loc))
            .reference(REF),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::harness::Harness;
    use crate::model::Tool;
    use crate::{ScanOptions, scan};
    use std::path::PathBuf;

    #[test]
    fn only_the_skysight_stat_is_under_memories() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chatgpt-macos-full");
        let h = Harness::from_fixture(&dir).unwrap();
        let report = scan(&h, &ScanOptions::default());
        let under: Vec<&str> = report
            .sources
            .iter()
            .filter(|s| s.tool == Tool::Chatgpt && s.source.path.contains("memories/"))
            .map(|s| s.source.path.as_str())
            .collect();
        assert_eq!(under, ["~/.codex/memories/extensions/skysight"]);
    }
}
