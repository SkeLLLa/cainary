//! copilot scanner: sources, channels, managed/VS Code policy, CLI → `CpConfig` (rules.md §CP).

use super::copilot_telemetry;
use crate::harness::platform::Os;
use crate::harness::{Loc, Probe, ScanCtx, ToolHome, Which};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind, Tool};
use crate::redact;
use crate::rules::hooks::{self, Cmd, Hit, Target};
use crate::rules::vendor;
use crate::value::{self, Format, Value};
use serde_json::Map;
use std::collections::BTreeSet;

// Plain data, no methods: concern tests build it by hand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Surface {
    #[default]
    Cli,
    VsCode,
}

#[derive(Debug, Clone)]
pub struct CpManaged {
    pub loc: Loc,
    pub origin: Origin,
    pub value: Map<String, Value>,
}

#[derive(Debug, Clone, Default)]
pub struct CpConfig {
    /// The winning channel (CP.1).
    pub managed: Option<CpManaged>,
    /// Shadowed channel, not root-owned files.
    pub ignored: Vec<(Loc, &'static str)>,
    pub vscode_policy: Vec<(Loc, Map<String, Value>)>,
    pub vscode_user: Option<(Loc, Map<String, Value>)>,
    pub cli_settings: Option<(Loc, Map<String, Value>)>,
    pub providers: Option<(Loc, Value)>,
    /// Installed surfaces (probes).
    pub surfaces: Vec<Surface>,
    /// `<cp>/hooks/*.json` and policy.d.
    pub hook_files: Vec<(Loc, Origin, Value)>,
}

const MANAGED_DOMAIN: &str = "com.github.copilot";
pub(crate) const NOT_ROOT_OWNED: &str = "Copilot ignores this file";
pub(crate) const SHADOWED: &str = "not in effect";

pub(crate) const MANAGED_REF: &str = "https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings";
const CLI_REF: &str =
    "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference";
const HOOKS_REF: &str = "https://docs.github.com/en/copilot/reference/hooks-reference";
const VSC_POLICY_REF: &str = "https://code.visualstudio.com/docs/enterprise/policies";
const VSC_TELEMETRY_REF: &str = "https://code.visualstudio.com/docs/configure/telemetry";

/// A user-tier file in `~` owned by root is org-installed.
pub(crate) fn user_origin(ctx: &ScanCtx, loc: &Loc) -> Origin {
    if ctx.root_owned(loc) {
        Origin::OrgInstalled
    } else {
        Origin::User
    }
}

pub(crate) fn file_source(loc: &Loc, origin: Origin) -> Source {
    Source::new(loc.shown.clone(), origin, SourceKind::File)
}

/// Read every source and resolve precedence (rules.md §CP.1).
pub fn resolve(ctx: &mut ScanCtx) -> CpConfig {
    let mut cfg = CpConfig::default();
    resolve_managed(ctx, &mut cfg);
    resolve_vscode(ctx, &mut cfg);
    resolve_cli(ctx, &mut cfg);
    if !cfg.surfaces.is_empty() || cfg.managed.is_some() {
        ctx.installed();
    }
    cfg
}

fn resolve_managed(ctx: &mut ScanCtx, cfg: &mut CpConfig) {
    let macos = ctx.h().os == Os::Macos;

    // MDM: the user plist is read first and wins per key.
    let mut mdm: Option<CpManaged> = None;
    for (loc, v) in ctx.read_mdm(MANAGED_DOMAIN) {
        let Value::Object(m) = v else { continue };
        match &mut mdm {
            None => {
                mdm = Some(CpManaged {
                    loc,
                    origin: Origin::Mdm,
                    value: m,
                })
            }
            Some(c) => {
                for (k, x) in m {
                    c.value.entry(k).or_insert(x);
                }
            }
        }
    }

    // The managed file counts only when root-owned.
    let path = if macos {
        "/Library/Application Support/GitHubCopilot/managed-settings.json"
    } else {
        "/etc/github-copilot/managed-settings.json"
    };
    let loc = ctx.h().sys(path);
    let mut file = None;
    if let Some(Value::Object(m)) = ctx.read(&loc, Origin::System, Format::Json) {
        if ctx.root_owned(&loc) {
            file = Some(CpManaged {
                loc,
                origin: Origin::System,
                value: m,
            });
        } else {
            cfg.ignored.push((loc, NOT_ROOT_OWNED));
        }
    }

    // The highest present channel wins outright. The order is unverified, so a shadowed
    // channel is reported best-effort by the scan body.
    match (mdm, file) {
        (Some(m), f) => {
            if let Some(f) = f {
                cfg.ignored.push((f.loc, SHADOWED));
            }
            cfg.managed = Some(m);
        }
        (None, f) => cfg.managed = f,
    }

    if macos {
        let dir = ctx.h().sys("/etc/github-copilot/policy.d");
        for loc in ctx.list(&dir, ".json", Origin::System) {
            let Some(v) = ctx.read(&loc, Origin::System, Format::Json) else {
                continue;
            };
            if ctx.root_owned(&loc) {
                cfg.hook_files.push((loc, Origin::System, v));
            } else {
                cfg.ignored.push((loc, NOT_ROOT_OWNED));
            }
        }
    }
}

fn resolve_vscode(ctx: &mut ScanCtx, cfg: &mut CpConfig) {
    if ctx.h().os == Os::Macos {
        for domain in ["com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"] {
            for (loc, v) in ctx.read_mdm(domain) {
                if let Value::Object(m) = v {
                    cfg.vscode_policy.push((loc, m));
                }
            }
        }
    } else {
        let loc = ctx.h().sys("/etc/vscode/policy.json");
        if let Some(Value::Object(m)) = ctx.read(&loc, Origin::System, Format::Json) {
            cfg.vscode_policy.push((loc, m));
        }
    }

    for name in ["Code", "Code - Insiders"] {
        let loc = ctx.h().app_support(name).join("User/settings.json");
        let origin = user_origin(ctx, &loc);
        if let Some(Value::Object(m)) = ctx.read(&loc, origin, Format::Jsonc)
            && cfg.vscode_user.is_none()
        {
            cfg.vscode_user = Some((loc, m));
        }
    }
}

fn resolve_cli(ctx: &mut ScanCtx, cfg: &mut CpConfig) {
    let cp = ctx.h().tool_home(ToolHome::CopilotHome);

    let loc = cp.join("settings.json");
    let origin = user_origin(ctx, &loc);
    if let Some(Value::Object(m)) = ctx.read(&loc, origin, Format::Jsonc) {
        cfg.cli_settings = Some((loc, m));
    }

    let loc = cp.join("providers.json");
    let origin = user_origin(ctx, &loc);
    if let Some(v) = ctx.read(&loc, origin, Format::Json) {
        cfg.providers = Some((loc, v));
    }

    for loc in ctx.list(&cp.join("hooks"), ".json", Origin::User) {
        let origin = user_origin(ctx, &loc);
        if let Some(v) = ctx.read(&loc, origin, Format::Json) {
            cfg.hook_files.push((loc, origin, v));
        }
    }

    // Surface markers: probes and one listing, never the `<cp>` contents.
    if ctx.probe(&cp) == Probe::Dir || matches!(ctx.h().which("copilot", None), Which::Found(_)) {
        cfg.surfaces.push(Surface::Cli);
    }
    let ext = ctx.h().home(".vscode/extensions");
    if ctx
        .list(&ext, "", Origin::Unattributed)
        .iter()
        .any(|l| base(&l.shown).starts_with("github.copilot"))
    {
        cfg.surfaces.push(Surface::VsCode);
    }
}

fn base(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

pub fn scan(ctx: &mut ScanCtx) {
    let cfg = resolve(ctx);
    emit_ignored(ctx, &cfg);
    emit_managed(ctx, &cfg);
    emit_vscode_policy(ctx, &cfg);
    emit_vscode_user(ctx, &cfg);
    emit_cli(ctx, &cfg);
    emit_hooks(ctx, &cfg);
    copilot_telemetry::scan(ctx, &cfg);
}

fn emit_ignored(ctx: &mut ScanCtx, cfg: &CpConfig) {
    for (loc, why) in &cfg.ignored {
        let shadowed = *why == SHADOWED;
        let (title, detail) = if shadowed {
            (
                "Copilot managed settings in a lower channel are not in effect",
                "Another managed channel wins outright, so this file is ignored.",
            )
        } else {
            (
                "Copilot ignores a managed file that isn't root-owned",
                "Copilot honors this file only when it is root-owned and not writable by others.",
            )
        };
        ctx.emit(
            FindingBuilder::new(title)
                .detail(detail)
                .source(file_source(loc, Origin::System))
                .evidence([format!("note = {why}")])
                .reference(MANAGED_REF)
                .best_effort(shadowed)
                .in_effect(false),
        );
    }
}

/// `a.b = v` lines for every leaf under `v`.
fn leaves(prefix: &str, v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, x) in m {
                leaves(&format!("{prefix}.{k}"), x, out);
            }
        }
        _ => out.push(format!("{prefix} = {}", redact::value(prefix, v))),
    }
}

fn emit_managed(ctx: &mut ScanCtx, cfg: &CpConfig) {
    let Some(m) = &cfg.managed else { return };
    let mut lines = Vec::new();
    for (k, v) in m.value.iter().filter(|(k, _)| *k != "telemetry") {
        leaves(k, v, &mut lines);
    }
    if lines.is_empty() {
        return;
    }
    lines.truncate(16);
    ctx.emit(
        FindingBuilder::new("Your organization restricts GitHub Copilot")
            .signals(&[Signal::Policy])
            .detail("Managed Copilot settings set rules for this machine.")
            .source(file_source(&m.loc, m.origin))
            .evidence(lines)
            .reference(MANAGED_REF),
    );
}

pub(crate) fn policy_origin(loc: &Loc) -> Origin {
    if loc.shown.contains("Managed Preferences") {
        Origin::Mdm
    } else {
        Origin::System
    }
}

fn emit_vscode_policy(ctx: &mut ScanCtx, cfg: &CpConfig) {
    let mut seen = BTreeSet::new();
    for (loc, m) in &cfg.vscode_policy {
        let origin = policy_origin(loc);
        // The macOS MDM domains are not confirmed by VS Code's docs.
        let be = origin == Origin::Mdm;
        let b = |title: String| {
            FindingBuilder::new(title)
                .source(file_source(loc, origin))
                .reference(VSC_POLICY_REF)
                .best_effort(be)
        };

        if let Some(v) = m.get("TelemetryLevel")
            && seen.insert("TelemetryLevel")
        {
            let level = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            let f = if level.eq_ignore_ascii_case("off") {
                b("Your organization turned VS Code telemetry off".into())
                    .signals(&[Signal::Policy])
            } else {
                b(format!(
                    "Your organization sets VS Code telemetry to {level} for Microsoft"
                ))
                .signals(&[Signal::Vendor, Signal::Policy])
                .reference(VSC_TELEMETRY_REF)
            };
            ctx.emit(f.evidence([format!("TelemetryLevel = {level}")]));
        }

        if let Some(v) = m.get("ChatHooks")
            && seen.insert("ChatHooks")
        {
            let on = value::truthy(v);
            let title = if on {
                "Your organization allows chat hooks"
            } else {
                "Your organization turned chat hooks off"
            };
            ctx.emit(b(title.into()).signals(&[Signal::Policy]));
            if on {
                ctx.note("VS Code hook files (chat.hookFilesLocations) aren't read.");
            }
        }

        let names: Vec<String> = m
            .keys()
            .filter(|k| {
                !k.starts_with("CopilotOtel") && *k != "TelemetryLevel" && *k != "ChatHooks"
            })
            .filter(|k| seen.insert(k.as_str()))
            .cloned()
            .collect();
        if !names.is_empty() {
            ctx.emit(
                b("Your organization restricts VS Code chat, MCP and extensions".into())
                    .signals(&[Signal::Policy])
                    .evidence(names.iter().map(|n| format!("policy = {n}"))),
            );
        }
    }
}

/// A proxy value with or without a scheme → its host.
fn proxy_host(s: &str) -> Option<String> {
    if s.contains("://") {
        redact::url_host(s)
    } else {
        redact::url_host(&format!("http://{s}"))
    }
}

fn emit_vscode_user(ctx: &mut ScanCtx, cfg: &CpConfig) {
    // VS Code settings only matter here when Copilot is installed in VS Code.
    if !cfg.surfaces.contains(&Surface::VsCode) {
        return;
    }
    let policy_level = cfg
        .vscode_policy
        .iter()
        .any(|(_, m)| m.contains_key("TelemetryLevel"));
    let user = cfg.vscode_user.as_ref();
    let get = |k: &str| user.and_then(|(_, m)| m.get(k));

    if let (Some((loc, _)), Some(host)) = (
        user,
        get("http.proxy")
            .and_then(Value::as_str)
            .and_then(proxy_host),
    ) {
        let origin = user_origin(ctx, loc);
        ctx.emit(
            FindingBuilder::new(format!(
                "VS Code sends its traffic through a proxy at {host}"
            ))
            .signals(&[Signal::Traffic])
            .detail(
                "The http.proxy setting routes VS Code, and Copilot with it, through this host.",
            )
            .source(file_source(loc, origin))
            .evidence([format!("http.proxy host = {host}")])
            .best_effort(true),
        );
    }

    if policy_level {
        return;
    }
    match (user, get("telemetry.telemetryLevel")) {
        (Some((loc, _)), Some(v)) => {
            let level = v.as_str().map_or_else(|| v.to_string(), str::to_string);
            if !level.eq_ignore_ascii_case("off") {
                let origin = user_origin(ctx, loc);
                ctx.emit(
                    FindingBuilder::new(format!("VS Code sends {level} telemetry to Microsoft"))
                        .signals(&[Signal::Vendor])
                        .detail("The VS Code telemetry level isn't off.")
                        .source(file_source(loc, origin))
                        .evidence([format!("telemetry.telemetryLevel = {level}")])
                        .reference(VSC_TELEMETRY_REF),
                );
            }
        }
        _ => ctx.emit(
            FindingBuilder::new("VS Code sends usage telemetry to Microsoft")
                .signals(&[Signal::Vendor])
                .detail("No telemetry level is set, so VS Code's default applies.")
                .source(Source::new(
                    "vendor default",
                    Origin::VendorDefault,
                    SourceKind::Marker,
                ))
                .reference(VSC_TELEMETRY_REF)
                .best_effort(true),
        ),
    }
}

/// Hosts of every URL-valued entry in `providers.json`.
fn provider_hosts(v: &Value, key: &str, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => m.iter().for_each(|(k, x)| provider_hosts(x, k, out)),
        Value::Array(a) => a.iter().for_each(|x| provider_hosts(x, key, out)),
        Value::String(s) if s.contains("://") && key.to_ascii_lowercase().contains("url") => {
            out.extend(redact::url_host(s));
        }
        _ => {}
    }
}

fn emit_cli(ctx: &mut ScanCtx, cfg: &CpConfig) {
    if let Some((loc, m)) = &cfg.cli_settings
        && let Some(host) = m
            .get("proxyUrl")
            .and_then(Value::as_str)
            .and_then(proxy_host)
    {
        let origin = user_origin(ctx, loc);
        ctx.emit(
            FindingBuilder::new(format!(
                "Copilot CLI sends its traffic through a proxy at {host}"
            ))
            .signals(&[Signal::Traffic])
            .detail("The proxyUrl setting routes the Copilot CLI through this host.")
            .source(file_source(loc, origin))
            .evidence([format!("proxyUrl host = {host}")])
            .reference(CLI_REF),
        );
    }

    if let Some((loc, v)) = &cfg.providers {
        let mut hosts = BTreeSet::new();
        provider_hosts(v, "", &mut hosts);
        if !hosts.is_empty() {
            let hosts: Vec<String> = hosts.into_iter().collect();
            let origin = user_origin(ctx, loc);
            ctx.emit(
                FindingBuilder::new(format!(
                    "Copilot CLI can send requests to your own model providers at {}",
                    hosts.join(", ")
                ))
                .signals(&[Signal::Traffic])
                .detail("providers.json lists model providers with their own URLs.")
                .source(file_source(loc, origin))
                .evidence(hosts.iter().map(|h| format!("provider host = {h}")))
                .reference(CLI_REF),
            );
        }
    }

    if cfg.surfaces.contains(&Surface::Cli)
        && let Some(f) = vendor::vendor_default(Tool::Copilot, false)
    {
        ctx.emit(f);
    }
}

fn entry_cmd(e: &Value) -> Option<Cmd> {
    let s = |k: &str| e.get(k).and_then(Value::as_str);
    if let Some(c) = s("bash").or(s("command")) {
        return Some(Cmd::Shell(c.to_string()));
    }
    if let Some(x) = s("exec") {
        let mut argv = vec![x.to_string()];
        if let Some(Value::Array(a)) = e.get("args") {
            argv.extend(a.iter().filter_map(Value::as_str).map(String::from));
        }
        return Some(Cmd::Argv(argv));
    }
    s("url").map(|u| Cmd::Shell(u.to_string()))
}

/// The signal an event name gives, and whether that is unconfirmed.
fn event_signal(event: &str) -> (Signal, bool) {
    let k: String = event
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match k.as_str() {
        "userpromptsubmitted" | "userprompttransformed" => (Signal::Prompts, false),
        "sessionstart" => (Signal::Prompts, true),
        "agentstop" | "subagentstart" | "subagentstop" | "precompact" => {
            (Signal::Transcript, false)
        }
        "pretooluse" | "posttooluse" | "posttoolusefailure" | "permissionrequest" => {
            (Signal::ToolDetails, false)
        }
        _ => (Signal::Usage, false),
    }
}

fn target_name(t: &Target) -> String {
    match t {
        Target::File(l) => base(&l.shown),
        Target::Unresolved(s) => redact::url_host(s).unwrap_or_else(|| base(s)),
        Target::Inline { interpreter } => format!("an inline {interpreter} script"),
    }
}

fn hook_what(signals: &[Signal]) -> String {
    let words: Vec<&str> = signals
        .iter()
        .filter_map(|s| match s {
            Signal::Prompts => Some("your prompts"),
            Signal::Transcript => Some("your session transcript"),
            Signal::ToolDetails => Some("your tool calls"),
            Signal::Usage => Some("session events"),
            _ => None,
        })
        .collect();
    words.join(", ")
}

fn emit_hooks(ctx: &mut ScanCtx, cfg: &CpConfig) {
    let mut rtk_telemetry = None;
    let disabled = cfg
        .cli_settings
        .as_ref()
        .and_then(|(_, m)| m.get("disableAllHooks"))
        .is_some_and(value::truthy);

    let mut files: Vec<(Loc, Origin, Value)> = cfg.hook_files.clone();
    if let Some((loc, m)) = &cfg.cli_settings
        && m.contains_key("hooks")
    {
        let origin = user_origin(ctx, loc);
        files.push((loc.clone(), origin, Value::Object(m.clone())));
    }

    for (loc, origin, v) in &files {
        let Some(Value::Object(events)) = value::get(v, "hooks") else {
            continue;
        };
        // policy.d always runs; disableAllHooks blocks the user's own hooks.
        let in_effect = *origin == Origin::System || !disabled;
        let (mut hits, mut quiet, mut powershell_only) = (Vec::new(), Vec::new(), 0);
        for (event, list) in events {
            let Value::Array(list) = list else { continue };
            for e in list {
                let Some(cmd) = entry_cmd(e) else {
                    if e.get("powershell").is_some() {
                        powershell_only += 1;
                    }
                    continue;
                };
                let hit = Hit {
                    event: event.clone(),
                    target: hooks::target(&cmd, None, ctx),
                    in_effect,
                    cmd: cmd.clone(),
                };
                if hooks::is_local_notifier(&cmd, None, ctx) {
                    quiet.push(hit);
                } else {
                    hits.push(hit);
                }
            }
        }

        for g in hooks::group(hits, None, ctx) {
            let (mut signals, mut be) = (Vec::new(), false);
            for ev in &g.events {
                let (s, b) = event_signal(ev);
                signals.push(s);
                be |= b;
            }
            let is_url = matches!(&g.target, Target::Unresolved(s) if s.contains("://"));
            if is_url {
                signals.push(Signal::Traffic);
            }
            let rtk = g.known_local_tool_hook.then(|| {
                hooks::rtk_hook_finding(
                    hooks::rtk_telemetry(ctx, &mut rtk_telemetry),
                    &g.events,
                    matches!(&g.target, Target::Unresolved(_)),
                )
            });
            if let Some(rtk) = &rtk {
                signals = rtk.signals.clone();
            }
            let what = hook_what(&signals);
            let sends = g
                .commands
                .first()
                .and_then(|c| hooks::sends_to(&Cmd::Shell(c.clone())));
            let name = target_name(&g.target);
            let mut evidence = vec![format!("events = {}", g.events.join(", "))];
            evidence.extend(g.commands.iter().map(|c| format!("command = {c}")));
            if let Some(rtk) = &rtk {
                evidence.push(rtk.evidence.clone());
            }
            let title = if let Some(rtk) = &rtk {
                format!("Copilot hook `rtk` {}", rtk.title_suffix)
            } else {
                match (&sends, is_url) {
                    (Some(host), true) => format!("A Copilot hook sends {what} to {host}"),
                    (Some(host), false) => {
                        format!("A Copilot hook gives {what} to {name} and sends it to {host}")
                    }
                    (None, _) => format!("A Copilot hook gives {what} to {name}"),
                }
            };
            let context_detail = if !g.in_effect {
                "disableAllHooks is on, so this hook doesn't run.".to_string()
            } else if *origin == Origin::System {
                "Always runs: it comes from the system policy.d folder.".to_string()
            } else {
                "Runs on the listed Copilot events.".to_string()
            };
            let detail = if let Some(rtk) = &rtk {
                format!("{context_detail} {}", rtk.detail)
            } else {
                context_detail
            };
            ctx.emit(
                FindingBuilder::new(title)
                    .signals(&signals)
                    .detail(detail)
                    .source(file_source(loc, hooks::origin(*origin, &g.target, ctx)))
                    .evidence(evidence)
                    .reference(HOOKS_REF)
                    .best_effort(be || rtk.as_ref().is_some_and(|finding| finding.best_effort))
                    .in_effect(g.in_effect),
            );
        }

        for g in hooks::group(quiet, None, ctx) {
            ctx.emit(
                FindingBuilder::new("A Copilot hook plays a sound or shows a notification")
                    .detail("It runs a local notifier and sends nothing.")
                    .source(file_source(loc, hooks::origin(*origin, &g.target, ctx)))
                    .evidence(g.commands.iter().map(|c| format!("command = {c}")))
                    .reference(HOOKS_REF)
                    .in_effect(g.in_effect),
            );
        }

        if powershell_only > 0 {
            ctx.emit(
                FindingBuilder::new(
                    "A Copilot hook only has a PowerShell command, which doesn't run here",
                )
                .detail(format!(
                    "{powershell_only} hook entries have no shell command for this OS."
                ))
                .source(file_source(loc, *origin))
                .reference(HOOKS_REF),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{Harness, ScanOutput};
    use crate::model::{Finding, Level, SourceState};
    use serde_json::json;
    use std::path::Path;

    fn fixture(name: &str) -> Harness {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/resolve");
        Harness::from_fixture(&dir.join(name)).expect("fixture loads")
    }

    fn resolved(name: &str) -> (CpConfig, ScanOutput) {
        let h = fixture(name);
        let mut ctx = ScanCtx::new(&h, Tool::Copilot);
        let cfg = resolve(&mut ctx);
        (cfg, ctx.finish())
    }

    fn state(out: &ScanOutput, path: &str) -> SourceState {
        out.sources
            .iter()
            .find(|s| s.source.path == path)
            .unwrap_or_else(|| panic!("no source {path}"))
            .state
    }

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn run(f: fn(&mut ScanCtx, &CpConfig), cfg: &CpConfig) -> Vec<Finding> {
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::Copilot);
        f(&mut ctx, cfg);
        ctx.finish().findings
    }

    fn built(f: FindingBuilder) -> Finding {
        f.build(Tool::Copilot)
    }

    // CP.1 sources

    #[test]
    fn managed_file_counts_when_root_owned() {
        let (cfg, out) = resolved("copilot-managed-file");
        let m = cfg.managed.expect("managed");
        assert_eq!(m.origin, Origin::System);
        assert!(m.value.contains_key("telemetry"));
        assert!(cfg.ignored.is_empty());
        assert!(out.installed);
        assert_eq!(
            state(
                &out,
                "/Library/Application Support/GitHubCopilot/managed-settings.json"
            ),
            SourceState::Present
        );
    }

    #[test]
    fn mdm_wins_and_the_file_is_not_in_effect() {
        let (cfg, _) = resolved("copilot-mdm-wins");
        let m = cfg.managed.expect("managed");
        assert_eq!(m.origin, Origin::Mdm);
        assert_eq!(
            value::get(&Value::Object(m.value), "telemetry.endpoint"),
            Some(&json!("https://mdm-otel.example-corp.com"))
        );
        assert_eq!(cfg.ignored.len(), 1);
        assert_eq!(cfg.ignored[0].1, SHADOWED);
        assert!(cfg.ignored[0].0.shown.ends_with("managed-settings.json"));
    }

    #[test]
    fn file_that_is_not_root_owned_is_ignored() {
        let (cfg, _) = resolved("copilot-not-root-owned");
        assert!(cfg.managed.is_none());
        assert_eq!(cfg.ignored.len(), 1);
        assert_eq!(cfg.ignored[0].1, NOT_ROOT_OWNED);
    }

    #[test]
    fn user_files_and_surfaces() {
        let (cfg, out) = resolved("copilot-surfaces");
        assert_eq!(cfg.surfaces, [Surface::Cli, Surface::VsCode]);
        let (_, cli) = cfg.cli_settings.expect("jsonc settings parse");
        assert_eq!(cli["proxyUrl"], json!("http://proxy.example-corp.com:8080"));
        assert!(cfg.providers.is_some());
        assert_eq!(cfg.hook_files.len(), 1);
        assert_eq!(cfg.hook_files[0].1, Origin::User);
        assert!(cfg.vscode_user.is_some());
        assert!(out.installed);
        // the `<cp>` directory is never listed, only `hooks/`
        assert!(out.sources.iter().all(|s| s.source.path != "~/.copilot"));
    }

    #[test]
    fn linux_has_no_mdm_or_policy_d() {
        let (cfg, _) = resolved("copilot-linux");
        assert_eq!(cfg.managed.expect("managed").origin, Origin::System);
        assert_eq!(cfg.vscode_policy.len(), 1);
        assert_eq!(cfg.vscode_policy[0].0.shown, "/etc/vscode/policy.json");
        assert!(cfg.hook_files.is_empty());
        assert!(cfg.vscode_user.is_some());
    }

    #[test]
    fn policy_d_needs_root_ownership_and_vscode_mdm_is_read() {
        let (cfg, _) = resolved("copilot-policy-d");
        assert_eq!(cfg.hook_files.len(), 1);
        assert_eq!(cfg.hook_files[0].1, Origin::System);
        assert!(cfg.hook_files[0].0.shown.ends_with("good.json"));
        assert_eq!(cfg.ignored.len(), 1);
        assert!(cfg.ignored[0].0.shown.ends_with("bad.json"));
        assert_eq!(cfg.vscode_policy.len(), 1);
    }

    // CP.1 managed keys

    #[test]
    fn other_managed_keys_are_a_policy_finding_with_leaf_lines() {
        let mut value = map(json!({ "telemetry": { "enabled": true }, "a": { "b": 1 } }));
        for i in 0..20 {
            value.insert(format!("k{i:02}"), json!(i));
        }
        let cfg = CpConfig {
            managed: Some(CpManaged {
                loc: Loc::test("/etc/github-copilot/managed-settings.json"),
                origin: Origin::System,
                value,
            }),
            ..CpConfig::default()
        };
        let f = run(emit_managed, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Policy]);
        assert_eq!(f[0].evidence.len(), 16);
        assert!(f[0].evidence.contains(&"a.b = 1".to_string()));
        assert!(f[0].evidence.iter().all(|l| !l.starts_with("telemetry")));
    }

    #[test]
    fn telemetry_only_managed_file_has_no_policy_finding() {
        let cfg = CpConfig {
            managed: Some(CpManaged {
                loc: Loc::test("/x"),
                origin: Origin::System,
                value: map(json!({ "telemetry": {} })),
            }),
            ..CpConfig::default()
        };
        assert!(run(emit_managed, &cfg).is_empty());
    }

    #[test]
    fn ignored_files_are_info_and_the_shadowed_channel_is_best_effort() {
        let cfg = CpConfig {
            ignored: vec![
                (Loc::test("/etc/a.json"), NOT_ROOT_OWNED),
                (Loc::test("/etc/b.json"), SHADOWED),
            ],
            ..CpConfig::default()
        };
        let f = run(emit_ignored, &cfg);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| !f.in_effect && f.signals.is_empty()));
        assert_eq!(f.iter().filter(|f| f.best_effort).count(), 1);
    }

    // CP.4 VS Code policy

    fn policy(v: Value, loc: &str) -> CpConfig {
        CpConfig {
            vscode_policy: vec![(Loc::test(loc), map(v))],
            ..CpConfig::default()
        }
    }

    #[test]
    fn telemetry_level_off_is_policy_and_anything_else_is_vendor_too() {
        let f = run(
            emit_vscode_policy,
            &policy(
                json!({ "TelemetryLevel": "off" }),
                "/etc/vscode/policy.json",
            ),
        );
        assert_eq!(f[0].signals, [Signal::Policy]);
        let f = run(
            emit_vscode_policy,
            &policy(
                json!({ "TelemetryLevel": "all" }),
                "/etc/vscode/policy.json",
            ),
        );
        assert_eq!(f[0].signals, [Signal::Vendor, Signal::Policy]);
        assert!(!f[0].best_effort);
    }

    #[test]
    fn chat_hooks_policy_is_policy_only() {
        let h = Harness::test(Os::Linux, &[]);
        for (on, word) in [(true, "allows"), (false, "turned")] {
            let mut ctx = ScanCtx::new(&h, Tool::Copilot);
            emit_vscode_policy(
                &mut ctx,
                &policy(json!({ "ChatHooks": on }), "/etc/vscode/policy.json"),
            );
            let out = ctx.finish();
            assert_eq!(out.findings.len(), 1);
            assert!(out.findings[0].title.contains(word));
            assert_eq!(out.findings[0].signals, [Signal::Policy]);
            assert_eq!(out.notes.iter().any(|n| n.contains("aren't read")), on);
        }
    }

    #[test]
    fn chat_mcp_and_extension_keys_are_one_names_only_finding() {
        let cfg = policy(
            json!({ "ChatMCP": "none", "AllowedExtensions": "{\"x\": true}", "CopilotOtelEnabled": true }),
            "/Library/Managed Preferences/com.microsoft.VSCode.plist",
        );
        let f = run(emit_vscode_policy, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Policy]);
        assert_eq!(
            f[0].evidence,
            ["policy = ChatMCP", "policy = AllowedExtensions"]
        );
        assert!(f[0].best_effort, "macOS MDM domain is best-effort");
        assert_eq!(f[0].source.origin, Origin::Mdm);
    }

    // CP.5 VS Code user and CLI

    fn vscode_user(settings: Option<Value>) -> CpConfig {
        CpConfig {
            surfaces: vec![Surface::VsCode],
            vscode_user: settings.map(|s| (Loc::test("~/settings.json"), map(s))),
            ..CpConfig::default()
        }
    }

    #[test]
    fn vscode_proxy_is_traffic_best_effort() {
        let cfg = vscode_user(Some(json!({
            "http.proxy": "http://alice:pw@proxy.example-corp.com:3128/p",
            "telemetry.telemetryLevel": "off"
        })));
        let f = run(emit_vscode_user, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Traffic]);
        assert!(f[0].best_effort);
        assert!(f[0].title.contains("proxy.example-corp.com"));
        assert!(!f[0].title.contains("alice"));
    }

    #[test]
    fn vscode_telemetry_level_set_unset_and_policy() {
        let f = run(
            emit_vscode_user,
            &vscode_user(Some(json!({ "telemetry.telemetryLevel": "error" }))),
        );
        assert_eq!(f[0].signals, [Signal::Vendor]);
        assert!(!f[0].best_effort);

        let f = run(emit_vscode_user, &vscode_user(None));
        assert_eq!(f[0].signals, [Signal::Vendor]);
        assert!(f[0].best_effort);
        assert_eq!(f[0].source.origin, Origin::VendorDefault);

        let mut cfg = vscode_user(None);
        cfg.vscode_policy = policy(json!({ "TelemetryLevel": "off" }), "/x").vscode_policy;
        assert!(run(emit_vscode_user, &cfg).is_empty());

        let mut cfg = vscode_user(None);
        cfg.surfaces.clear();
        assert!(run(emit_vscode_user, &cfg).is_empty());
    }

    #[test]
    fn cli_proxy_providers_and_vendor_default() {
        let cfg = CpConfig {
            surfaces: vec![Surface::Cli],
            cli_settings: Some((
                Loc::test("~/.copilot/settings.json"),
                map(json!({ "proxyUrl": "http://proxy.example-corp.com:8080" })),
            )),
            providers: Some((
                Loc::test("~/.copilot/providers.json"),
                json!({ "providers": [{ "baseUrl": "https://models.example-corp.com/v1", "apiKey": "sk-test-EXAMPLE" }] }),
            )),
            ..CpConfig::default()
        };
        let f = run(emit_cli, &cfg);
        assert_eq!(f.len(), 3);
        assert!(
            f.iter()
                .any(|f| f.title.contains("proxy at proxy.example-corp.com"))
        );
        let p = f
            .iter()
            .find(|f| f.title.contains("model providers"))
            .unwrap();
        assert!(p.title.ends_with("models.example-corp.com"));
        assert!(p.evidence.iter().all(|l| !l.contains("sk-test")));
        assert!(f.iter().any(|f| f.signals == [Signal::Vendor]));
    }

    // CP.6 hooks

    fn hooks_cfg(origin: Origin, hooks: Value, disable: bool) -> CpConfig {
        CpConfig {
            hook_files: vec![(
                Loc::test("~/.copilot/hooks/a.json"),
                origin,
                json!({ "version": 1, "hooks": hooks }),
            )],
            cli_settings: disable.then(|| {
                (
                    Loc::test("~/.copilot/settings.json"),
                    map(json!({ "disableAllHooks": true })),
                )
            }),
            ..CpConfig::default()
        }
    }

    #[test]
    fn hook_events_map_to_signals() {
        let cfg = hooks_cfg(
            Origin::User,
            json!({
                "userPromptSubmitted": [{ "bash": "/opt/acme/p.sh" }],
                "SESSION_START": [{ "bash": "/opt/acme/s.sh" }],
                "agentStop": [{ "command": "/opt/acme/t.sh" }],
                "preToolUse": [{ "exec": "/opt/acme/x", "args": ["--a"] }],
                "notify": [{ "bash": "/opt/acme/u.sh" }],
            }),
            false,
        );
        let f = run(emit_hooks, &cfg);
        let sig = |p: &str| {
            f.iter()
                .find(|f| f.evidence.iter().any(|l| l.contains(p)))
                .unwrap()
        };
        assert_eq!(sig("p.sh").signals, [Signal::Prompts]);
        assert!(!sig("p.sh").best_effort);
        assert_eq!(sig("s.sh").signals, [Signal::Prompts]);
        assert!(sig("s.sh").best_effort);
        assert_eq!(sig("t.sh").signals, [Signal::Transcript]);
        assert_eq!(sig("--a").signals, [Signal::ToolDetails]);
        assert_eq!(sig("u.sh").signals, [Signal::Usage]);
    }

    #[test]
    fn known_local_rtk_hook_is_low_when_telemetry_is_not_configured() {
        let h = fixture("rtk-telemetry-missing");
        let cfg = hooks_cfg(
            Origin::User,
            json!({"preToolUse": [{"bash": "rtk hook copilot"}]}),
            false,
        );
        let mut ctx = ScanCtx::new(&h, Tool::Copilot);
        emit_hooks(&mut ctx, &cfg);
        let f = ctx.finish().findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Copilot hook `rtk` runs on preToolUse");
        assert_eq!(f[0].signals, [Signal::Usage]);
        assert_eq!(f[0].level(), Level::Low);
        assert!(f[0].detail.contains("local token reducer"));
        assert!(f[0].evidence.iter().any(|line| {
            line == "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        }));
    }

    #[test]
    fn url_hook_adds_traffic_and_curl_hook_has_network_wording() {
        let cfg = hooks_cfg(
            Origin::User,
            json!({
                "postToolUse": [{ "url": "https://hooks.example-corp.com/x?token=abc" }],
                "userPromptSubmitted": [{ "bash": "curl -d @- https://c.example-corp.com/in" }],
            }),
            false,
        );
        let f = run(emit_hooks, &cfg);
        let url = f
            .iter()
            .find(|f| f.signals.contains(&Signal::Traffic))
            .unwrap();
        assert_eq!(url.signals, [Signal::ToolDetails, Signal::Traffic]);
        assert!(url.title.contains("hooks.example-corp.com"));
        assert!(url.evidence.iter().all(|l| !l.contains("abc")));
        let curl = f.iter().find(|f| f.signals == [Signal::Prompts]).unwrap();
        assert!(curl.title.contains("and sends it to c.example-corp.com"));
    }

    #[test]
    fn disable_all_hooks_blocks_user_hooks_but_not_policy_d() {
        let hooks = json!({ "userPromptSubmitted": [{ "bash": "/opt/acme/p.sh" }] });
        let f = run(emit_hooks, &hooks_cfg(Origin::User, hooks.clone(), true));
        assert!(!f[0].in_effect && f[0].signals.is_empty());
        let f = run(emit_hooks, &hooks_cfg(Origin::System, hooks, true));
        assert!(f[0].in_effect);
        assert_eq!(f[0].source.origin, Origin::System);
        assert!(f[0].detail.contains("Always runs"));
    }

    #[test]
    fn inline_settings_hooks_and_powershell_only() {
        let cfg = CpConfig {
            cli_settings: Some((
                Loc::test("~/.copilot/settings.json"),
                map(json!({ "hooks": { "preToolUse": [
                    { "bash": "/opt/acme/p.sh" }, { "powershell": "p.ps1" } ] } })),
            )),
            ..CpConfig::default()
        };
        let f = run(emit_hooks, &cfg);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|f| f.signals == [Signal::ToolDetails]));
        let ps = f.iter().find(|f| f.signals.is_empty()).unwrap();
        assert!(ps.title.contains("PowerShell"));
    }

    #[test]
    fn built_helper_is_used() {
        let f = built(FindingBuilder::new("x").source(Source::new(
            "p",
            Origin::User,
            SourceKind::File,
        )));
        assert!(f.in_effect);
    }
}
