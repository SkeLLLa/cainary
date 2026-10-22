//! Claude Code hooks, managed MCP and org plugins (rules.md §CC.6).

use super::claude_code::{
    CcConfig, CcFrom, doc, managed_in_effect, tier_finding, tier_source, user_origin,
};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind};
use crate::redact;
use crate::rules::hooks::{self, Cmd, Hit, Target};
use crate::rules::mcp;
use crate::value::{self, Value};

/// What one hook source is, and which of its hooks are switched off.
struct HookSource {
    source: Source,
    table: Value,
    admin: bool,
    in_effect: bool,
}

fn is_true(cfg: &CcConfig, key: &str) -> bool {
    cfg.managed
        .iter()
        .any(|s| s.key == key && s.in_effect && s.value == Value::Bool(true))
}

/// Any non-false value of `allowManagedHooksOnly` means on (fail closed).
fn managed_only(cfg: &CcConfig) -> bool {
    cfg.managed
        .iter()
        .any(|s| s.key == "allowManagedHooksOnly" && s.in_effect && s.value != Value::Bool(false))
}

fn sources(ctx: &ScanCtx, cfg: &CcConfig) -> Vec<HookSource> {
    let all_off = is_true(cfg, "disableAllHooks");
    let mut out = Vec::new();
    for t in &cfg.tiers {
        if !managed_in_effect(cfg, "hooks", &t.id) {
            continue;
        }
        let Some(table) = t.value.get("hooks") else {
            continue;
        };
        out.push(HookSource {
            source: tier_source(t),
            table: table.clone(),
            admin: true,
            in_effect: !all_off,
        });
    }
    if let Some((loc, v)) = &cfg.user
        && let Some(table) = v.get("hooks")
    {
        let user_off = v.get("disableAllHooks") == Some(&Value::Bool(true));
        out.push(HookSource {
            source: Source::new(loc.shown.clone(), user_origin(ctx, loc), SourceKind::File),
            table: table.clone(),
            admin: false,
            in_effect: !(all_off || managed_only(cfg) || user_off),
        });
    }
    out
}

/// The signals one event adds to a hook's input.
fn event_signals(event: &str) -> Vec<Signal> {
    match event {
        "UserPromptSubmit" | "UserPromptExpansion" => vec![Signal::Prompts],
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure" | "PostToolBatch"
        | "PermissionRequest" | "PermissionDenied" => vec![Signal::ToolDetails],
        "Stop" | "SubagentStop" => vec![Signal::Responses],
        _ => vec![],
    }
}

fn target_label(t: &Target) -> String {
    let base = |s: &str| redact::text(s.rsplit('/').next().unwrap_or(s));
    match t {
        Target::File(loc) => base(&loc.shown),
        Target::Unresolved(s) if s.is_empty() => "a command".to_string(),
        Target::Unresolved(s) => base(s),
        Target::Inline { interpreter } => format!("an inline {} script", base(interpreter)),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// A hook that isn't a command, with the events it listens to.
struct Other {
    kind: String,
    key: String,
    events: Vec<String>,
    entry: Value,
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let path = cfg
        .env
        .iter()
        .find(|v| v.name == "PATH" && v.in_effect && v.from != CcFrom::Process)
        .map(|v| v.value.clone());
    let mut rtk_telemetry = None;
    for hs in sources(ctx, cfg) {
        hook_source(ctx, cfg, &hs, path.as_deref(), &mut rtk_telemetry);
    }
    managed_mcp(ctx, cfg);
    plugins(ctx, cfg);
}

fn hook_source(
    ctx: &mut ScanCtx,
    cfg: &CcConfig,
    hs: &HookSource,
    path: Option<&str>,
    rtk_telemetry: &mut Option<hooks::RtkTelemetry>,
) {
    let Some(events) = hs.table.as_object() else {
        return;
    };
    let mut hits = Vec::new();
    let mut quiet = Vec::new();
    let mut others: Vec<Other> = Vec::new();
    for (event, entries) in events {
        for entry in entries.as_array().into_iter().flatten() {
            for h in entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let kind = str_of(h, "type").unwrap_or("command");
                if kind == "command" {
                    let Some(command) = str_of(h, "command") else {
                        continue;
                    };
                    // `args` present = exec form: `command` is the executable, no shell.
                    let cmd = match h.get("args").and_then(Value::as_array) {
                        Some(a) => Cmd::Argv(
                            std::iter::once(command)
                                .chain(a.iter().filter_map(Value::as_str))
                                .map(String::from)
                                .collect(),
                        ),
                        None => Cmd::Shell(command.to_string()),
                    };
                    let notifier = hooks::is_local_notifier(&cmd, path, ctx);
                    let hit = Hit {
                        event: event.clone(),
                        target: hooks::target(&cmd, path, ctx),
                        cmd,
                        in_effect: hs.in_effect,
                    };
                    if notifier {
                        quiet.push(hit);
                    } else {
                        hits.push(hit);
                    }
                    continue;
                }
                let key = match kind {
                    "http" => str_of(h, "url").unwrap_or_default().to_string(),
                    "mcp_tool" => format!(
                        "{}/{}",
                        str_of(h, "server").unwrap_or_default(),
                        str_of(h, "tool").unwrap_or_default()
                    ),
                    _ => String::new(),
                };
                match others.iter_mut().find(|o| o.kind == kind && o.key == key) {
                    Some(o) => {
                        if !o.events.contains(event) {
                            o.events.push(event.clone());
                        }
                    }
                    None => others.push(Other {
                        kind: kind.to_string(),
                        key,
                        events: vec![event.clone()],
                        entry: h.clone(),
                    }),
                }
            }
        }
    }
    commands(ctx, hs, hits, path, false, rtk_telemetry);
    commands(ctx, hs, quiet, path, true, rtk_telemetry);
    for o in others {
        other(ctx, cfg, hs, &o);
    }
}

fn commands(
    ctx: &mut ScanCtx,
    hs: &HookSource,
    list: Vec<Hit>,
    path: Option<&str>,
    plays_sound: bool,
    rtk_telemetry: &mut Option<hooks::RtkTelemetry>,
) {
    let all = list.clone();
    for g in hooks::group(list, path, ctx) {
        let label = target_label(&g.target);
        let origin = hooks::origin(hs.source.origin, &g.target, ctx);
        let rtk = g.known_local_tool_hook.then(|| {
            hooks::rtk_hook_finding(
                hooks::rtk_telemetry(ctx, rtk_telemetry),
                &g.events,
                matches!(&g.target, Target::Unresolved(_)),
            )
        });
        let mut signals: Vec<Signal> = rtk
            .as_ref()
            .map_or_else(Vec::new, |finding| finding.signals.clone());
        if !plays_sound && rtk.is_none() {
            signals.push(Signal::Transcript);
            for e in &g.events {
                signals.extend(event_signals(e));
            }
        }
        let host = all
            .iter()
            .filter(|h| h.target == g.target)
            .find_map(|h| hooks::sends_to(&h.cmd));
        let mut title = if plays_sound {
            format!("Claude Code hook `{label}` plays a sound or shows a notification")
        } else if let Some(rtk) = &rtk {
            format!("Claude Code hook `rtk` {}", rtk.title_suffix)
        } else {
            format!("Claude Code hook `{label}` runs on {}", g.events.join(", "))
        };
        if !plays_sound
            && rtk.is_none()
            && let Some(host) = host
        {
            title.push_str(&format!(" and sends what it receives to {host}"));
        }
        let mut evidence = vec![format!("events = {}", g.events.join(", "))];
        evidence.extend(g.commands.iter().map(|c| format!("command = {c}")));
        if let Some(rtk) = &rtk {
            evidence.push(rtk.evidence.clone());
        }
        if let Target::Unresolved(name) = &g.target {
            evidence.push(format!("couldn't tell which `{}` runs", redact::text(name)));
        }
        let mut finding = FindingBuilder::new(title)
            .signals(&signals)
            .evidence(evidence)
            .source(Source::new(
                hs.source.path.clone(),
                origin,
                SourceKind::File,
            ))
            .reference(doc("hooks"))
            .best_effort(rtk.as_ref().is_some_and(|finding| finding.best_effort))
            .in_effect(g.in_effect);
        if let Some(rtk) = rtk {
            finding = finding.detail(rtk.detail);
        }
        ctx.emit(finding);
    }
}

fn other(ctx: &mut ScanCtx, cfg: &CcConfig, hs: &HookSource, o: &Other) {
    let mut signals: Vec<Signal> = o.events.iter().flat_map(|e| event_signals(e)).collect();
    let mut evidence = vec![format!("events = {}", o.events.join(", "))];
    let mut best_effort = false;
    let (title, policy) = match o.kind.as_str() {
        "http" => {
            let host = redact::url_host(&o.key).unwrap_or_else(|| "a remote host".to_string());
            evidence.push(format!("url = {}", redact::url(&o.key)));
            for h in redact::header_names(o.entry.get("headers").unwrap_or(&Value::Null)) {
                evidence.push(format!("header {h} = <redacted>"));
            }
            signals.push(Signal::Traffic);
            (
                format!("Claude Code hook posts each event to {host}"),
                false,
            )
        }
        "mcp_tool" => {
            evidence.push(format!("mcp tool = {}", redact::text(&o.key)));
            best_effort = true;
            (
                format!(
                    "Claude Code hook sends each event to MCP tool `{}`",
                    redact::text(&o.key)
                ),
                false,
            )
        }
        kind => {
            signals.clear();
            if hs.admin {
                signals.push(Signal::Policy);
            }
            (
                format!(
                    "Claude Code evaluates a `{kind}` hook with Claude on {}",
                    o.events.join(", ")
                ),
                true,
            )
        }
    };
    let b = FindingBuilder::new(title)
        .signals(&signals)
        .reference(doc("hooks"))
        .in_effect(hs.in_effect);
    let b = if policy {
        b.detail("The hook is evaluated by Claude. Nothing leaves.")
    } else {
        b
    };
    emit_from(ctx, cfg, hs, b, evidence, best_effort);
}

/// Source, evidence and best-effort flag for a finding of one hook source.
fn emit_from(
    ctx: &mut ScanCtx,
    cfg: &CcConfig,
    hs: &HookSource,
    b: FindingBuilder,
    evidence: Vec<String>,
    own_be: bool,
) {
    let tier = cfg
        .tiers
        .iter()
        .find(|t| hs.admin && t.loc.shown == hs.source.path)
        .map(|t| t.id.clone());
    let b = match tier {
        Some(id) => tier_finding(cfg, &id, b, evidence, own_be),
        None => Some(
            b.source(hs.source.clone())
                .evidence(evidence)
                .best_effort(own_be),
        ),
    };
    if let Some(b) = b {
        ctx.emit(b);
    }
}

fn remote(entry: &Value) -> bool {
    ["url", "http_url", "serverUrl"]
        .iter()
        .any(|k| entry.get(k).and_then(Value::as_str).is_some())
}

/// `managed-mcp.json` and `managedMcpServers`.
fn managed_mcp(ctx: &mut ScanCtx, cfg: &CcConfig) {
    if let Some((loc, v)) = &cfg.mcp_lock
        && let Some(servers) = v.get("mcpServers").and_then(Value::as_object)
    {
        let source = Source::new(loc.shown.clone(), Origin::System, SourceKind::File);
        ctx.emit(
            FindingBuilder::new("Your organization fixes which MCP servers Claude Code uses")
                .signals(&[Signal::Policy])
                .evidence(
                    servers
                        .keys()
                        .map(|k| format!("server = {}", redact::text(k)))
                        .collect::<Vec<_>>(),
                )
                .source(source.clone())
                .reference(doc("managed-mcp")),
        );
        for (name, entry) in servers.iter().filter(|(_, e)| remote(e)) {
            let b = mcp::server(name, entry, Origin::System, ctx)
                .source(source.clone())
                .reference(doc("managed-mcp"));
            ctx.emit(b);
        }
    }
    for t in &cfg.tiers {
        if !managed_in_effect(cfg, "managedMcpServers", &t.id) {
            continue;
        }
        let Some(servers) = t.value.get("managedMcpServers").and_then(Value::as_object) else {
            continue;
        };
        let b = FindingBuilder::new(format!(
            "Your organization added {} MCP servers to Claude Code",
            servers.len()
        ))
        .signals(&[Signal::ToolDetails])
        .reference(doc("settings-reference"));
        let evidence = servers
            .keys()
            .map(|k| format!("server = {}", redact::text(k)))
            .collect();
        if let Some(b) = tier_finding(cfg, &t.id, b, evidence, true) {
            ctx.emit(b);
        }
        for (name, entry) in servers.iter().filter(|(_, e)| remote(e)) {
            let b = mcp::server(name, entry, t.origin, ctx)
                .source(tier_source(t))
                .reference(doc("settings-reference"));
            ctx.emit(b);
        }
    }
}

/// `enabledPlugins` from an admin tier.
fn plugins(ctx: &mut ScanCtx, cfg: &CcConfig) {
    for t in &cfg.tiers {
        if !managed_in_effect(cfg, "enabledPlugins", &t.id) {
            continue;
        }
        let names: Vec<String> = t
            .value
            .get("enabledPlugins")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| value::truthy(v))
                    .map(|(k, _)| format!("plugin = {}", redact::text(k)))
                    .collect()
            })
            .unwrap_or_default();
        let b =
            FindingBuilder::new("Plugins your organization enabled may run hooks or MCP servers")
                .signals(&[Signal::ToolDetails])
                .detail("cAInary doesn't read plugin contents, so what they send isn't known.")
                .reference(doc("settings-reference"));
        if let Some(b) = tier_finding(cfg, &t.id, b, names, true) {
            ctx.emit(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::platform::Os;
    use crate::harness::{Harness, Loc};
    use crate::model::{Finding, Level, Tool};
    use crate::scanners::claude_code::{CcSetting, CcTier, CcTierId, is_policy_doc};
    use serde_json::{Map, json};
    use std::path::Path;

    fn fixture(name: &str) -> Harness {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resolve")
            .join(name);
        Harness::from_fixture(&dir).expect("fixture loads")
    }

    fn user_cfg(settings: Value) -> CcConfig {
        CcConfig {
            user: Some((
                Loc::test("/home/alice/.claude/settings.json"),
                settings.as_object().cloned().unwrap_or_default(),
            )),
            ..CcConfig::default()
        }
    }

    fn admin_cfg(settings: Value) -> CcConfig {
        let value: Map<String, Value> = settings.as_object().cloned().unwrap_or_default();
        let managed = value
            .iter()
            .map(|(k, v)| CcSetting {
                key: k.clone(),
                value: v.clone(),
                tier: CcTierId::File,
                in_effect: true,
            })
            .collect();
        CcConfig {
            tiers: vec![CcTier {
                id: CcTierId::File,
                loc: Loc::test("/etc/claude-code/managed-settings.json"),
                origin: Origin::System,
                policy: is_policy_doc(&value),
                value,
            }],
            policy_tier: Some(CcTierId::File),
            managed,
            ..CcConfig::default()
        }
    }

    fn run(h: &Harness, cfg: &CcConfig) -> Vec<Finding> {
        let mut ctx = ScanCtx::new(h, Tool::ClaudeCode);
        scan(&mut ctx, cfg);
        ctx.finish().findings
    }

    fn hook(event: &str, h: Value) -> Value {
        json!({ "hooks": { event: [{ "hooks": [h] }] } })
    }

    #[test]
    fn command_hook_signals_by_event() {
        let h = Harness::test(Os::Macos, &[]);
        let cfg = user_cfg(hook(
            "UserPromptSubmit",
            json!({"type": "command", "command": "/opt/acme/log.sh"}),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Prompts, Signal::Transcript]);
        // a missing type means command
        let cfg = user_cfg(hook("Stop", json!({"command": "/opt/acme/log.sh"})));
        let f = run(&h, &cfg);
        assert_eq!(f[0].signals, [Signal::Responses, Signal::Transcript]);
    }

    #[test]
    fn exec_form_hook_uses_command_as_executable() {
        let h = Harness::test(Os::Macos, &[]);
        let cfg = user_cfg(hook(
            "UserPromptSubmit",
            json!({
                "type": "command",
                "command": "/Library/Application Support/Pitwall/pitwall",
                "args": ["--agent", "claude"]
            }),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].title,
            "Claude Code hook `pitwall` runs on UserPromptSubmit"
        );
    }

    #[test]
    fn known_local_rtk_hook_is_low_when_telemetry_is_not_configured() {
        let h = fixture("rtk-telemetry-missing");
        let cfg = user_cfg(hook(
            "PreToolUse",
            json!({"type": "command", "command": "rtk hook claude"}),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Claude Code hook `rtk` runs on PreToolUse");
        assert_eq!(f[0].signals, [Signal::Usage]);
        assert_eq!(f[0].level(), Level::Low);
        assert!(f[0].detail.contains("local token reducer"));
        assert!(f[0].evidence.iter().any(|line| {
            line == "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        }));
    }

    #[test]
    fn curl_hook_has_network_wording() {
        let h = Harness::test(Os::Macos, &[]);
        let cfg = admin_cfg(hook(
            "PostToolUse",
            json!({"type": "command", "command": "curl -s https://collect.example-corp.com/e -d @-"}),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f.len(), 1);
        assert!(
            f[0].title
                .contains("sends what it receives to collect.example-corp.com")
        );
        assert!(f[0].signals.contains(&Signal::ToolDetails));
    }

    #[test]
    fn http_hook_is_traffic_and_event_signals() {
        let h = Harness::test(Os::Macos, &[]);
        let cfg = admin_cfg(hook(
            "UserPromptSubmit",
            json!({"type": "http", "url": "https://hooks.example-corp.com/e"}),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f[0].signals, [Signal::Prompts, Signal::Traffic]);
        assert!(f[0].title.contains("hooks.example-corp.com"));
    }

    #[test]
    fn mcp_tool_hook_is_best_effort() {
        let h = Harness::test(Os::Macos, &[]);
        let cfg = admin_cfg(hook(
            "Stop",
            json!({"type": "mcp_tool", "server": "acme", "tool": "log"}),
        ));
        let f = run(&h, &cfg);
        assert_eq!(f[0].signals, [Signal::Responses]);
        assert!(f[0].best_effort);
    }

    #[test]
    fn prompt_hook_is_policy_for_admin_info_for_user() {
        let h = Harness::test(Os::Macos, &[]);
        let body = hook("Stop", json!({"type": "prompt", "prompt": "ok?"}));
        let f = run(&h, &admin_cfg(body.clone()));
        assert_eq!(f[0].signals, [Signal::Policy]);
        let f = run(&h, &user_cfg(body));
        assert!(f[0].signals.is_empty());
    }

    #[test]
    fn allow_managed_hooks_only_blocks_user_hooks() {
        let h = Harness::test(Os::Macos, &[]);
        let mut cfg = user_cfg(hook(
            "Stop",
            json!({"type": "command", "command": "/opt/acme/log.sh"}),
        ));
        cfg.managed.push(CcSetting {
            key: "allowManagedHooksOnly".into(),
            value: json!("true"),
            tier: CcTierId::File,
            in_effect: true,
        });
        let f = run(&h, &cfg);
        assert_eq!(f.len(), 1);
        assert!(!f[0].in_effect && f[0].signals.is_empty());
    }

    #[test]
    fn disable_all_hooks_blocks_admin_hooks() {
        let h = Harness::test(Os::Macos, &[]);
        let mut body = hook("Stop", json!({"command": "/opt/acme/log.sh"}));
        body["disableAllHooks"] = json!(true);
        let f = run(&h, &admin_cfg(body));
        assert_eq!(f.len(), 1);
        assert!(!f[0].in_effect);
        // a user's own switch blocks only user hooks
        let mut body = hook("Stop", json!({"command": "/opt/acme/log.sh"}));
        body["disableAllHooks"] = json!(true);
        let f = run(&h, &user_cfg(body));
        assert!(!f[0].in_effect);
    }

    #[test]
    fn managed_mcp_and_plugins() {
        let h = Harness::test(Os::Macos, &[]);
        let mut cfg = admin_cfg(json!({
            "enabledPlugins": {"acme@corp": true},
            "managedMcpServers": {
                "remote": {"url": "https://mcp.example-corp.com/v1"},
                "local": {"command": "/opt/acme/mcp"}
            }
        }));
        cfg.mcp_lock = Some((
            Loc::test("/etc/claude-code/managed-mcp.json"),
            json!({"mcpServers": {"r2": {"url": "https://mcp2.example-corp.com"}, "l": {"command": "x"}}})
                .as_object()
                .cloned()
                .unwrap(),
        ));
        let f = run(&h, &cfg);
        let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("fixes which MCP servers")));
        assert!(titles.iter().any(|t| t.contains("mcp2.example-corp.com")));
        assert!(titles.iter().any(|t| t.contains("mcp.example-corp.com")));
        assert!(titles.iter().any(|t| t.contains("added 2 MCP servers")));
        assert!(
            titles
                .iter()
                .any(|t| t.contains("Plugins your organization enabled"))
        );
        // local servers get no H.7 finding
        assert!(
            !titles
                .iter()
                .any(|t| t.contains("`local`") || t.contains("`l`"))
        );
        assert!(
            f.iter()
                .filter(|f| f.title.contains("Plugins"))
                .all(|f| f.best_effort)
        );
    }
}
