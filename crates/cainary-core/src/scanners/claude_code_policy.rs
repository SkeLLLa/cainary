//! Claude Code policy keys, gateways/proxies, vendor default (rules.md §CC.4, CC.5, CC.7).

use super::claude_code::{
    self, CcConfig, CcEnvVar, CcFrom, CcTier, CcTierId, doc, is_control, tier_finding, tier_source,
};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind, Tool};
use crate::redact;
use crate::rules::hooks::{self, Cmd};
use crate::rules::vendor;
use crate::value::{self, Value};

const MAX_LINES: usize = 20;
const MAX_VALUE_CHARS: usize = 160;

/// `(group key, title)`, in report order.
const GROUPS: [(&str, &str); 7] = [
    (
        "login",
        "Your organization controls how you sign in to Claude Code",
    ),
    (
        "permissions",
        "Your organization sets Claude Code's permissions and sandbox",
    ),
    (
        "mcp",
        "Your organization controls which MCP servers and plugins Claude Code uses",
    ),
    ("hooks", "Your organization controls whether hooks may run"),
    (
        "models",
        "Your organization controls Claude Code's models and updates",
    ),
    (
        "instructions",
        "Your organization adds instructions for Claude Code",
    ),
    ("other", "Your organization sets other Claude Code policies"),
];

fn group_of(key: &str) -> &'static str {
    match key {
        "forceLoginMethod" | "forceLoginOrgUUID" | "allowedProviders" => "login",
        "permissions" | "allowManagedPermissionRulesOnly" | "sandbox" => "permissions",
        "allowedMcpServers"
        | "deniedMcpServers"
        | "allowManagedMcpServersOnly"
        | "managedMcpServers"
        | "enabledPlugins"
        | "strictKnownMarketplaces"
        | "blockedMarketplaces"
        | "extraKnownMarketplaces"
        | "disableClaudeAiConnectors" => "mcp",
        "allowManagedHooksOnly" | "disableAllHooks" | "allowedHttpHookUrls" => "hooks",
        "availableModels" | "model" | "requiredMinimumVersion" | "autoUpdatesChannel" => "models",
        "claudeMd" | "companyAnnouncements" => "instructions",
        _ => "other",
    }
}

fn is_lock(key: &str) -> bool {
    ["allowManaged", "disable", "strict", "force"]
        .iter()
        .any(|p| key.starts_with(p))
}

/// Keys that other findings report, or that have their own rule.
fn reported_elsewhere(key: &str) -> bool {
    matches!(
        key,
        "hooks" | "policyHelper" | "forceLoginGatewayUrl" | "gatewayInternalNetworks"
    )
}

fn is_gateway_key(key: &str, v: &Value) -> bool {
    matches!(key, "forceLoginGatewayUrl" | "gatewayInternalNetworks")
        || (key == "forceLoginMethod" && v.as_str() == Some("gateway"))
}

fn clip(s: String) -> String {
    if s.chars().count() > MAX_VALUE_CHARS {
        let cut: String = s.chars().take(MAX_VALUE_CHARS).collect();
        format!("{cut}…")
    } else {
        s
    }
}

fn char_count(v: &Value) -> usize {
    match v {
        Value::String(s) => s.chars().count(),
        Value::Array(a) => a.iter().map(char_count).sum(),
        _ => 0,
    }
}

fn line(key: &str, v: &Value) -> String {
    match group_of(key) {
        "instructions" => format!("{key} = {} characters", char_count(v)),
        "other" => key.to_string(),
        _ => clip(format!("{key} = {}", redact::value(key, v))),
    }
}

fn base(s: &str) -> String {
    redact::text(s.rsplit('/').next().unwrap_or(s))
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CcConfig) {
    helper(ctx, cfg);
    policy_keys(ctx, cfg);
    limits(ctx, cfg);
    user_restrictions(ctx, cfg);
    gateways(ctx, cfg);
    proxies(ctx, cfg);
    api_key_helper(ctx, cfg);
    vendor_default(ctx, cfg);
}

/// CC.5: one policy finding per tier and group, for the keys in effect from that tier.
fn policy_keys(ctx: &mut ScanCtx, cfg: &CcConfig) {
    for t in &cfg.tiers {
        let mut groups: Vec<Vec<String>> = vec![Vec::new(); GROUPS.len()];
        for s in cfg.managed.iter().filter(|s| s.tier == t.id && s.in_effect) {
            if is_control(&s.key)
                || reported_elsewhere(&s.key)
                || is_gateway_key(&s.key, &s.value)
                || (is_lock(&s.key) && s.value == Value::Bool(false))
            {
                continue;
            }
            let g = group_of(&s.key);
            let i = GROUPS.iter().position(|(k, _)| *k == g).unwrap_or(0);
            groups[i].push(line(&s.key, &s.value));
        }
        for ((_, title), mut lines) in GROUPS.into_iter().zip(groups) {
            if lines.is_empty() {
                continue;
            }
            let more = lines.len().saturating_sub(MAX_LINES);
            lines.truncate(MAX_LINES);
            if more > 0 {
                lines.push(format!("… and {more} more"));
            }
            let b = FindingBuilder::new(title)
                .signals(&[Signal::Policy])
                .detail("These settings come from your organization and can't be changed locally.")
                .reference(doc("settings-reference"));
            if let Some(b) = tier_finding(cfg, &t.id, b, lines, false) {
                ctx.emit(b);
            }
        }
        tls_terminate(ctx, cfg, t);
    }
}

fn tls_terminate(ctx: &mut ScanCtx, cfg: &CcConfig, t: &CcTier) {
    let on = cfg.managed.iter().any(|s| {
        s.tier == t.id
            && s.in_effect
            && s.key == "sandbox"
            && value::get(&s.value, "network.tlsTerminate").is_some_and(value::truthy)
    });
    if !on {
        return;
    }
    let b = FindingBuilder::new(
        "Your organization can inspect Claude Code's sandboxed network traffic",
    )
    .signals(&[Signal::Traffic])
    .detail("The sandbox terminates TLS, so requests it makes can be read in the clear.")
    .reference(doc("settings-reference"));
    if let Some(b) = tier_finding(
        cfg,
        &t.id,
        b,
        vec!["sandbox.network.tlsTerminate = true".to_string()],
        false,
    ) {
        ctx.emit(b);
    }
}

/// CC.5 `policyHelper`: never run, so the scan is incomplete and admin findings are BE.
fn helper(ctx: &mut ScanCtx, cfg: &CcConfig) {
    for t in cfg.tiers.iter().filter(|t| t.id != CcTierId::Server) {
        let Some(v) = t.value.get("policyHelper").filter(|v| !v.is_null()) else {
            continue;
        };
        let selected = cfg.helper.as_ref().filter(|(_, id)| *id == t.id);
        if let Some((loc, _)) = selected {
            ctx.not_run(
                loc,
                t.origin,
                "policyHelper output decides the managed settings",
            );
            let mut evidence = vec![format!("path = {}", redact::text(&loc.shown))];
            for k in ["timeoutMs", "refreshIntervalMs"] {
                if let Some(x) = v.get(k) {
                    evidence.push(format!("{k} = {}", redact::value(k, x)));
                }
            }
            ctx.emit(
                FindingBuilder::new(format!(
                    "Your organization computes Claude Code policy at runtime with {}",
                    base(&loc.shown)
                ))
                .signals(&[Signal::Policy])
                .detail(
                    "cAInary doesn't run it, so the managed settings below may not be what applies.",
                )
                .source(tier_source(t))
                .evidence(evidence)
                .reference(doc("managed-settings"))
                .best_effort(true),
            );
            continue;
        }
        let why = if v
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|p| !(p.starts_with('/') || p.starts_with("~/")))
        {
            "An invalid policy helper setting is ignored"
        } else if cfg.policy_tier == Some(CcTierId::Server) {
            "A policy helper is ignored because server-managed settings take precedence"
        } else {
            continue;
        };
        ctx.emit(
            FindingBuilder::new(why)
                .detail("Claude Code doesn't use this helper, so it has no effect.")
                .source(tier_source(t))
                .reference(doc("managed-settings"))
                .best_effort(claude_code::admin_be(cfg, &t.id, false))
                .in_effect(false),
        );
    }
}

/// CC.5 `policy-limits.json` (internals unverified, so best effort).
fn limits(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let Some((loc, m)) = &cfg.limits else { return };
    let source = Source::new(loc.shown.clone(), Origin::Server, SourceKind::File);
    if let Some(n) = m.get("monitoring_notice").filter(|v| !v.is_null()) {
        ctx.emit(
            FindingBuilder::new("Your organization may monitor Claude Code use")
                .signals(&[Signal::Usage])
                .detail("Your organization's policy limits include a monitoring notice.")
                .source(source.clone())
                .evidence([clip(format!(
                    "monitoring_notice = {}",
                    redact::value("monitoring_notice", n)
                ))])
                .reference(doc("data-usage"))
                .best_effort(true),
        );
    }
    let denied: Vec<String> = m
        .get("restrictions")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, r)| r.get("allowed") == Some(&Value::Bool(false)))
        .map(|(k, _)| format!("restrictions.{} = not allowed", redact::text(k)))
        .collect();
    if !denied.is_empty() {
        ctx.emit(
            FindingBuilder::new("Your organization turns off some Claude Code features")
                .signals(&[Signal::Policy])
                .detail("Your organization's policy limits don't allow these features.")
                .source(source)
                .evidence(denied)
                .reference(doc("settings-reference"))
                .best_effort(true),
        );
    }
}

/// CC.5: the user restricted Claude Code themselves.
fn user_restrictions(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let Some((loc, m)) = &cfg.user else { return };
    let mut lines = Vec::new();
    if let Some(p) = m.get("permissions").filter(|v| !v.is_null()) {
        lines.push(clip(format!(
            "permissions = {}",
            redact::value("permissions", p)
        )));
    }
    if let Some(v) = m.get("sandbox").and_then(|s| value::get(s, "enabled")) {
        lines.push(format!("sandbox.enabled = {}", redact::value("enabled", v)));
    }
    if lines.is_empty() {
        return;
    }
    ctx.emit(
        FindingBuilder::new("You restricted Claude Code yourself")
            .detail("Your own settings limit what Claude Code may do.")
            .source(Source::new(
                loc.shown.clone(),
                claude_code::user_origin(ctx, loc),
                SourceKind::File,
            ))
            .evidence(lines)
            .reference(doc("settings")),
    );
}

fn is_anthropic(url: &str) -> bool {
    redact::url_host(url).is_some_and(|h| h.eq_ignore_ascii_case("api.anthropic.com"))
}

fn var_line(v: &CcEnvVar) -> String {
    clip(format!(
        "{} = {}",
        v.name,
        redact::value(&v.name, &Value::from(v.value.as_str()))
    ))
}

fn truthy_var(cfg: &CcConfig, name: &str) -> bool {
    claude_code::env_value(cfg, name).is_some_and(|v| value::truthy(&Value::from(v)))
}

/// CC.4: base URL, cloud providers, gateway login keys.
fn gateways(ctx: &mut ScanCtx, cfg: &CcConfig) {
    if let Some(v) = claude_code::env(cfg, "ANTHROPIC_BASE_URL")
        && !is_anthropic(&v.value)
    {
        let host = redact::url_host(&v.value).unwrap_or_else(|| "a custom host".to_string());
        let b = FindingBuilder::new(format!("Claude Code's model traffic goes through {host}"))
            .signals(&[Signal::Traffic])
            .detail("The base URL isn't Anthropic's API, so a gateway sees your requests.")
            .reference(doc("env-vars"));
        ctx.emit(claude_code::from_finding(
            ctx,
            cfg,
            &v.from,
            &v.name,
            b,
            vec![var_line(v)],
            false,
        ));
    }
    for (switch, provider, base_url) in [
        (
            "CLAUDE_CODE_USE_BEDROCK",
            "Amazon Bedrock",
            "ANTHROPIC_BEDROCK_BASE_URL",
        ),
        (
            "CLAUDE_CODE_USE_VERTEX",
            "Google Vertex AI",
            "ANTHROPIC_VERTEX_BASE_URL",
        ),
        (
            "CLAUDE_CODE_USE_FOUNDRY",
            "Microsoft Foundry",
            "ANTHROPIC_FOUNDRY_BASE_URL",
        ),
    ] {
        if !truthy_var(cfg, switch) {
            continue;
        }
        let Some(v) = claude_code::env(cfg, switch) else {
            continue;
        };
        let mut evidence = vec![var_line(v)];
        evidence.extend(claude_code::env(cfg, base_url).map(var_line));
        let b = FindingBuilder::new(format!("Claude Code runs through {provider}"))
            .signals(&[Signal::Traffic])
            .detail("Model requests go to your cloud provider instead of Anthropic.")
            .reference(doc("env-vars"));
        ctx.emit(claude_code::from_finding(
            ctx, cfg, &v.from, &v.name, b, evidence, false,
        ));
    }
    for t in &cfg.tiers {
        let keys: Vec<_> = cfg
            .managed
            .iter()
            .filter(|s| s.tier == t.id && s.in_effect && is_gateway_key(&s.key, &s.value))
            .collect();
        if keys.is_empty() {
            continue;
        }
        let evidence = keys
            .iter()
            .map(|s| clip(format!("{} = {}", s.key, redact::value(&s.key, &s.value))))
            .collect();
        let b =
            FindingBuilder::new("Your organization signs you in to Claude Code through a gateway")
                .signals(&[Signal::Traffic, Signal::Policy])
                .detail("Sign-in and requests are routed through your organization's gateway.")
                .reference(doc("settings-reference"));
        if let Some(b) = tier_finding(cfg, &t.id, b, evidence, false) {
            ctx.emit(b);
        }
    }
}

/// CC.4: HTTP(S) proxies and extra CA certificates.
fn proxies(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|n| claude_code::env(cfg, n));
    let ca = claude_code::env(cfg, "NODE_EXTRA_CA_CERTS");
    match (proxy, ca) {
        (Some(p), Some(c)) => {
            let b = FindingBuilder::new("Claude Code uses a proxy that can decrypt traffic")
                .signals(&[Signal::Traffic])
                .detail("An extra certificate authority lets the proxy read encrypted requests.")
                .reference(doc("network-config"));
            let evidence = vec![var_line(p), var_line(c)];
            ctx.emit(claude_code::from_finding(
                ctx, cfg, &p.from, &p.name, b, evidence, false,
            ));
        }
        (Some(p), None) => {
            let b = FindingBuilder::new("Claude Code uses a proxy")
                .detail("The proxy sees which hosts Claude Code connects to, not what it sends.")
                .reference(doc("network-config"));
            ctx.emit(claude_code::from_finding(
                ctx,
                cfg,
                &p.from,
                &p.name,
                b,
                vec![var_line(p)],
                false,
            ));
        }
        (None, Some(c)) => {
            let b = FindingBuilder::new("Claude Code trusts an extra certificate authority")
                .signals(&[Signal::Traffic])
                .detail(
                    "A proxy that uses it could read encrypted requests. The file isn't opened.",
                )
                .reference(doc("network-config"));
            ctx.emit(claude_code::from_finding(
                ctx,
                cfg,
                &c.from,
                &c.name,
                b,
                vec![var_line(c)],
                true,
            ));
        }
        (None, None) => {}
    }
}

/// CC.4: `apiKeyHelper`, an admin one is policy and a user one is info. Never run.
fn api_key_helper(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let path = claude_code::env(cfg, "PATH")
        .filter(|v| v.from != CcFrom::Process)
        .map(|v| v.value.as_str());
    let describe = |ctx: &ScanCtx, cmd: &str| {
        let target = hooks::target(&Cmd::Shell(cmd.to_string()), path, ctx);
        let shown = match target {
            hooks::Target::File(loc) => loc.shown,
            hooks::Target::Unresolved(s) => s,
            hooks::Target::Inline { interpreter } => format!("{interpreter} (inline)"),
        };
        vec![
            format!("apiKeyHelper = {}", redact::command(cmd)),
            format!("runs {}", redact::text(&shown)),
        ]
    };
    for t in &cfg.tiers {
        let Some(s) = cfg
            .managed
            .iter()
            .find(|s| s.tier == t.id && s.in_effect && s.key == "apiKeyHelper")
        else {
            continue;
        };
        let Some(cmd) = s.value.as_str() else {
            continue;
        };
        let b = FindingBuilder::new("Claude Code gets its API key from a helper command")
            .signals(&[Signal::Policy])
            .detail("Your organization sets the command. cAInary never runs it.")
            .reference(doc("settings-reference"));
        let evidence = describe(ctx, cmd);
        if let Some(b) = tier_finding(cfg, &t.id, b, evidence, false) {
            ctx.emit(b);
        }
    }
    if let Some((loc, m)) = &cfg.user
        && let Some(cmd) = m.get("apiKeyHelper").and_then(Value::as_str)
    {
        let evidence = describe(ctx, cmd);
        let origin = claude_code::user_origin(ctx, loc);
        ctx.emit(
            FindingBuilder::new("Claude Code gets its API key from a helper command")
                .detail("A command from your own settings supplies the key. cAInary never runs it.")
                .source(Source::new(loc.shown.clone(), origin, SourceKind::File))
                .evidence(evidence)
                .reference(doc("settings-reference")),
        );
    }
}

/// CC.7: Anthropic's usage metrics are on by default unless something opts out.
fn vendor_default(ctx: &mut ScanCtx, cfg: &CcConfig) {
    if !claude_code::is_installed(ctx, cfg) {
        return;
    }
    let set = |n: &str| claude_code::env(cfg, n).is_some();
    let opted_out = set("DISABLE_TELEMETRY")
        || truthy_var(cfg, "DO_NOT_TRACK")
        || set("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
        || ["BEDROCK", "VERTEX", "FOUNDRY"]
            .iter()
            .any(|p| truthy_var(cfg, &format!("CLAUDE_CODE_USE_{p}")));
    if let Some(b) = vendor::vendor_default(Tool::ClaudeCode, opted_out) {
        ctx.emit(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::platform::Os;
    use crate::harness::{Loc, ScanCtx};
    use crate::model::Finding;
    use crate::scanners::claude_code::{Behavior, CcSetting};
    use serde_json::{Map, json};

    fn tier(id: CcTierId, v: Value) -> CcTier {
        let (loc, origin) = match id {
            CcTierId::Server => ("~/.claude/remote-settings.json", Origin::Server),
            CcTierId::Mdm => (
                "/Library/Managed Preferences/com.anthropic.claudecode.plist",
                Origin::Mdm,
            ),
            CcTierId::File => (
                "/Library/Application Support/ClaudeCode/managed-settings.json",
                Origin::System,
            ),
        };
        let value: Map<String, Value> = v.as_object().cloned().unwrap_or_default();
        CcTier {
            id,
            loc: Loc::test(loc),
            origin,
            policy: claude_code::is_policy_doc(&value),
            value,
        }
    }

    /// A config whose every key of every tier is in effect.
    fn cfg(tiers: Vec<CcTier>) -> CcConfig {
        let managed = tiers
            .iter()
            .flat_map(|t| {
                t.value.iter().map(|(k, v)| CcSetting {
                    key: k.clone(),
                    value: v.clone(),
                    tier: t.id.clone(),
                    in_effect: true,
                })
            })
            .collect();
        CcConfig {
            policy_tier: claude_code::policy_tier(&tiers),
            behavior: Behavior::FirstWins,
            tiers,
            managed,
            ..CcConfig::default()
        }
    }

    fn with_env(mut c: CcConfig, pairs: &[(&str, &str, CcFrom)]) -> CcConfig {
        for (n, v, from) in pairs {
            c.env.push(CcEnvVar {
                name: n.to_string(),
                value: v.to_string(),
                from: from.clone(),
                in_effect: true,
                why: None,
            });
        }
        c
    }

    fn run(
        cfg: &CcConfig,
        f: fn(&mut ScanCtx, &CcConfig),
    ) -> (Vec<Finding>, Vec<crate::model::ScannedSource>) {
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        f(&mut ctx, cfg);
        let out = ctx.finish();
        (out.findings, out.sources)
    }

    #[test]
    fn policy_keys_group_per_tier() {
        let c = cfg(vec![tier(
            CcTierId::File,
            json!({
                "forceLoginOrgUUID": "uuid-1",
                "permissions": {"deny": ["Read(./.env)"]},
                "allowManagedHooksOnly": true,
                "disableAllHooks": false,
                "model": "opus",
                "claudeMd": "Be careful.",
                "customThing": {"secret": "sk-test-EXAMPLE"},
                "$schema": "x"
            }),
        )]);
        let (f, _) = run(&c, policy_keys);
        let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(f.len(), 6, "{titles:?}");
        assert!(
            f.iter()
                .all(|f| f.signals == [Signal::Policy] && f.source.origin == Origin::System)
        );
        let by = |s: &str| f.iter().find(|f| f.title.contains(s)).unwrap();
        assert_eq!(by("sign in").evidence, ["forceLoginOrgUUID = uuid-1"]);
        assert_eq!(
            by("hooks may run").evidence,
            ["allowManagedHooksOnly = true"]
        );
        assert_eq!(by("instructions").evidence, ["claudeMd = 11 characters"]);
        assert_eq!(by("other Claude Code").evidence, ["customThing"]);
        assert!(
            !f.iter()
                .any(|f| f.evidence.iter().any(|e| e.contains("sk-test")))
        );
    }

    #[test]
    fn tls_terminate_is_traffic() {
        let c = cfg(vec![tier(
            CcTierId::File,
            json!({"sandbox": {"network": {"tlsTerminate": true}}}),
        )]);
        let (f, _) = run(&c, policy_keys);
        assert!(f.iter().any(|f| f.signals == [Signal::Traffic]));
    }

    #[test]
    fn selected_helper_is_refused_and_admin_findings_are_be() {
        let mut c = cfg(vec![tier(
            CcTierId::Mdm,
            json!({"policyHelper": {"path": "/usr/local/acme/policy-helper", "timeoutMs": 3000}, "model": "opus"}),
        )]);
        c.helper = Some((Loc::test("/usr/local/acme/policy-helper"), CcTierId::Mdm));
        let (f, sources) = run(&c, scan);
        let s = sources
            .iter()
            .find(|s| s.source.path == "/usr/local/acme/policy-helper")
            .expect("helper source");
        assert_eq!(s.source.kind, SourceKind::Command);
        assert_eq!(s.state, crate::model::SourceState::Refused);
        let h = f.iter().find(|f| f.title.contains("at runtime")).unwrap();
        assert!(h.best_effort && h.signals == [Signal::Policy]);
        assert!(h.title.ends_with("policy-helper"));
        let m = f.iter().find(|f| f.title.contains("models")).unwrap();
        assert!(m.best_effort);
        assert!(
            m.evidence
                .iter()
                .any(|e| e.contains("may be replaced by policyHelper"))
        );
    }

    #[test]
    fn unused_helpers_are_info() {
        let c = cfg(vec![
            tier(CcTierId::Server, json!({"model": "opus"})),
            tier(
                CcTierId::File,
                json!({"policyHelper": {"path": "/opt/acme/h"}}),
            ),
        ]);
        let (f, sources) = run(&c, helper);
        assert_eq!(f.len(), 1);
        assert!(!f[0].in_effect && f[0].signals.is_empty());
        assert!(sources.is_empty());
        let c = cfg(vec![tier(
            CcTierId::File,
            json!({"policyHelper": "/opt/acme/h"}),
        )]);
        let (f, _) = run(&c, helper);
        assert!(f[0].title.contains("invalid"));
    }

    #[test]
    fn policy_limits() {
        let mut c = CcConfig::default();
        let Value::Object(m) = json!({
            "monitoring_notice": "Acme may monitor usage",
            "restrictions": {"web_search": {"allowed": false}, "voice": {"allowed": true}}
        }) else {
            unreachable!()
        };
        c.limits = Some((Loc::test("~/.claude/policy-limits.json"), m));
        let (f, _) = run(&c, limits);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.best_effort));
        let u = f.iter().find(|f| f.signals == [Signal::Usage]).unwrap();
        assert!(u.title.contains("may monitor"));
        let p = f.iter().find(|f| f.signals == [Signal::Policy]).unwrap();
        assert_eq!(p.evidence, ["restrictions.web_search = not allowed"]);
    }

    #[test]
    fn user_restriction_is_info() {
        let mut c = CcConfig::default();
        let Value::Object(m) = json!({"permissions": {"deny": ["Bash(rm:*)"]}}) else {
            unreachable!()
        };
        c.user = Some((Loc::test("~/.claude/settings.json"), m));
        let (f, _) = run(&c, user_restrictions);
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && f[0].source.origin == Origin::User);
    }

    #[test]
    fn base_url_and_provider() {
        let c = with_env(
            cfg(vec![tier(CcTierId::File, json!({"model": "x"}))]),
            &[
                (
                    "ANTHROPIC_BASE_URL",
                    "https://alice:sk-test-EXAMPLE@llm.example-corp.com/v1?k=1",
                    CcFrom::Tier(CcTierId::File),
                ),
                ("CLAUDE_CODE_USE_BEDROCK", "1", CcFrom::Process),
                (
                    "ANTHROPIC_BEDROCK_BASE_URL",
                    "https://bedrock.example-corp.com",
                    CcFrom::Process,
                ),
            ],
        );
        let (f, _) = run(&c, gateways);
        assert_eq!(f.len(), 2);
        let g = f
            .iter()
            .find(|f| f.title.contains("llm.example-corp.com"))
            .unwrap();
        assert_eq!(g.signals, [Signal::Traffic]);
        assert_eq!(g.source.origin, Origin::System);
        assert!(!g.evidence.concat().contains("sk-test"));
        let p = f
            .iter()
            .find(|f| f.title.contains("Amazon Bedrock"))
            .unwrap();
        assert_eq!(p.source.path, "env:CLAUDE_CODE_USE_BEDROCK");
        assert_eq!(p.evidence.len(), 2);
        let none = with_env(
            CcConfig::default(),
            &[(
                "ANTHROPIC_BASE_URL",
                "https://api.anthropic.com",
                CcFrom::Process,
            )],
        );
        assert!(run(&none, gateways).0.is_empty());
    }

    #[test]
    fn gateway_login_keys_are_traffic_and_policy() {
        let c = cfg(vec![tier(
            CcTierId::File,
            json!({"forceLoginGatewayUrl": "https://gw.example-corp.com"}),
        )]);
        let (f, _) = run(&c, gateways);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Traffic, Signal::Policy]);
        // and the key is not repeated as a policy-group finding
        assert!(run(&c, policy_keys).0.is_empty());
    }

    #[test]
    fn proxy_cases() {
        let proxy = (
            "HTTPS_PROXY",
            "http://proxy.example-corp.com:8080",
            CcFrom::Process,
        );
        let ca = (
            "NODE_EXTRA_CA_CERTS",
            "/etc/ssl/acme-ca.pem",
            CcFrom::Process,
        );
        let (f, _) = run(
            &with_env(CcConfig::default(), &[proxy.clone(), ca.clone()]),
            proxies,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Traffic]);
        assert!(f[0].title.contains("decrypt"));
        let (f, _) = run(&with_env(CcConfig::default(), &[proxy]), proxies);
        assert!(f[0].signals.is_empty());
        let (f, _) = run(&with_env(CcConfig::default(), &[ca]), proxies);
        assert_eq!(f[0].signals, [Signal::Traffic]);
        assert!(f[0].best_effort);
    }

    #[test]
    fn api_key_helper_admin_is_policy_user_is_info() {
        let mut c = cfg(vec![tier(
            CcTierId::File,
            json!({"apiKeyHelper": "/opt/acme/get-key --token sk-test-EXAMPLE"}),
        )]);
        let Value::Object(m) = json!({"apiKeyHelper": "get-key"}) else {
            unreachable!()
        };
        c.user = Some((Loc::test("~/.claude/settings.json"), m));
        let (f, _) = run(&c, api_key_helper);
        assert_eq!(f.len(), 2);
        let admin = f
            .iter()
            .find(|f| f.source.origin == Origin::System)
            .unwrap();
        assert_eq!(admin.signals, [Signal::Policy]);
        assert!(admin.evidence.iter().any(|e| e == "runs /opt/acme/get-key"));
        assert!(!admin.evidence.concat().contains("sk-test"));
        let user = f.iter().find(|f| f.source.origin == Origin::User).unwrap();
        assert!(user.signals.is_empty());
    }

    #[test]
    fn vendor_default_and_opt_out() {
        let c = CcConfig {
            user: Some((Loc::test("~/.claude/settings.json"), Map::new())),
            ..CcConfig::default()
        };
        let (f, _) = run(&c, vendor_default);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Vendor]);
        assert_eq!(f[0].source.origin, Origin::VendorDefault);
        let c = with_env(c, &[("DISABLE_TELEMETRY", "1", CcFrom::Process)]);
        let (f, _) = run(&c, vendor_default);
        assert!(f[0].signals.is_empty() && !f[0].in_effect);
        // not installed: nothing
        assert!(run(&CcConfig::default(), vendor_default).0.is_empty());
    }
}
