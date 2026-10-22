//! claude_code scanner: sources, tier/control selection, merge → `CcConfig` (rules.md §CC).

use super::{claude_code_hooks, claude_code_policy, claude_code_telemetry};
use crate::harness::platform::{EnvKind, Os};
use crate::harness::{Loc, Probe, ScanCtx, ToolHome, Which};
use crate::model::{FindingBuilder, Origin, Source, SourceKind};
use crate::redact;
use crate::value::{self, Format, Value};
use serde_json::Map;
use std::collections::BTreeSet;

// Plain data, no methods: concern tests build it by hand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CcTierId {
    #[default]
    Server,
    Mdm,
    File,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Behavior {
    #[default]
    FirstWins,
    Merge,
}

#[derive(Debug, Clone)]
pub struct CcTier {
    pub id: CcTierId,
    pub loc: Loc,
    pub origin: Origin,
    pub value: Map<String, Value>,
    pub policy: bool,
}

/// Step 5.
#[derive(Debug, Clone)]
pub struct CcSetting {
    pub key: String,
    pub value: Value,
    pub tier: CcTierId,
    pub in_effect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcFrom {
    Tier(CcTierId),
    User,
    Process,
}

#[derive(Debug, Clone)]
pub struct CcEnvVar {
    pub name: String,
    pub value: String,
    pub from: CcFrom,
    pub in_effect: bool,
    pub why: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CcConfig {
    /// Present admin tiers, highest first (file = merged drop-ins).
    pub tiers: Vec<CcTier>,
    pub policy_tier: Option<CcTierId>,
    pub behavior: Behavior,
    /// A selected `policyHelper` (CC.5).
    pub helper: Option<(Loc, CcTierId)>,
    pub server_be: bool,
    /// Every top-level key of every admin tier.
    pub managed: Vec<CcSetting>,
    /// `<cfg>/settings.json`.
    pub user: Option<(Loc, Map<String, Value>)>,
    /// `managed-mcp.json`.
    pub mcp_lock: Option<(Loc, Map<String, Value>)>,
    /// `policy-limits.json`.
    pub limits: Option<(Loc, Map<String, Value>)>,
    /// Steps 6–7: every candidate, in effect or dropped, sorted by name.
    pub env: Vec<CcEnvVar>,
}

const DOMAIN: &str = "com.anthropic.claudecode";
const CONTROL: [&str; 3] = [
    "managedSourcesBehavior",
    "wslInheritsWindowsSettings",
    "$schema",
];
const CROSS: [&str; 13] = [
    "env",
    "allowAllClaudeAiMcps",
    "allowManagedMcpServersOnly",
    "deniedMcpServers",
    "disableClaudeAiConnectors",
    "useAutoModeDuringPlan",
    "syncClaudeAiSkills",
    "syncClaudeAiPlugins",
    "enableArtifact",
    "maxEffortLevel",
    "attribution",
    "includeCoAuthoredBy",
    "forceRemoteSettingsRefresh",
];
const SANDBOX_CROSS: [&str; 7] = [
    "network.allowManagedDomainsOnly",
    "filesystem.allowManagedReadPathsOnly",
    "bwrapPath",
    "socatPath",
    "ripgrep",
    "filesystem.disabled",
    "network.strictAllowlist",
];
const TOP_ONLY: [&str; 11] = [
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "proxyAuthHelper",
    "forceLoginOrgUUID",
    "forceLoginMethod",
    "parentSettingsBehavior",
    "modelPicker",
    "policyHelper",
];
/// Under `Merge` these come from every policy tier.
const MERGE_ALL: [&str; 8] = [
    "hooks",
    "permissions",
    "managedMcpServers",
    "enabledPlugins",
    "extraKnownMarketplaces",
    "strictKnownMarketplaces",
    "blockedMarketplaces",
    "allowedHttpHookUrls",
];
const SIGNALS: [&str; 3] = ["LOGS", "METRICS", "TRACES"];
const KINDS: [&str; 5] = [
    "ENDPOINT",
    "PROTOCOL",
    "HEADERS",
    "CLIENT_KEY",
    "CLIENT_CERTIFICATE",
];
/// Process variables the rules read, besides the `OTEL_EXPORTER_OTLP_*` family.
const PROCESS_VARS: [&str; 30] = [
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    "ENABLE_ENHANCED_TELEMETRY_BETA",
    "ENABLE_BETA_TRACING_DETAILED",
    "BETA_TRACING_ENDPOINT",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_METRICS_INCLUDE_ACCOUNT_UUID",
    "OTEL_LOG_USER_PROMPTS",
    "OTEL_LOG_ASSISTANT_RESPONSES",
    "OTEL_LOG_TOOL_DETAILS",
    "OTEL_LOG_TOOL_CONTENT",
    "OTEL_LOG_RAW_API_BODIES",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NODE_EXTRA_CA_CERTS",
    "DISABLE_TELEMETRY",
    "DO_NOT_TRACK",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
];

/// `https://code.claude.com/docs/en/<page>`.
pub fn doc(page: &str) -> String {
    format!("https://code.claude.com/docs/en/{page}")
}

pub fn tier_name(id: &CcTierId) -> &'static str {
    match id {
        CcTierId::Server => "server-managed settings",
        CcTierId::Mdm => "MDM",
        CcTierId::File => "the managed settings file",
    }
}

pub fn is_control(key: &str) -> bool {
    CONTROL.contains(&key)
}

pub fn tier<'a>(cfg: &'a CcConfig, id: &CcTierId) -> Option<&'a CcTier> {
    cfg.tiers.iter().find(|t| &t.id == id)
}

pub fn tier_source(t: &CcTier) -> Source {
    Source::new(t.loc.shown.clone(), t.origin, SourceKind::File)
}

/// Is `key` of `tier` in effect (step 5)? Missing keys are not.
pub fn managed_in_effect(cfg: &CcConfig, key: &str, tier: &CcTierId) -> bool {
    cfg.managed
        .iter()
        .any(|s| s.key == key && &s.tier == tier && s.in_effect)
}

/// The effective value of an environment variable, if one is in effect.
pub fn env<'a>(cfg: &'a CcConfig, name: &str) -> Option<&'a CcEnvVar> {
    cfg.env.iter().find(|v| v.name == name && v.in_effect)
}

pub fn env_value<'a>(cfg: &'a CcConfig, name: &str) -> Option<&'a str> {
    env(cfg, name).map(|v| v.value.as_str())
}

/// Do findings from this admin tier need the best-effort flag (CC.2 step 8, CC.5)? `own` is the
/// finding's own best-effort reason.
pub fn admin_be(cfg: &CcConfig, tier: &CcTierId, own: bool) -> bool {
    own || cfg.helper.is_some() || (*tier == CcTierId::Server && cfg.server_be)
}

/// Add the source, evidence and best-effort flag of a finding that comes from an admin tier.
pub fn tier_finding(
    cfg: &CcConfig,
    id: &CcTierId,
    b: FindingBuilder,
    mut evidence: Vec<String>,
    own_be: bool,
) -> Option<FindingBuilder> {
    let t = tier(cfg, id)?;
    if cfg.helper.is_some() {
        evidence.push("may be replaced by policyHelper".to_string());
    }
    Some(
        b.source(tier_source(t))
            .evidence(evidence)
            .best_effort(admin_be(cfg, id, own_be)),
    )
}

/// A user-tier file owned by uid 0 is org-installed.
pub fn user_origin(ctx: &ScanCtx, loc: &Loc) -> Origin {
    if ctx.root_owned(loc) {
        Origin::OrgInstalled
    } else {
        Origin::User
    }
}

fn merge_value(a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            let mut out = x.clone();
            for v in y {
                if !out.contains(v) {
                    out.push(v.clone());
                }
            }
            Value::Array(out)
        }
        (Value::Object(x), Value::Object(y)) => {
            let mut out = x.clone();
            for (k, v) in y {
                let m = out
                    .get(k)
                    .map_or_else(|| v.clone(), |old| merge_value(old, v));
                out.insert(k.clone(), m);
            }
            Value::Object(out)
        }
        _ => b.clone(),
    }
}

/// Step 1: fold a later drop-in `b` into `a`.
pub fn merge_dropin(a: &Map<String, Value>, b: &Map<String, Value>) -> Map<String, Value> {
    let mut out = a.clone();
    for (k, v) in b {
        let m = match (k.as_str(), out.get(k), v) {
            ("fallbackModel" | "modelPicker", _, _) => v.clone(),
            (
                "extraKnownMarketplaces" | "managedMcpServers",
                Some(Value::Object(x)),
                Value::Object(y),
            ) => {
                let mut m = x.clone();
                m.extend(y.clone());
                Value::Object(m)
            }
            (_, Some(old), _) => merge_value(old, v),
            (_, None, _) => v.clone(),
        };
        out.insert(k.clone(), m);
    }
    out
}

/// Step 2: a key other than the control keys, with a non-null value.
pub fn is_policy_doc(v: &Map<String, Value>) -> bool {
    v.iter().any(|(k, x)| !is_control(k) && !x.is_null())
}

/// Step 3: the highest of server, mdm, file with a policy document.
pub fn policy_tier(tiers: &[CcTier]) -> Option<CcTierId> {
    tiers.iter().find(|t| t.policy).map(|t| t.id.clone())
}

/// Step 4. The second value is `(tier, text)` for a value that isn't understood.
pub fn behavior(tiers: &[CcTier]) -> (Behavior, Option<(CcTierId, String)>) {
    let holder = tiers.iter().find(|t| {
        t.policy
            || t.value
                .get("managedSourcesBehavior")
                .is_some_and(|v| !v.is_null())
    });
    let Some(t) = holder else {
        return (Behavior::FirstWins, None);
    };
    match t.value.get("managedSourcesBehavior") {
        None | Some(Value::Null) => (Behavior::FirstWins, None),
        Some(Value::String(s)) if s == "merge" => (Behavior::Merge, None),
        Some(Value::String(s)) if s == "first-wins" => (Behavior::FirstWins, None),
        Some(other) => (
            Behavior::FirstWins,
            Some((t.id.clone(), redact::value("managedSourcesBehavior", other))),
        ),
    }
}

fn sets(t: &CcTier, key: &str) -> bool {
    t.value.get(key).is_some_and(|v| !v.is_null())
}

fn is_lock(key: &str) -> bool {
    ["allowManaged", "disable", "strict", "force"]
        .iter()
        .any(|p| key.starts_with(p))
}

fn has_sandbox_cross(v: &Value) -> bool {
    SANDBOX_CROSS
        .iter()
        .any(|p| value::get(v, p).is_some_and(|x| !x.is_null()))
}

/// Step 5: is a top-level key of an admin tier in effect?
pub fn in_effect(
    tiers: &[CcTier],
    policy: Option<&CcTierId>,
    behavior: &Behavior,
    key: &str,
    t: &CcTier,
) -> bool {
    if is_control(key) {
        return true;
    }
    let v = &t.value[key];
    if CROSS.contains(&key) || (key == "sandbox" && has_sandbox_cross(v)) {
        return true;
    }
    let gateway = ["forceLoginGatewayUrl", "gatewayInternalNetworks"].contains(&key)
        || (key == "forceLoginMethod" && v.as_str() == Some("gateway"));
    if gateway {
        let top = tiers.iter().find(|x| x.id != CcTierId::Server && x.policy);
        return t.id != CcTierId::Server && top.map(|x| &x.id) == Some(&t.id);
    }
    let highest = |k: &str| tiers.iter().find(|x| sets(x, k)).map(|x| &x.id);
    if key == "allowedMcpServers"
        && tiers.iter().any(|x| {
            x.value
                .get("allowManagedMcpServersOnly")
                .is_some_and(value::truthy)
        })
    {
        return highest(key) == Some(&t.id);
    }
    match behavior {
        Behavior::FirstWins => policy == Some(&t.id),
        Behavior::Merge if TOP_ONLY.contains(&key) => policy == Some(&t.id),
        Behavior::Merge if MERGE_ALL.contains(&key) || is_lock(key) => t.policy,
        Behavior::Merge => highest(key) == Some(&t.id),
    }
}

/// Members of the telemetry unit (step 6).
pub fn is_unit(name: &str) -> bool {
    name.starts_with("OTEL_EXPORTER_OTLP_")
        || name.starts_with("OTEL_LOG_")
        || [
            "OTEL_LOGS_EXPORTER",
            "ENABLE_BETA_TRACING_DETAILED",
            "BETA_TRACING_ENDPOINT",
        ]
        .contains(&name)
}

fn env_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn env_pairs(m: &Map<String, Value>) -> Vec<(String, String)> {
    let Some(Value::Object(env)) = m.get("env") else {
        return Vec::new();
    };
    env.iter()
        .map(|(k, v)| (k.clone(), env_text(v)))
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

fn var(name: &str, value: &str, from: CcFrom) -> CcEnvVar {
    CcEnvVar {
        name: name.to_string(),
        value: value.to_string(),
        from,
        in_effect: true,
        why: None,
    }
}

/// Step 6: managed `env`, with the telemetry unit taken from one tier.
pub fn managed_env(tiers: &[CcTier]) -> Vec<CcEnvVar> {
    let unit_tier = tiers.iter().find(|t| {
        env_pairs(&t.value).iter().any(|(k, _)| is_unit(k)) || sets(t, "otelHeadersHelper")
    });
    let mut out: Vec<CcEnvVar> = Vec::new();
    let mut seen = BTreeSet::new();
    for t in tiers {
        for (name, val) in env_pairs(&t.value) {
            let from = CcFrom::Tier(t.id.clone());
            if is_unit(&name) {
                let mut v = var(&name, &val, from);
                if unit_tier.map(|u| &u.id) != Some(&t.id) {
                    v.in_effect = false;
                    let by = unit_tier.map_or("another tier", |u| tier_name(&u.id));
                    v.why = Some(format!("replaced by {by}'s telemetry settings"));
                }
                out.push(v);
            } else if seen.insert(name.clone()) {
                out.push(var(&name, &val, from));
            }
        }
    }
    out
}

/// The managed variable that makes a local unit member irrelevant, if any (step 7).
fn dropped_by(name: &str, managed: &dyn Fn(&str) -> bool) -> Option<String> {
    let general = |k: &str| format!("OTEL_EXPORTER_OTLP_{k}");
    let per = |s: &str, k: &str| format!("OTEL_EXPORTER_OTLP_{s}_{k}");
    let by = |n: String| Some(format!("an administrator's {n} replaces it"));
    for s in SIGNALS {
        for k in ["ENDPOINT", "PROTOCOL"] {
            if name == per(s, k) && managed(&general(k)) {
                return by(general(k));
            }
        }
        for k in ["HEADERS", "CLIENT_KEY", "CLIENT_CERTIFICATE"] {
            if name == per(s, k) && managed(&general(k)) {
                return by(general(k));
            }
        }
    }
    let is_endpoint =
        name == general("ENDPOINT") || SIGNALS.iter().any(|s| name == per(s, "ENDPOINT"));
    if is_endpoint {
        for k in ["HEADERS", "CLIENT_KEY", "CLIENT_CERTIFICATE"] {
            if managed(&general(k)) {
                return by(general(k));
            }
        }
    }
    if name == "BETA_TRACING_ENDPOINT" {
        for n in [
            general("ENDPOINT"),
            per("LOGS", "ENDPOINT"),
            per("TRACES", "ENDPOINT"),
        ] {
            if managed(&n) {
                return by(n);
            }
        }
    }
    None
}

/// Step 7: managed > user `settings.json` `env` > process env, then drop the local unit members
/// an admin endpoint replaces.
pub fn effective_env(
    managed: Vec<CcEnvVar>,
    user_env: Vec<(String, String)>,
    process_env: Vec<(String, String)>,
) -> Vec<CcEnvVar> {
    let mut out = managed;
    let locals = user_env
        .into_iter()
        .map(|(k, v)| (k, v, CcFrom::User))
        .chain(
            process_env
                .into_iter()
                .map(|(k, v)| (k, v, CcFrom::Process)),
        );
    for (k, v, from) in locals {
        if !out.iter().any(|x| x.name == k && x.in_effect) {
            out.push(var(&k, &v, from));
        }
    }
    let managed_has: BTreeSet<String> = out
        .iter()
        .filter(|v| v.in_effect && matches!(v.from, CcFrom::Tier(_)))
        .map(|v| v.name.clone())
        .collect();
    for v in &mut out {
        if v.in_effect
            && !matches!(v.from, CcFrom::Tier(_))
            && let Some(why) = dropped_by(&v.name, &|n| managed_has.contains(n))
        {
            v.in_effect = false;
            v.why = Some(why);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn process_vars() -> Vec<String> {
    let mut names: Vec<String> = PROCESS_VARS.iter().map(|s| s.to_string()).collect();
    for k in KINDS {
        names.push(format!("OTEL_EXPORTER_OTLP_{k}"));
        for s in SIGNALS {
            names.push(format!("OTEL_EXPORTER_OTLP_{s}_{k}"));
        }
    }
    names
}

/// Step 8: does Claude Code skip server-managed settings with this setup?
fn skips_server(env: &[CcEnvVar]) -> bool {
    let get = |n: &str| {
        env.iter()
            .find(|v| v.name == n && v.in_effect)
            .map(|v| v.value.as_str())
    };
    ["BEDROCK", "VERTEX", "FOUNDRY"].iter().any(|p| {
        get(&format!("CLAUDE_CODE_USE_{p}")).is_some_and(|v| value::truthy(&Value::from(v)))
    }) || get("ANTHROPIC_BASE_URL").is_some_and(|u| {
        redact::url_host(u).is_none_or(|h| !h.eq_ignore_ascii_case("api.anthropic.com"))
    })
}

/// Step 9: the selected `policyHelper`.
pub fn policy_helper(
    ctx: &ScanCtx,
    tiers: &[CcTier],
    policy: Option<&CcTierId>,
) -> Option<(Loc, CcTierId)> {
    let t = tiers
        .iter()
        .find(|t| Some(&t.id) == policy && t.id != CcTierId::Server)?;
    let path = t.value.get("policyHelper")?.get("path")?.as_str()?;
    let loc = if let Some(rest) = path.strip_prefix("~/") {
        ctx.h().home(rest)
    } else if path.starts_with('/') {
        ctx.h().sys(path)
    } else {
        return None;
    };
    Some((loc, t.id.clone()))
}

fn read_object(ctx: &mut ScanCtx, loc: &Loc, origin: Origin) -> Option<Map<String, Value>> {
    match ctx.read(loc, origin, Format::Json)? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// Read every source and resolve precedence (rules.md §CC.2).
pub fn resolve(ctx: &mut ScanCtx) -> CcConfig {
    let cfg_dir = ctx.h().tool_home(ToolHome::ClaudeConfig);
    let sys_dir = match ctx.h().os {
        Os::Macos => ctx.h().sys("/Library/Application Support/ClaudeCode"),
        Os::Linux => ctx.h().sys("/etc/claude-code"),
    };
    let mut tiers = Vec::new();

    let server_loc = cfg_dir.join("remote-settings.json");
    if let Some(value) = read_object(ctx, &server_loc, Origin::Server) {
        tiers.push(make_tier(
            CcTierId::Server,
            server_loc,
            Origin::Server,
            value,
        ));
    }

    let mut mdm: Option<(Loc, Map<String, Value>)> = None;
    for (loc, v) in ctx.read_mdm(DOMAIN) {
        let Value::Object(m) = v else { continue };
        match &mut mdm {
            None => mdm = Some((loc, m)),
            Some((_, acc)) => {
                for (k, x) in m {
                    acc.entry(k).or_insert(x);
                }
            }
        }
    }
    if let Some((loc, value)) = mdm {
        tiers.push(make_tier(CcTierId::Mdm, loc, Origin::Mdm, value));
    }

    let main = sys_dir.join("managed-settings.json");
    let mut file: Option<(Loc, Map<String, Value>)> =
        read_object(ctx, &main, Origin::System).map(|m| (main, m));
    let dropins = sys_dir.join("managed-settings.d");
    for loc in ctx.list(&dropins, ".json", Origin::System) {
        let Some(m) = read_object(ctx, &loc, Origin::System) else {
            continue;
        };
        file = Some(match file {
            Some((l, a)) => (l, merge_dropin(&a, &m)),
            None => (dropins.clone(), m),
        });
    }
    if let Some((loc, value)) = file {
        tiers.push(make_tier(CcTierId::File, loc, Origin::System, value));
    }

    let mcp_lock = {
        let loc = sys_dir.join("managed-mcp.json");
        read_object(ctx, &loc, Origin::System).map(|m| (loc, m))
    };
    let user = {
        let loc = cfg_dir.join("settings.json");
        let origin = user_origin(ctx, &loc);
        read_object(ctx, &loc, origin).map(|m| (loc, m))
    };
    let limits = {
        let loc = cfg_dir.join("policy-limits.json");
        read_object(ctx, &loc, Origin::Server).map(|m| (loc, m))
    };

    let policy = policy_tier(&tiers);
    let (behavior, bad_behavior) = behavior(&tiers);
    let managed: Vec<CcSetting> = tiers
        .iter()
        .flat_map(|t| {
            t.value
                .iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| CcSetting {
                    key: k.clone(),
                    value: v.clone(),
                    tier: t.id.clone(),
                    in_effect: in_effect(&tiers, policy.as_ref(), &behavior, k, t),
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let user_env = user.as_ref().map(|(_, m)| env_pairs(m)).unwrap_or_default();
    let process_env: Vec<(String, String)> = process_vars()
        .into_iter()
        .filter_map(|n| ctx.h().env(&n).map(|v| (n, v.to_string())))
        .collect();
    let env = effective_env(managed_env(&tiers), user_env, process_env);
    let server_be = skips_server(&env) || ctx.h().env_kind == EnvKind::Launchd;
    let helper = policy_helper(ctx, &tiers, policy.as_ref());

    let cfg = CcConfig {
        tiers,
        policy_tier: policy,
        behavior,
        helper,
        server_be,
        managed,
        user,
        mcp_lock,
        limits,
        env,
    };
    if is_installed(ctx, &cfg) {
        ctx.installed();
        ctx.note("Server-managed settings are visible only through the local cache.");
        if ctx.h().env_kind == EnvKind::Launchd {
            ctx.note(
                "Your shell's variables aren't visible here, so settings made with them may be missing. Run `cainary scan` in a terminal.",
            );
        }
    }
    resolver_findings(ctx, &cfg, bad_behavior);
    cfg
}

/// The probe: `<cfg>` is a directory, `claude` is on PATH, or any source is present.
pub fn is_installed(ctx: &ScanCtx, cfg: &CcConfig) -> bool {
    let dir = ctx.h().tool_home(ToolHome::ClaudeConfig);
    ctx.probe(&dir) == Probe::Dir
        || matches!(ctx.h().which("claude", None), Which::Found(_))
        || !cfg.tiers.is_empty()
        || cfg.mcp_lock.is_some()
        || cfg.user.is_some()
        || cfg.limits.is_some()
}

/// Source, evidence and best-effort flag of a finding that comes from an effective variable.
pub fn from_finding(
    ctx: &ScanCtx,
    cfg: &CcConfig,
    from: &CcFrom,
    var: &str,
    b: FindingBuilder,
    mut evidence: Vec<String>,
    own_be: bool,
) -> FindingBuilder {
    match from {
        CcFrom::Tier(id) => match tier(cfg, id) {
            Some(t) => {
                if cfg.helper.is_some() {
                    evidence.push("may be replaced by policyHelper".to_string());
                }
                b.source(tier_source(t))
                    .evidence(evidence)
                    .best_effort(admin_be(cfg, id, own_be))
            }
            None => b.source(ctx.env_source(var)).evidence(evidence),
        },
        CcFrom::User => {
            let source = match &cfg.user {
                Some((loc, _)) => {
                    Source::new(loc.shown.clone(), user_origin(ctx, loc), SourceKind::File)
                }
                None => ctx.env_source(var),
            };
            b.source(source).evidence(evidence).best_effort(own_be)
        }
        CcFrom::Process => b
            .source(ctx.env_source(var))
            .evidence(evidence)
            .best_effort(own_be),
    }
}

fn make_tier(id: CcTierId, loc: Loc, origin: Origin, value: Map<String, Value>) -> CcTier {
    let policy = is_policy_doc(&value);
    CcTier {
        id,
        loc,
        origin,
        value,
        policy,
    }
}

/// Info findings about the tiers themselves: an empty cache, an unknown merge mode, ignored keys.
fn resolver_findings(ctx: &mut ScanCtx, cfg: &CcConfig, bad_behavior: Option<(CcTierId, String)>) {
    if let Some(t) = tier(cfg, &CcTierId::Server)
        && t.value.is_empty()
        && let Some(b) = tier_finding(
            cfg,
            &t.id,
            FindingBuilder::new("Your organization has no server-managed settings")
                .detail("The local copy of the server-managed settings is empty.")
                .reference(doc("server-managed-settings")),
            Vec::new(),
            false,
        )
    {
        ctx.emit(b);
    }
    if let Some((id, text)) = bad_behavior
        && let Some(b) = tier_finding(
            cfg,
            &id,
            FindingBuilder::new("Managed settings use an unknown merge mode")
                .detail("`managedSourcesBehavior` has a value cAInary doesn't know, so it reads the settings as first-wins.")
                .reference(doc("managed-settings")),
            vec![format!("managedSourcesBehavior = {text}")],
            false,
        )
    {
        ctx.emit(b);
    }
    for t in &cfg.tiers {
        let keys: Vec<&str> = cfg
            .managed
            .iter()
            .filter(|s| s.tier == t.id && !s.in_effect)
            .map(|s| s.key.as_str())
            .collect();
        if keys.is_empty() {
            continue;
        }
        let mut lines: Vec<String> = keys.iter().take(20).map(|k| k.to_string()).collect();
        if keys.len() > 20 {
            lines.push(format!("… and {} more", keys.len() - 20));
        }
        let b = FindingBuilder::new(format!("Settings in {} are ignored", tier_name(&t.id)))
            .detail("A tier that takes precedence decides these settings, so they have no effect.")
            .reference(doc("managed-settings"))
            .in_effect(false);
        if let Some(b) = tier_finding(cfg, &t.id, b, lines, false) {
            ctx.emit(b);
        }
    }
}

pub fn scan(ctx: &mut ScanCtx) {
    let cfg = resolve(ctx);
    claude_code_policy::scan(ctx, &cfg);
    claude_code_telemetry::scan(ctx, &cfg);
    claude_code_hooks::scan(ctx, &cfg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{Harness, ScanOutput};
    use crate::model::Tool;
    use serde_json::json;
    use std::path::Path;

    fn resolved(name: &str) -> (CcConfig, ScanOutput) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/resolve");
        let h = Harness::from_fixture(&dir.join(name)).expect("fixture loads");
        let mut ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        let cfg = resolve(&mut ctx);
        (cfg, ctx.finish())
    }

    fn setting<'a>(cfg: &'a CcConfig, key: &str, tier: CcTierId) -> &'a CcSetting {
        cfg.managed
            .iter()
            .find(|s| s.key == key && s.tier == tier)
            .unwrap_or_else(|| panic!("no {key}"))
    }

    #[test]
    fn server_shadows_mdm_shadows_file() {
        let (cfg, out) = resolved("claude-code-tiers");
        let ids: Vec<_> = cfg.tiers.iter().map(|t| t.id.clone()).collect();
        assert_eq!(ids, [CcTierId::Server, CcTierId::Mdm, CcTierId::File]);
        assert_eq!(cfg.policy_tier, Some(CcTierId::Server));
        assert_eq!(cfg.behavior, Behavior::FirstWins);
        assert!(setting(&cfg, "model", CcTierId::Server).in_effect);
        assert!(!setting(&cfg, "model", CcTierId::Mdm).in_effect);
        assert!(!setting(&cfg, "model", CcTierId::File).in_effect);
        // `env` is read from every tier
        assert!(setting(&cfg, "env", CcTierId::File).in_effect);
        assert!(env(&cfg, "ACME_MODE").is_some());
        assert!(out.installed);
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("Server-managed settings are visible only"))
        );
        assert!(
            out.findings
                .iter()
                .any(|f| !f.in_effect && f.title.contains("the managed settings file are ignored"))
        );
    }

    #[test]
    fn dropins_merge_in_name_order() {
        let (cfg, _) = resolved("claude-code-tiers");
        let file = tier(&cfg, &CcTierId::File).unwrap();
        assert_eq!(file.value["availableModels"], json!(["a", "b"]));
        assert_eq!(file.value["model"], json!("haiku"));
    }

    #[test]
    fn merge_mode_takes_locks_from_every_tier_and_scalars_from_the_highest() {
        let (cfg, _) = resolved("claude-code-merge");
        assert_eq!(cfg.behavior, Behavior::Merge);
        assert_eq!(cfg.policy_tier, Some(CcTierId::Mdm));
        assert!(setting(&cfg, "model", CcTierId::Mdm).in_effect);
        assert!(!setting(&cfg, "model", CcTierId::File).in_effect);
        assert!(setting(&cfg, "disableAllHooks", CcTierId::File).in_effect);
        assert!(setting(&cfg, "permissions", CcTierId::File).in_effect);
    }

    #[test]
    fn launchd_note_and_dropped_local_routing_var() {
        let (cfg, out) = resolved("claude-code-launchd");
        let v = cfg
            .env
            .iter()
            .find(|v| v.name == "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
            .expect("local var kept in the list");
        assert!(!v.in_effect && v.why.is_some());
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("Your shell's variables aren't visible"))
        );
        assert!(cfg.server_be);
    }

    #[test]
    fn policy_helper_is_selected_from_mdm_or_file() {
        let (cfg, _) = resolved("claude-code-helper");
        let (loc, id) = cfg.helper.expect("helper selected");
        assert_eq!(id, CcTierId::File);
        assert_eq!(loc.shown, "/opt/acme/policy-helper");
        let (cfg, _) = resolved("claude-code-tiers");
        assert!(cfg.helper.is_none());
    }
}
