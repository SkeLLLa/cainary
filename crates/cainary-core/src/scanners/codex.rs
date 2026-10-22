//! codex scanner: layers, requirements, config precedence → `CxConfig` (rules.md §CX).

use super::codex_telemetry;
use crate::harness::{Loc, Probe, ScanCtx, ToolHome, Which};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind};
use crate::redact;
use crate::rules::hooks::{self, Cmd, Hit, Target};
use crate::rules::mcp;
use crate::value::{self, Format, Value};
use serde_json::Map;
use std::collections::{BTreeMap, BTreeSet};

const MDM_DOMAIN: &str = "com.openai.codex";
const REF_MANAGED: &str = "https://learn.chatgpt.com/docs/enterprise/managed-configuration";
const REF_CONFIG: &str = "https://learn.chatgpt.com/docs/config-file/config-reference";
const REF_HOOKS: &str = "https://learn.chatgpt.com/docs/hooks";
const LEGACY_KEYS: [&str; 3] = ["approval_policy", "approvals_reviewer", "sandbox_mode"];
const PLUGIN_HOOK_DETAIL: &str =
    "Codex runs a plugin's hooks only after you trust them with /hooks.";
const HOOK_TRUST_NOTE: &str = "Codex runs hooks that don't come from your organization only after you trust them with /hooks; cAInary can't see which ones you trusted.";
/// CX.2: keys Codex ignores in cloud requirements.
const CLOUD_IGNORED: [&str; 4] = [
    "allowed_login_methods",
    "allowed_chatgpt_workspaces",
    "cli_auth_credentials_store",
    "chatgpt_base_url",
];
const PROFILE_NOTE: &str = "Findings about telemetry, analytics, model providers, `notify` and hooks describe your base config; a `--profile` you use can change them.";

// Plain data, no methods: concern tests build it by hand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CxLayerId {
    #[default]
    MdmReq,
    MdmCfg,
    CloudReq,
    CloudCfg,
    LegacyReq,
    SysReq,
    ManagedCfg,
    UserCfg,
    SysDefaults,
}

#[derive(Debug, Clone)]
pub struct CxLayer {
    pub id: CxLayerId,
    pub loc: Loc,
    pub origin: Origin,
}

#[derive(Debug, Clone, Default)]
pub struct CxSetting {
    pub value: Value,
    pub layer: CxLayerId,
    pub shadowed: Vec<CxLayerId>,
}

/// The dotted keys the resolver resolves; everything else is only listed in policy evidence.
pub const CX_KEYS: &[&str] = &[
    "model_provider",
    "model_providers",
    "openai_base_url",
    "chatgpt_base_url",
    "notify",
    "mcp_servers",
    "hooks",
    "features",
    "otel.exporter",
    "otel.trace_exporter",
    "otel.metrics_exporter",
    "otel.log_user_prompt",
    "analytics.enabled",
    "profile",
    "profiles",
];

#[derive(Debug, Clone, Default)]
pub struct CxConfig {
    /// Every present layer, requirements and config.
    pub layers: Vec<CxLayer>,
    /// Composed requirements, by top-level key.
    pub req: BTreeMap<String, CxSetting>,
    /// Each requirements layer's own `hooks` table, highest first: the composed table loses
    /// which layer contributed an event.
    pub req_hooks: Vec<(CxLayerId, Value)>,
    /// Effective config for `CX_KEYS`, plus every other top-level key that a managed config
    /// layer (MDM, managed file, cloud) sets: the scan lists those as "organization defaults".
    pub cfg: BTreeMap<String, CxSetting>,
    /// `<home>/hooks.json`.
    pub hooks_file: Option<(Loc, Value)>,
    /// Config MCP servers after per-name merging; each entry retains its setting layer.
    pub config_mcp_servers: Vec<(CxLayerId, String, Value)>,
    /// The hooks table of each enabled plugin's manifest (CX.7), with the manifest's location.
    pub plugin_hooks: Vec<(Loc, Value)>,
    /// Enabled plugin MCP server entries, with their `.mcp.json` source.
    pub plugin_mcp_servers: Vec<(Loc, String, Value)>,
    /// CX.2 keys found in cloud requirements.
    pub cloud_ignored: Vec<String>,
}

/// A layer as read: its parsed TOML (an object).
struct Raw {
    id: CxLayerId,
    loc: Loc,
    origin: Origin,
    value: Value,
}

/// CX.1: a table merges by key, anything else is the higher layer's.
pub fn compose_req(lower: &Value, higher: &Value) -> Value {
    match (lower, higher) {
        (Value::Object(l), Value::Object(h)) => {
            let mut out = l.clone();
            for (k, hv) in h {
                let v = match l.get(k) {
                    Some(lv) => compose_req(lv, hv),
                    None => hv.clone(),
                };
                out.insert(k.clone(), v);
            }
            Value::Object(out)
        }
        _ => higher.clone(),
    }
}

/// The setting of `key` over the layers in `order` (highest first).
fn settle(raws: &[Raw], order: &[CxLayerId], key: &str, merge: bool) -> Option<CxSetting> {
    let setters: Vec<(CxLayerId, &Value)> = order
        .iter()
        .filter_map(|id| {
            let raw = raws.iter().find(|r| r.id == *id)?;
            value::get(&raw.value, key).map(|v| (*id, v))
        })
        .collect();
    let (layer, top) = *setters.first()?;
    let value = if merge {
        let mut lowest_first = setters.iter().rev();
        let mut acc = lowest_first.next()?.1.clone();
        for (_, v) in lowest_first {
            acc = compose_req(&acc, v);
        }
        acc
    } else {
        top.clone()
    };
    Some(CxSetting {
        value,
        layer,
        shadowed: setters[1..].iter().map(|(id, _)| *id).collect(),
    })
}

/// The first MDM plist that carries `key` gives a base64 TOML document.
fn mdm_toml(ctx: &mut ScanCtx, plists: &[(Loc, Value)], key: &str) -> Option<(Loc, Value)> {
    let (loc, text) = plists
        .iter()
        .find_map(|(loc, v)| Some((loc, v.get(key)?.as_str()?)))?;
    let parsed = ctx.parse_inner(loc, Origin::Mdm, key, text.as_bytes(), Format::TomlBase64)?;
    Some((loc.clone(), parsed))
}

/// The cloud cache's TOML texts of one kind, parsed and composed in order.
fn cloud_toml(ctx: &mut ScanCtx, cache: &Value, loc: &Loc, kind: &str) -> Option<Value> {
    let path = format!("signed_payload.bundle.{kind}.enterprise_managed");
    let entries = value::get(cache, &path)?.as_array()?;
    let mut merged: Option<Value> = None;
    for (i, entry) in entries.iter().enumerate() {
        let Some(text) = entry.get("contents").and_then(Value::as_str) else {
            continue;
        };
        let key = format!("{kind}.{i}");
        if let Some(t) = ctx.parse_inner(loc, Origin::Server, &key, text.as_bytes(), Format::Toml) {
            merged = Some(match merged {
                Some(m) => compose_req(&m, &t),
                None => t,
            });
        }
    }
    merged
}

/// `<home>` is a dir or `codex` is on PATH.
pub fn is_installed(ctx: &ScanCtx) -> bool {
    let home = ctx.h().tool_home(ToolHome::CodexHome);
    ctx.probe(&home) == Probe::Dir || matches!(ctx.h().which("codex", None), Which::Found(_))
}

/// Read every source and resolve precedence (rules.md §CX.1).
pub fn resolve(ctx: &mut ScanCtx) -> CxConfig {
    let home = ctx.h().tool_home(ToolHome::CodexHome);
    let mut raws: Vec<Raw> = Vec::new();
    let mut cloud_ignored = Vec::new();
    let push = |raws: &mut Vec<Raw>, id, loc: Loc, origin, value: Value| {
        raws.push(Raw {
            id,
            loc,
            origin,
            value,
        })
    };

    let plists = ctx.read_mdm(MDM_DOMAIN);
    for (id, key) in [
        (CxLayerId::MdmReq, "requirements_toml_base64"),
        (CxLayerId::MdmCfg, "config_toml_base64"),
    ] {
        if let Some((loc, v)) = mdm_toml(ctx, &plists, key) {
            push(&mut raws, id, loc, Origin::Mdm, v);
        }
    }

    let cloud_loc = home.join("cloud-config-bundle-cache.json");
    if let Some(cache) = ctx.read(&cloud_loc, Origin::Server, Format::Json) {
        if let Some(mut req) = cloud_toml(ctx, &cache, &cloud_loc, "requirements_toml") {
            if let Value::Object(map) = &mut req {
                for key in CLOUD_IGNORED {
                    if map.remove(key).is_some() {
                        cloud_ignored.push(key.to_string());
                    }
                }
            }
            push(
                &mut raws,
                CxLayerId::CloudReq,
                cloud_loc.clone(),
                Origin::Server,
                req,
            );
        }
        if let Some(c) = cloud_toml(ctx, &cache, &cloud_loc, "config_toml") {
            push(
                &mut raws,
                CxLayerId::CloudCfg,
                cloud_loc.clone(),
                Origin::Server,
                c,
            );
        }
    }

    let managed_loc = ctx.h().sys("/etc/codex/managed_config.toml");
    if let Some(managed) = ctx.read(&managed_loc, Origin::System, Format::Toml) {
        let legacy: Map<String, Value> = LEGACY_KEYS
            .iter()
            .filter_map(|k| Some((k.to_string(), managed.get(k)?.clone())))
            .collect();
        if !legacy.is_empty() {
            push(
                &mut raws,
                CxLayerId::LegacyReq,
                managed_loc.clone(),
                Origin::System,
                Value::Object(legacy),
            );
        }
        push(
            &mut raws,
            CxLayerId::ManagedCfg,
            managed_loc,
            Origin::System,
            managed,
        );
    }

    let sys_req = ctx.h().sys("/etc/codex/requirements.toml");
    if let Some(v) = ctx.read(&sys_req, Origin::System, Format::Toml) {
        push(&mut raws, CxLayerId::SysReq, sys_req, Origin::System, v);
    }
    let user_cfg = home.join("config.toml");
    if let Some(v) = ctx.read(&user_cfg, Origin::User, Format::Toml) {
        push(&mut raws, CxLayerId::UserCfg, user_cfg, Origin::User, v);
    }
    let defaults = ctx.h().sys("/etc/codex/config.toml");
    if let Some(v) = ctx.read(&defaults, Origin::System, Format::Toml) {
        push(
            &mut raws,
            CxLayerId::SysDefaults,
            defaults,
            Origin::System,
            v,
        );
    }
    let hooks_loc = home.join("hooks.json");
    let hooks_file = ctx
        .read(&hooks_loc, Origin::User, Format::Json)
        .map(|v| (hooks_loc, v));

    use CxLayerId::*;
    let req_order = [MdmReq, LegacyReq, CloudReq, SysReq];
    let cfg_order = [MdmCfg, ManagedCfg, UserCfg, CloudCfg, SysDefaults];
    let org_cfg_order = [MdmCfg, ManagedCfg, CloudCfg];

    let mut req = BTreeMap::new();
    let req_keys: BTreeSet<&String> = raws
        .iter()
        .filter(|r| req_order.contains(&r.id))
        .filter_map(|r| r.value.as_object())
        .flat_map(Map::keys)
        .collect();
    for key in req_keys {
        if let Some(s) = settle(&raws, &req_order, key, true) {
            req.insert(key.clone(), s);
        }
    }

    let req_hooks = req_order
        .iter()
        .filter_map(|id| {
            let raw = raws.iter().find(|r| r.id == *id)?;
            Some((*id, raw.value.get("hooks")?.clone()))
        })
        .collect();

    let mut cfg = BTreeMap::new();
    for key in CX_KEYS {
        if let Some(s) = settle(&raws, &cfg_order, key, false) {
            cfg.insert(key.to_string(), s);
        }
    }
    let known: BTreeSet<&str> = CX_KEYS
        .iter()
        .map(|k| k.split('.').next().unwrap_or(k))
        .collect();
    let org_keys: BTreeSet<&String> = raws
        .iter()
        .filter(|r| org_cfg_order.contains(&r.id))
        .filter_map(|r| r.value.as_object())
        .flat_map(Map::keys)
        .filter(|k| !known.contains(k.split('.').next().unwrap_or(k)))
        .collect();
    for key in org_keys {
        if let Some(s) = settle(&raws, &org_cfg_order, key, false) {
            cfg.insert(key.clone(), s);
        }
    }

    // Requirements first, then config, each highest first.
    let layers = req_order
        .iter()
        .chain(&cfg_order)
        .filter_map(|id| raws.iter().find(|r| r.id == *id))
        .map(|r| CxLayer {
            id: r.id,
            loc: r.loc.clone(),
            origin: r.origin,
        })
        .collect();

    let mut config_mcp_servers = Vec::new();
    let mut seen_mcp_servers = BTreeSet::new();
    for id in &cfg_order {
        let Some(servers) = raws
            .iter()
            .find(|raw| raw.id == *id)
            .and_then(|raw| raw.value.get("mcp_servers"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (name, entry) in servers {
            if seen_mcp_servers.insert(name.clone()) {
                config_mcp_servers.push((*id, name.clone(), entry.clone()));
            }
        }
    }

    let plugin_settings = settle(&raws, &cfg_order, "plugins", true).map(|s| s.value);
    let enabled_plugins = plugin_settings
        .as_ref()
        .map(|settings| plugin_manifests(ctx, &home, settings))
        .unwrap_or_default();
    let plugin_hooks = plugin_hooks(ctx, &enabled_plugins);
    let plugin_mcp_servers = plugin_mcp_sources(ctx, &enabled_plugins);

    if is_installed(ctx) {
        ctx.installed();
    }
    CxConfig {
        layers,
        req,
        req_hooks,
        cfg,
        hooks_file,
        config_mcp_servers,
        plugin_hooks,
        plugin_mcp_servers,
        cloud_ignored,
    }
}

/// A plugin or marketplace name that is safe to use as one path segment.
fn path_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\'])
}

/// Dotted-number order, so `10.0` sorts above `9.0`; anything non-numeric falls back to text.
fn version_key(name: &str) -> (Vec<u64>, String) {
    let nums = name.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    (nums, name.to_string())
}

struct ResolvedPlugin {
    root: Loc,
    manifest_loc: Loc,
    manifest: Value,
    settings: Value,
}

/// The highest installed version of each enabled plugin.
fn plugin_manifests(ctx: &mut ScanCtx, home: &Loc, settings: &Value) -> Vec<ResolvedPlugin> {
    let Some(table) = settings.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, entry) in table {
        let enabled = entry
            .get("enabled")
            .is_some_and(|v| v == &Value::Bool(true));
        let Some((name, market)) = key.split_once('@') else {
            continue;
        };
        if !enabled || !path_segment(name) || !path_segment(market) {
            continue;
        }
        let dir = home.join(&format!("plugins/cache/{market}/{name}"));
        let mut versions = ctx.list(&dir, "", Origin::User);
        versions.retain(|loc| {
            let version = loc.shown.rsplit('/').next().unwrap_or("");
            !version.starts_with('.') && ctx.probe(loc) == Probe::Dir
        });
        versions.sort_by_key(|l| version_key(l.shown.rsplit('/').next().unwrap_or("")));
        let Some(root) = versions.pop() else {
            continue;
        };
        let Some(canonical_root) = ctx.canonical(&root) else {
            continue;
        };
        let cache_prefix = format!("{}/", dir.shown.trim_end_matches('/'));
        if !canonical_root.shown.starts_with(&cache_prefix) {
            continue;
        }
        let Some(manifest_loc) = plugin_file(ctx, &root, "./.codex-plugin/plugin.json") else {
            continue;
        };
        let Some(manifest) = ctx.read(&manifest_loc, Origin::User, Format::Json) else {
            continue;
        };
        out.push(ResolvedPlugin {
            root,
            manifest_loc,
            manifest,
            settings: entry.clone(),
        });
    }
    out
}

fn hooks_table(value: &Value) -> &Value {
    value
        .get("hooks")
        .filter(|hooks| hooks.is_object())
        .unwrap_or(value)
}

/// A plugin-relative JSON file that resolves inside the canonical plugin root.
fn plugin_file(ctx: &ScanCtx, root: &Loc, path: &str) -> Option<Loc> {
    let relative = path.strip_prefix("./")?;
    if relative.is_empty() || relative.contains('\\') || relative.contains("..") {
        return None;
    }
    let canonical_root = ctx.canonical(root)?;
    let canonical_file = ctx.canonical(&root.join(relative))?;
    let prefix = format!("{}/", canonical_root.shown.trim_end_matches('/'));
    canonical_file
        .shown
        .starts_with(&prefix)
        .then_some(canonical_file)
}

/// Add one plugin hook source, either from an inline object or a safe in-root JSON path.
fn plugin_hook_source(
    ctx: &mut ScanCtx,
    plugin: &ResolvedPlugin,
    value: &Value,
    out: &mut Vec<(Loc, Value)>,
) {
    if let Some(path) = value.as_str() {
        let Some(loc) = plugin_file(ctx, &plugin.root, path) else {
            return;
        };
        if let Some(file) = ctx.read(&loc, Origin::User, Format::Json) {
            let table = hooks_table(&file);
            out.push((loc, table.clone()));
        }
    } else if value.is_object() {
        let table = hooks_table(value);
        out.push((plugin.manifest_loc.clone(), table.clone()));
    }
}

/// The hook sources of each enabled plugin. A present manifest `hooks` value replaces the
/// default `hooks/hooks.json` source.
fn plugin_hooks(ctx: &mut ScanCtx, plugins: &[ResolvedPlugin]) -> Vec<(Loc, Value)> {
    let mut out = Vec::new();
    for plugin in plugins {
        if let Some(hooks) = plugin.manifest.get("hooks") {
            match hooks {
                Value::Array(items) => {
                    for item in items {
                        plugin_hook_source(ctx, plugin, item, &mut out);
                    }
                }
                other => plugin_hook_source(ctx, plugin, other, &mut out),
            }
        } else {
            let Some(loc) = plugin_file(ctx, &plugin.root, "./hooks/hooks.json") else {
                continue;
            };
            if let Some(file) = ctx.read(&loc, Origin::User, Format::Json) {
                let table = file.get("hooks").filter(|h| h.is_object()).unwrap_or(&file);
                out.push((loc, table.clone()));
            }
        }
    }
    out
}

/// MCP servers from each enabled plugin's declared file, defaulting to `./.mcp.json`.
fn plugin_mcp_sources(ctx: &mut ScanCtx, plugins: &[ResolvedPlugin]) -> Vec<(Loc, String, Value)> {
    let mut out = Vec::new();
    for plugin in plugins {
        let path = match plugin.manifest.get("mcpServers") {
            Some(Value::String(path)) => path.as_str(),
            None => "./.mcp.json",
            Some(_) => continue,
        };
        let Some(loc) = plugin_file(ctx, &plugin.root, path) else {
            continue;
        };
        let Some(file) = ctx.read(&loc, Origin::User, Format::Json) else {
            continue;
        };
        let Some(servers) = file.get("mcpServers").and_then(Value::as_object) else {
            continue;
        };
        for (name, entry) in servers {
            let disabled_in_file = entry.get("enabled") == Some(&Value::Bool(false));
            let disabled_in_config = plugin
                .settings
                .get("mcp_servers")
                .and_then(|servers| servers.get(name))
                .and_then(|server| server.get("enabled"))
                == Some(&Value::Bool(false));
            if !disabled_in_file && !disabled_in_config {
                out.push((loc.clone(), name.clone(), entry.clone()));
            }
        }
    }
    out
}

/// The source a layer's findings cite.
pub fn layer_source(cfg: &CxConfig, id: CxLayerId) -> Source {
    match cfg.layers.iter().find(|l| l.id == id) {
        Some(l) => Source::new(l.loc.shown.clone(), l.origin, SourceKind::File),
        None => Source::new("codex", Origin::Unattributed, SourceKind::File),
    }
}

fn is_req(id: CxLayerId) -> bool {
    matches!(
        id,
        CxLayerId::MdmReq | CxLayerId::LegacyReq | CxLayerId::CloudReq | CxLayerId::SysReq
    )
}

fn is_org_cfg(id: CxLayerId) -> bool {
    matches!(
        id,
        CxLayerId::MdmCfg | CxLayerId::ManagedCfg | CxLayerId::CloudCfg
    )
}

pub fn scan(ctx: &mut ScanCtx) {
    let cfg = resolve(ctx);
    scan_config(ctx, &cfg);
    codex_telemetry::scan(ctx, &cfg);
}

/// CX.3, CX.6, CX.7 and MCP: everything except telemetry.
pub fn scan_config(ctx: &mut ScanCtx, cfg: &CxConfig) {
    policy(ctx, cfg);
    org_defaults(ctx, cfg);
    routing(ctx, cfg);
    notify(ctx, cfg);
    mcp_servers(ctx, cfg);
    hook_findings(ctx, cfg);
    profiles(ctx, cfg);
    ca_certificates(ctx);
}

fn req_group(key: &str) -> &'static str {
    match key {
        "approval_policy"
        | "approvals_reviewer"
        | "sandbox_mode"
        | "allowed_approval_policies"
        | "allowed_sandbox_modes" => "approvals/sandbox",
        "allowed_login_methods" | "allowed_chatgpt_workspaces" => "login",
        "features" => "features",
        "allow_managed_hooks_only" | "hooks" => "hooks",
        k if k.contains("mcp") => "mcp",
        _ => "other",
    }
}

const REQ_GROUPS: [&str; 6] = [
    "approvals/sandbox",
    "login",
    "features",
    "mcp",
    "hooks",
    "other",
];

fn policy(ctx: &mut ScanCtx, cfg: &CxConfig) {
    for layer in cfg.layers.iter().filter(|l| is_req(l.id)) {
        let keys: Vec<&str> = cfg
            .req
            .iter()
            .filter(|(_, s)| s.layer == layer.id)
            .map(|(k, _)| k.as_str())
            .collect();
        if keys.is_empty() {
            continue;
        }
        let evidence: Vec<String> = REQ_GROUPS
            .iter()
            .filter_map(|g| {
                let in_group: Vec<&str> = keys
                    .iter()
                    .copied()
                    .filter(|k| req_group(k) == *g)
                    .collect();
                (!in_group.is_empty()).then(|| format!("{g}: {}", in_group.join(", ")))
            })
            .collect();
        ctx.emit(
            FindingBuilder::new("Your organization sets Codex requirements")
                .signals(&[Signal::Policy])
                .detail("Requirements constrain what Codex may do; the values aren't shown.")
                .evidence(evidence)
                .source(layer_source(cfg, layer.id))
                .reference(REF_MANAGED),
        );
    }
    if !cfg.cloud_ignored.is_empty() {
        ctx.emit(
            FindingBuilder::new("Codex ignores some of your organization's cloud policy")
                .detail(
                    "Set in your organization's cloud policy, but Codex doesn't enforce it here.",
                )
                .evidence(cfg.cloud_ignored.iter().map(|k| format!("key = {k}")))
                .source(layer_source(cfg, CxLayerId::CloudReq))
                .reference(REF_MANAGED)
                .in_effect(false),
        );
    }
}

/// A managed layer's other config keys.
fn org_defaults(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let known: BTreeSet<&str> = CX_KEYS
        .iter()
        .map(|k| k.split('.').next().unwrap_or(k))
        .collect();
    for layer in cfg.layers.iter().filter(|l| is_org_cfg(l.id)) {
        let keys: Vec<String> = cfg
            .cfg
            .iter()
            .filter(|(k, s)| {
                s.layer == layer.id && !known.contains(k.split('.').next().unwrap_or(k))
            })
            .map(|(k, _)| format!("key = {k}"))
            .collect();
        if keys.is_empty() {
            continue;
        }
        ctx.emit(
            FindingBuilder::new("Your organization sets Codex defaults")
                .signals(&[Signal::Policy])
                .evidence(keys)
                .source(layer_source(cfg, layer.id))
                .reference(REF_MANAGED),
        );
    }
}

fn str_of<'a>(cfg: &'a CxConfig, key: &str) -> Option<&'a str> {
    cfg.cfg.get(key)?.value.as_str()
}

fn host_of(url: &str) -> String {
    redact::url_host(url).unwrap_or_else(|| "a custom endpoint".to_string())
}

fn routing(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let req_provider = cfg.req.get("model_provider").and_then(|s| s.value.as_str());
    let selected = req_provider
        .or_else(|| str_of(cfg, "model_provider"))
        .unwrap_or("openai");

    if let Some(setting) = cfg.cfg.get("model_providers")
        && let Some(providers) = setting.value.as_object()
    {
        for (name, p) in providers {
            let Some(url) = p.get("base_url").and_then(Value::as_str) else {
                continue;
            };
            let host = host_of(url);
            let mut evidence = vec![format!("base_url = {}", redact::url(url))];
            let mut header_names =
                redact::header_names(p.get("http_headers").unwrap_or(&Value::Null));
            if let Some(env) = p.get("env_http_headers").and_then(Value::as_object) {
                header_names.extend(env.keys().cloned());
            }
            evidence.extend(
                header_names
                    .iter()
                    .map(|h| format!("header {h} = <redacted>")),
            );
            let b = if name == selected {
                let mut signals = vec![Signal::Traffic];
                if !header_names.is_empty() {
                    signals.push(Signal::Identity);
                }
                if req_provider.is_some() {
                    signals.push(Signal::Policy);
                }
                FindingBuilder::new(format!("Codex model traffic goes through {host}"))
                    .signals(&signals)
            } else {
                FindingBuilder::new(format!(
                    "Codex has provider `{name}` set to {host} but doesn't use it"
                ))
            };
            ctx.emit(
                b.evidence(evidence)
                    .source(layer_source(cfg, setting.layer))
                    .reference(REF_CONFIG),
            );
        }
    }

    let mut base_urls = vec![("chatgpt_base_url", "Codex ChatGPT traffic")];
    if selected == "openai" {
        base_urls.push(("openai_base_url", "Codex model traffic"));
    }
    for (key, what) in base_urls {
        let (Some(url), Some(setting)) = (str_of(cfg, key), cfg.cfg.get(key)) else {
            continue;
        };
        ctx.emit(
            FindingBuilder::new(format!("{what} goes through {}", host_of(url)))
                .signals(&[Signal::Traffic])
                .evidence([format!("{key} = {}", redact::url(url))])
                .source(layer_source(cfg, setting.layer))
                .reference(REF_CONFIG),
        );
    }
}

fn argv(v: &Value) -> Option<Vec<String>> {
    let words: Vec<String> = v
        .as_array()?
        .iter()
        .map(|w| w.as_str().map(str::to_string))
        .collect::<Option<_>>()?;
    (!words.is_empty()).then_some(words)
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

fn notify(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let Some(setting) = cfg.cfg.get("notify") else {
        return;
    };
    let Some(words) = argv(&setting.value) else {
        return;
    };
    let cmd = Cmd::Argv(words);
    let source = layer_source(cfg, setting.layer);
    let evidence = [format!("command = {}", redact::command(&words_text(&cmd)))];
    if hooks::is_local_notifier(&cmd, None, ctx) {
        ctx.emit(
            FindingBuilder::new("Codex plays a sound or shows a notification after every turn")
                .evidence(evidence)
                .source(source)
                .reference(REF_CONFIG),
        );
        return;
    }
    let target = hooks::target(&cmd, None, ctx);
    let origin = hooks::origin(source.origin, &target, ctx);
    let source = Source::new(source.path, origin, SourceKind::File);
    let mut title = format!(
        "{} receives your prompts and Codex's replies after every turn",
        target_label(&target)
    );
    if let Some(host) = hooks::sends_to(&cmd) {
        title.push_str(&format!(" and sends them to {host}"));
    }
    ctx.emit(
        FindingBuilder::new(title)
            .signals(&[Signal::Prompts, Signal::Responses])
            .evidence(evidence)
            .source(source)
            .reference(REF_CONFIG),
    );
}

fn words_text(cmd: &Cmd) -> String {
    match cmd {
        Cmd::Shell(s) => s.clone(),
        Cmd::Argv(a) => a.join(" "),
    }
}

fn mcp_servers(ctx: &mut ScanCtx, cfg: &CxConfig) {
    for (layer, name, entry) in &cfg.config_mcp_servers {
        let source = layer_source(cfg, *layer);
        let finding = mcp::server(name, entry, source.origin, ctx)
            .source(source)
            .reference(REF_CONFIG);
        ctx.emit(finding);
    }
    for (loc, name, entry) in &cfg.plugin_mcp_servers {
        let source = Source::new(loc.shown.clone(), Origin::User, SourceKind::File);
        ctx.emit(
            mcp::server(name, entry, Origin::User, ctx)
                .source(source)
                .reference(REF_CONFIG),
        );
    }
}

/// CX.7 signals for one event.
fn event_signals(event: &str) -> Vec<Signal> {
    let mut s = vec![Signal::Transcript];
    match event {
        "UserPromptSubmit" => s.push(Signal::Prompts),
        "PreToolUse" | "PostToolUse" | "PermissionRequest" => s.push(Signal::ToolDetails),
        "Stop" | "SubagentStop" => s.push(Signal::Responses),
        _ => {}
    }
    s
}

fn hook_cmd(v: &Value) -> Option<Cmd> {
    match v.get("command")? {
        Value::String(s) => Some(Cmd::Shell(s.clone())),
        other => argv(other).map(Cmd::Argv),
    }
}

/// `<server>.<tool>` of an `mcp_tool` handler.
fn mcp_tool_name(v: &Value) -> Option<String> {
    if v.get("type")?.as_str()? != "mcp_tool" {
        return None;
    }
    let server = v.get("server")?.as_str()?;
    let tool = v.get("tool")?.as_str()?;
    Some(format!("{server}.{tool}"))
}

fn hook_findings(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let mut rtk_telemetry = None;
    let mut trust_note_needed = false;
    if let Some((loc, v)) = &cfg.hooks_file {
        let table = hooks_table(v);
        let source = Source::new(loc.shown.clone(), Origin::User, SourceKind::File);
        trust_note_needed |= source.origin == Origin::User
            && hooks_from(ctx, cfg, table, source, None, false, &mut rtk_telemetry);
    }
    if let Some(setting) = cfg.cfg.get("hooks") {
        let source = layer_source(cfg, setting.layer);
        let in_effect = hooks_from(
            ctx,
            cfg,
            &setting.value,
            source.clone(),
            None,
            false,
            &mut rtk_telemetry,
        );
        trust_note_needed |=
            source.origin == Origin::User && !is_org_cfg(setting.layer) && in_effect;
    }
    // Plugin hooks are not managed: `allow_managed_hooks_only` blocks them like user hooks.
    for (loc, table) in &cfg.plugin_hooks {
        let source = Source::new(loc.shown.clone(), Origin::User, SourceKind::File);
        trust_note_needed |= source.origin == Origin::User
            && hooks_from(ctx, cfg, table, source, None, true, &mut rtk_telemetry);
    }
    // Requirements hooks are the managed hooks: exempt from `allow_managed_hooks_only`. Each
    // layer is read on its own so a finding cites the layer that set it; with more than one
    // contributing layer Codex's composition is uncertain, so they are BE (CX.7).
    let has_events = |t: &Value| {
        t.as_object()
            .is_some_and(|m| m.values().any(Value::is_array))
    };
    let multi = cfg.req_hooks.iter().filter(|(_, t)| has_events(t)).count() > 1;
    for (id, table) in &cfg.req_hooks {
        let source = layer_source(cfg, *id);
        let best_effort = multi || *id == CxLayerId::CloudReq;
        let _ = hooks_from(
            ctx,
            cfg,
            table,
            source,
            Some(best_effort),
            false,
            &mut rtk_telemetry,
        );
    }
    if trust_note_needed {
        ctx.note(HOOK_TRUST_NOTE);
    }
}

fn hooks_from(
    ctx: &mut ScanCtx,
    cfg: &CxConfig,
    table: &Value,
    source: Source,
    managed: Option<bool>,
    best_effort_override: bool,
    rtk_telemetry: &mut Option<hooks::RtkTelemetry>,
) -> bool {
    let Some(events) = table.as_object() else {
        return false;
    };
    let managed_only = cfg
        .req
        .get("allow_managed_hooks_only")
        .is_some_and(|s| value::truthy(&s.value));
    let feature_off = cfg
        .cfg
        .get("features")
        .and_then(|s| s.value.get("hooks"))
        .is_some_and(|v| v == &Value::Bool(false));
    let pinned_on = cfg
        .req
        .get("features")
        .and_then(|s| s.value.get("hooks"))
        .is_some_and(value::truthy);
    let pinned_off = cfg
        .req
        .get("features")
        .and_then(|s| s.value.get("hooks"))
        .is_some_and(|v| v == &Value::Bool(false));
    let blocked = (managed.is_none() && managed_only && source.origin == Origin::User)
        || pinned_off
        || (feature_off && !pinned_on);

    let mut hits = Vec::new();
    let mut quiet = Vec::new();
    let mut mcp_hits: Vec<(String, String)> = Vec::new();
    for (event, entries) in events {
        for entry in entries.as_array().into_iter().flatten() {
            let inner: Vec<&Value> = match entry.get("hooks").and_then(Value::as_array) {
                Some(list) => list.iter().collect(),
                None => vec![entry],
            };
            for h in inner {
                if let Some(kind) = h.get("type")
                    && !matches!(kind.as_str(), Some("command" | "mcp_tool"))
                {
                    continue;
                }
                let Some(cmd) = hook_cmd(h) else {
                    if let Some(tool) = mcp_tool_name(h) {
                        mcp_hits.push((event.clone(), tool));
                    }
                    continue;
                };
                let notifier = hooks::is_local_notifier(&cmd, None, ctx);
                let hit = Hit {
                    event: event.clone(),
                    target: hooks::target(&cmd, None, ctx),
                    cmd,
                    in_effect: !blocked,
                };
                if notifier {
                    quiet.push(hit);
                } else {
                    hits.push(hit);
                }
            }
        }
    }
    let in_effect = !blocked && (!hits.is_empty() || !quiet.is_empty() || !mcp_hits.is_empty());

    // An `mcp_tool` handler calls a tool on an MCP server: one finding per `server.tool`. Its
    // `input` isn't shown; the tool's own behaviour is unknown, so only the event's data is claimed.
    let mut tools: Vec<(String, Vec<String>)> = Vec::new();
    for (event, tool) in mcp_hits {
        let i = tools
            .iter()
            .position(|(t, _)| *t == tool)
            .unwrap_or_else(|| {
                tools.push((tool, Vec::new()));
                tools.len() - 1
            });
        if !tools[i].1.contains(&event) {
            tools[i].1.push(event);
        }
    }
    for (tool, events) in tools {
        let signals: Vec<Signal> = events.iter().flat_map(|e| event_signals(e)).collect();
        let tool = redact::text(&tool);
        let mut finding = FindingBuilder::new(format!(
            "Codex hook calls MCP tool `{tool}` on {}",
            events.join(", ")
        ))
        .signals(&signals)
        .evidence([
            format!("events = {}", events.join(", ")),
            format!("tool = {tool}"),
        ])
        .source(source.clone())
        .reference(REF_HOOKS)
        .best_effort(best_effort_override || managed == Some(true))
        .in_effect(!blocked);
        if best_effort_override {
            finding = finding.detail(PLUGIN_HOOK_DETAIL);
        }
        ctx.emit(finding);
    }

    for (list, plays_sound) in [(hits, false), (quiet, true)] {
        let all = list.clone();
        for g in hooks::group(list, None, ctx) {
            let label = target_label(&g.target);
            let origin = hooks::origin(source.origin, &g.target, ctx);
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
                for e in &g.events {
                    signals.extend(event_signals(e));
                }
            }
            let host = all
                .iter()
                .filter(|h| h.target == g.target)
                .find_map(|h| hooks::sends_to(&h.cmd));
            let mut title = if plays_sound {
                format!("Codex hook `{label}` plays a sound or shows a notification")
            } else if let Some(rtk) = &rtk {
                format!("Codex hook `rtk` {}", rtk.title_suffix)
            } else {
                format!("Codex hook `{label}` runs on {}", g.events.join(", "))
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
                .source(Source::new(source.path.clone(), origin, SourceKind::File))
                .reference(REF_HOOKS)
                .best_effort(
                    best_effort_override
                        || managed == Some(true)
                        || rtk.as_ref().is_some_and(|finding| finding.best_effort),
                )
                .in_effect(g.in_effect);
            let mut detail = best_effort_override.then(|| PLUGIN_HOOK_DETAIL.to_string());
            if let Some(rtk) = rtk {
                detail = Some(match detail {
                    Some(existing) => format!("{existing} {}", rtk.detail),
                    None => rtk.detail,
                });
            }
            if let Some(detail) = detail {
                finding = finding.detail(detail);
            }
            ctx.emit(finding);
        }
    }
    in_effect
}

fn profiles(ctx: &mut ScanCtx, cfg: &CxConfig) {
    if is_installed(ctx) {
        ctx.note(PROFILE_NOTE);
    }
    for key in ["profile", "profiles"] {
        if let Some(setting) = cfg.cfg.get(key) {
            ctx.emit(
                FindingBuilder::new(format!("Codex no longer reads `{key}`"))
                    .evidence([format!("key = {key}")])
                    .source(layer_source(cfg, setting.layer))
                    .reference(REF_CONFIG),
            );
        }
    }
}

fn ca_certificates(ctx: &mut ScanCtx) {
    for var in ["CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"] {
        let Some(path) = ctx.h().env(var).map(str::to_string) else {
            continue;
        };
        let b = FindingBuilder::new("Codex trusts a custom CA certificate for HTTPS traffic")
            .signals(&[Signal::Traffic])
            .best_effort(true)
            .evidence([format!("{var} = {}", redact::text(&path))])
            .source(ctx.env_source(var))
            .reference(REF_CONFIG);
        ctx.emit(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::platform::Os;
    use crate::model::{Finding, Level, SourceState, Tool};
    use serde_json::json;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Harness {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resolve")
            .join(name);
        Harness::from_fixture(&dir).unwrap()
    }

    fn setting(v: Value, layer: CxLayerId) -> CxSetting {
        CxSetting {
            value: v,
            layer,
            shadowed: vec![],
        }
    }

    fn layer(id: CxLayerId, origin: Origin) -> CxLayer {
        CxLayer {
            id,
            loc: Loc::test(&format!("/test/{id:?}")),
            origin,
        }
    }

    /// `scan_config` over a hand-built config.
    fn run(cfg: &CxConfig) -> Vec<Finding> {
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, cfg);
        ctx.finish().findings
    }

    fn with_cfg(layers: &[(CxLayerId, Origin)], cfg: &[(&str, Value, CxLayerId)]) -> CxConfig {
        let mut config_mcp_servers = Vec::new();
        let mut seen_mcp_servers = BTreeSet::new();
        for layer in [
            CxLayerId::MdmCfg,
            CxLayerId::ManagedCfg,
            CxLayerId::UserCfg,
            CxLayerId::CloudCfg,
            CxLayerId::SysDefaults,
        ] {
            for (key, value, source_layer) in cfg {
                if *key != "mcp_servers" || *source_layer != layer {
                    continue;
                }
                let Some(servers) = value.as_object() else {
                    continue;
                };
                for (name, entry) in servers {
                    if seen_mcp_servers.insert(name.clone()) {
                        config_mcp_servers.push((layer, name.clone(), entry.clone()));
                    }
                }
            }
        }
        CxConfig {
            layers: layers.iter().map(|(i, o)| layer(*i, *o)).collect(),
            cfg: cfg
                .iter()
                .map(|(k, v, l)| (k.to_string(), setting(v.clone(), *l)))
                .collect(),
            config_mcp_servers,
            ..CxConfig::default()
        }
    }

    // ---- resolver (R4-cx-a) ----

    #[test]
    fn resolver_layers_and_precedence() {
        let h = fixture("codex-layers");
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        let out = ctx.finish();
        assert!(out.installed);

        // LegacyReq sits above CloudReq: approval_policy comes from the legacy file.
        let ap = &cfg.req["approval_policy"];
        assert_eq!(ap.layer, CxLayerId::MdmReq);
        assert_eq!(ap.shadowed, [CxLayerId::LegacyReq, CxLayerId::CloudReq]);
        assert_eq!(cfg.req["sandbox_mode"].layer, CxLayerId::LegacyReq);
        assert_eq!(cfg.req["sandbox_mode"].value, "read-only");
        // sys requirements win only where nothing above sets the key
        assert_eq!(cfg.req["allow_managed_hooks_only"].layer, CxLayerId::SysReq);
        // tables merge by key across layers
        assert_eq!(
            cfg.req["features"].value,
            json!({"hooks": true, "web": false})
        );
        assert_eq!(cfg.req["features"].layer, CxLayerId::MdmReq);

        // CloudCfg sits below UserCfg; mdm cfg is on top
        let ex = &cfg.cfg["otel.exporter"];
        assert_eq!(ex.layer, CxLayerId::UserCfg);
        assert_eq!(ex.shadowed, [CxLayerId::CloudCfg]);
        assert_eq!(cfg.cfg["model_provider"].layer, CxLayerId::MdmCfg);
        assert_eq!(cfg.cfg["model_provider"].value, "acme");
        assert_eq!(cfg.cfg["notify"].layer, CxLayerId::ManagedCfg);
        assert_eq!(cfg.cfg["analytics.enabled"].layer, CxLayerId::SysDefaults);
        // a managed layer's other keys are kept; a user-only key is not
        assert_eq!(cfg.cfg["model"].layer, CxLayerId::ManagedCfg);
        assert!(!cfg.cfg.contains_key("user_only"));

        assert!(cfg.hooks_file.is_some());
        let ids: Vec<CxLayerId> = cfg.layers.iter().map(|l| l.id).collect();
        assert_eq!(ids.len(), 9);
        assert_eq!(ids[0], CxLayerId::MdmReq);
    }

    #[test]
    fn resolver_cloud_ignores_exactly_four_keys() {
        let h = fixture("codex-layers");
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        assert_eq!(
            cfg.cloud_ignored,
            [
                "allowed_login_methods",
                "allowed_chatgpt_workspaces",
                "cli_auth_credentials_store",
                "chatgpt_base_url"
            ]
        );
        // an ordinary cloud requirement key still composes
        assert_eq!(cfg.req["allowed_sandbox_modes"].layer, CxLayerId::CloudReq);
        assert!(!cfg.req.contains_key("allowed_login_methods"));
    }

    #[test]
    fn resolver_records_embedded_sources() {
        let h = fixture("codex-layers");
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        resolve(&mut ctx);
        let out = ctx.finish();
        let state = |suffix: &str| {
            out.sources
                .iter()
                .find(|s| s.source.path.ends_with(suffix))
                .unwrap_or_else(|| panic!("no source {suffix}"))
                .state
        };
        assert_eq!(state("#requirements_toml_base64"), SourceState::Present);
        assert_eq!(state("#config_toml_base64"), SourceState::Present);
        assert_eq!(state("#requirements_toml.0"), SourceState::Present);
    }

    #[test]
    fn resolver_undecodable_base64_is_an_error_source() {
        let h = fixture("codex-bad-base64");
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        let out = ctx.finish();
        assert!(cfg.req.is_empty());
        assert!(
            out.sources
                .iter()
                .any(|s| s.source.path.ends_with("#requirements_toml_base64")
                    && s.state == SourceState::Error)
        );
    }

    #[test]
    fn compose_req_merges_tables_and_replaces_the_rest() {
        let lower = json!({"a": [1], "t": {"x": 1, "y": 1}, "s": "low"});
        let higher = json!({"a": [2], "t": {"y": 2, "z": 2}, "s": "high"});
        assert_eq!(
            compose_req(&lower, &higher),
            json!({"a": [2], "t": {"x": 1, "y": 2, "z": 2}, "s": "high"})
        );
    }

    // ---- scan (R4-cx-b) ----

    #[test]
    fn requirements_give_one_policy_finding_per_layer() {
        let mut cfg = with_cfg(
            &[
                (CxLayerId::MdmReq, Origin::Mdm),
                (CxLayerId::SysReq, Origin::System),
            ],
            &[],
        );
        cfg.req.insert(
            "approval_policy".into(),
            setting(json!("on-request"), CxLayerId::MdmReq),
        );
        cfg.req.insert(
            "allow_managed_hooks_only".into(),
            setting(json!(true), CxLayerId::MdmReq),
        );
        cfg.req
            .insert("mcp_servers".into(), setting(json!({}), CxLayerId::SysReq));
        let f = run(&cfg);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.signals == [Signal::Policy]));
        assert_eq!(
            f[0].evidence,
            [
                "approvals/sandbox: approval_policy",
                "hooks: allow_managed_hooks_only"
            ]
        );
        assert_eq!(f[1].evidence, ["mcp: mcp_servers"]);
    }

    #[test]
    fn cloud_ignored_keys_are_info() {
        let mut cfg = with_cfg(&[(CxLayerId::CloudReq, Origin::Server)], &[]);
        cfg.cloud_ignored = vec!["allowed_login_methods".into()];
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && !f[0].in_effect);
    }

    #[test]
    fn selected_provider_gives_traffic_and_identity() {
        let providers = json!({
            "acme": {"base_url": "https://llm.example-corp.com/v1?k=sk-test-EXAMPLE",
                     "http_headers": {"X-Org": "alice"}, "env_http_headers": {"X-Tok": "ACME_TOKEN"}},
            "other": {"base_url": "https://other.example-corp.com"}
        });
        let mut cfg = with_cfg(
            &[(CxLayerId::ManagedCfg, Origin::System)],
            &[
                ("model_provider", json!("acme"), CxLayerId::ManagedCfg),
                ("model_providers", providers, CxLayerId::ManagedCfg),
            ],
        );
        let f = run(&cfg);
        let acme = f
            .iter()
            .find(|x| x.title.contains("llm.example-corp.com"))
            .unwrap();
        assert_eq!(acme.signals, [Signal::Traffic, Signal::Identity]);
        let ev = acme.evidence.join("\n");
        assert!(ev.contains("header X-Org") && ev.contains("header X-Tok"));
        assert!(!ev.contains("sk-test-EXAMPLE") && !ev.contains("alice"));
        let other = f
            .iter()
            .find(|x| x.title.contains("other.example-corp.com"))
            .unwrap();
        assert!(other.signals.is_empty());

        // a provider pinned by requirements adds policy
        cfg.req.insert(
            "model_provider".into(),
            setting(json!("acme"), CxLayerId::MdmReq),
        );
        let f = run(&cfg);
        let acme = f
            .iter()
            .find(|x| x.title.contains("llm.example-corp.com"))
            .unwrap();
        assert!(acme.signals.contains(&Signal::Policy));
    }

    #[test]
    fn base_urls_are_traffic() {
        let cfg = with_cfg(
            &[(CxLayerId::UserCfg, Origin::User)],
            &[
                (
                    "openai_base_url",
                    json!("https://proxy.example-corp.com/v1"),
                    CxLayerId::UserCfg,
                ),
                (
                    "chatgpt_base_url",
                    json!("https://chat.example-corp.com"),
                    CxLayerId::UserCfg,
                ),
            ],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.signals == [Signal::Traffic]));
        // openai_base_url only applies while the openai provider is selected
        let cfg = with_cfg(
            &[(CxLayerId::UserCfg, Origin::User)],
            &[
                ("model_provider", json!("acme"), CxLayerId::UserCfg),
                (
                    "openai_base_url",
                    json!("https://proxy.example-corp.com/v1"),
                    CxLayerId::UserCfg,
                ),
            ],
        );
        assert!(run(&cfg).is_empty());
    }

    #[test]
    fn notify_gives_prompts_and_responses() {
        let cfg = with_cfg(
            &[(CxLayerId::UserCfg, Origin::User)],
            &[(
                "notify",
                json!([
                    "python3",
                    "/opt/acme/notify.py",
                    "https://hooks.example-corp.com/x"
                ]),
                CxLayerId::UserCfg,
            )],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Prompts, Signal::Responses]);
        assert!(f[0].title.contains("notify.py"));
        assert!(f[0].title.contains("hooks.example-corp.com"));
    }

    #[test]
    fn org_and_user_mcp_servers_use_h7_signals() {
        let servers = json!({"acme": {"url": "https://mcp.example-corp.com/v1"}});
        let org = with_cfg(
            &[(CxLayerId::MdmCfg, Origin::Mdm)],
            &[("mcp_servers", servers.clone(), CxLayerId::MdmCfg)],
        );
        let f = run(&org);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::ToolDetails]);
        assert!(f[0].best_effort);
        let user = with_cfg(
            &[(CxLayerId::UserCfg, Origin::User)],
            &[(
                "mcp_servers",
                json!({
                    "remote": {"url": "https://mcp.example-corp.com/v1"},
                    "local": {"command": "/usr/local/bin/local-mcp"}
                }),
                CxLayerId::UserCfg,
            )],
        );
        let f = run(&user);
        assert_eq!(f.len(), 2);
        let remote = f
            .iter()
            .find(|finding| finding.title.contains("mcp.example-corp.com"))
            .unwrap();
        assert_eq!(remote.signals, [Signal::ToolDetails]);
        assert!(remote.best_effort);
        let local = f
            .iter()
            .find(|finding| finding.title.contains("local-mcp"))
            .unwrap();
        assert!(local.signals.is_empty());
        assert!(!local.best_effort);
        assert_eq!(local.source.origin, Origin::User);
    }

    #[test]
    fn org_and_user_mcp_servers_merge_per_name_with_layer_provenance() {
        let cfg = with_cfg(
            &[
                (CxLayerId::MdmCfg, Origin::Mdm),
                (CxLayerId::UserCfg, Origin::User),
            ],
            &[
                (
                    "mcp_servers",
                    json!({
                        "acme-org": {"url": "https://org.example-corp.com/v1"},
                        "acme-shared": {"url": "https://org-shared.example-corp.com/v1"}
                    }),
                    CxLayerId::MdmCfg,
                ),
                (
                    "mcp_servers",
                    json!({
                        "acme-user": {"url": "https://user.example-corp.com/v1"},
                        "acme-shared": {"url": "https://user-shared.example-corp.com/v1"}
                    }),
                    CxLayerId::UserCfg,
                ),
            ],
        );
        let findings = run(&cfg);
        assert_eq!(findings.len(), 3);

        let org = findings
            .iter()
            .find(|finding| finding.title.contains("org.example-corp.com"))
            .unwrap();
        assert_eq!(org.source.origin, Origin::Mdm);
        assert!(org.source.path.ends_with("/MdmCfg"));
        assert_eq!(org.signals, [Signal::ToolDetails]);
        assert!(org.best_effort);

        let user = findings
            .iter()
            .find(|finding| finding.title.contains("user.example-corp.com"))
            .unwrap();
        assert_eq!(user.source.origin, Origin::User);
        assert!(user.source.path.ends_with("/UserCfg"));

        let shared = findings
            .iter()
            .find(|finding| finding.title.contains("org-shared.example-corp.com"))
            .unwrap();
        assert_eq!(shared.source.origin, Origin::Mdm);
        assert!(shared.source.path.ends_with("/MdmCfg"));
        assert!(
            findings
                .iter()
                .all(|finding| !finding.title.contains("user-shared.example-corp.com"))
        );
    }

    #[test]
    fn resolver_merges_mcp_servers_from_org_and_user_layers() {
        let h = fixture("codex-mcp-merge");
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        assert_eq!(
            cfg.config_mcp_servers
                .iter()
                .map(|(layer, name, _)| (*layer, name.as_str()))
                .collect::<Vec<_>>(),
            [
                (CxLayerId::ManagedCfg, "acme-org"),
                (CxLayerId::ManagedCfg, "acme-shared"),
                (CxLayerId::UserCfg, "acme-user"),
            ]
        );
        scan_config(&mut ctx, &cfg);
        let findings = ctx.finish().findings;
        assert_eq!(findings.len(), 3);

        let org = findings
            .iter()
            .find(|finding| finding.title.contains("org.example-corp.com"))
            .unwrap();
        assert_eq!(org.source.origin, Origin::System);
        assert!(org.source.path.ends_with("/managed_config.toml"));
        let user = findings
            .iter()
            .find(|finding| finding.title.contains("user.example-corp.com"))
            .unwrap();
        assert_eq!(user.source.origin, Origin::User);
        assert!(user.source.path.ends_with("/config.toml"));
        let shared = findings
            .iter()
            .find(|finding| finding.title.contains("org-shared.example-corp.com"))
            .unwrap();
        assert_eq!(shared.source.origin, Origin::System);
        assert!(shared.source.path.ends_with("/managed_config.toml"));
        assert!(
            findings
                .iter()
                .all(|finding| !finding.title.contains("user-shared.example-corp.com"))
        );
    }

    #[test]
    fn managed_layer_other_keys_are_policy() {
        let cfg = with_cfg(
            &[(CxLayerId::ManagedCfg, Origin::System)],
            &[
                ("model", json!("gpt-x"), CxLayerId::ManagedCfg),
                ("otel.exporter", json!("none"), CxLayerId::ManagedCfg),
            ],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].evidence,
            ["key = model"],
            "resolved keys aren't 'other'"
        );
        assert_eq!(f[0].signals, [Signal::Policy]);
        assert_eq!(f[0].title, "Your organization sets Codex defaults");
    }

    #[test]
    fn retired_profile_keys_are_info() {
        let cfg = with_cfg(
            &[(CxLayerId::UserCfg, Origin::User)],
            &[("profile", json!("work"), CxLayerId::UserCfg)],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty());
        assert!(f[0].title.contains("no longer reads"));
    }

    #[test]
    fn profile_note_needs_codex_installed() {
        // Harness::test points at nothing: not installed, no note.
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &CxConfig::default());
        assert!(ctx.finish().notes.is_empty());
    }

    #[test]
    fn ca_certificate_env_is_traffic_be() {
        let h = Harness::test(Os::Macos, &[("CODEX_CA_CERTIFICATE", "/etc/acme/ca.pem")]);
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &CxConfig::default());
        let f = ctx.finish().findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Traffic]);
        assert!(f[0].best_effort);
    }

    fn hooks_cfg(hooks: Value, extra: &[(&str, Value, CxLayerId)]) -> CxConfig {
        let mut cfg = with_cfg(&[(CxLayerId::UserCfg, Origin::User)], extra);
        cfg.hooks_file = Some((Loc::test("~/.codex/hooks.json"), hooks));
        cfg
    }

    #[test]
    fn trust_note_is_once_for_in_effect_user_config_and_plugin_hooks() {
        let table = json!({"Stop": [{"command": "/opt/acme/run.sh"}]});
        let mut cfg = hooks_cfg(
            json!({"hooks": table.clone()}),
            &[("hooks", table.clone(), CxLayerId::UserCfg)],
        );
        cfg.plugin_hooks = vec![(
            Loc::test("~/.codex/plugins/cache/example-market/acme-demo/1.0.0/hooks/hooks.json"),
            table,
        )];
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        let output = ctx.finish();
        assert_eq!(output.notes, vec![HOOK_TRUST_NOTE.to_string()]);

        let org = with_cfg(
            &[(CxLayerId::MdmCfg, Origin::Mdm)],
            &[(
                "hooks",
                json!({"Stop": [{"command": "/opt/acme/run.sh"}]}),
                CxLayerId::MdmCfg,
            )],
        );
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &org);
        assert!(ctx.finish().notes.is_empty());

        let mut cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "/opt/acme/run.sh"}]}}),
            &[],
        );
        cfg.req.insert(
            "allow_managed_hooks_only".into(),
            setting(json!(true), CxLayerId::MdmReq),
        );
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        assert!(ctx.finish().notes.is_empty());
    }

    #[test]
    fn hooks_signals_by_event() {
        let cfg = hooks_cfg(
            json!({"hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/opt/acme/log.sh"}]}],
                "PreToolUse": [{"command": ["/opt/acme/log.sh"]}],
                "Stop": [{"hooks": [{"command": "/opt/acme/log.sh"}]}]
            }}),
            &[],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 1, "grouped by target");
        assert_eq!(
            f[0].signals,
            [
                Signal::Prompts,
                Signal::Responses,
                Signal::Transcript,
                Signal::ToolDetails
            ]
        );
        assert!(f[0].in_effect);
    }

    #[test]
    fn known_local_rtk_hook_is_low_when_telemetry_is_not_configured() {
        let h = fixture("rtk-telemetry-missing");
        let cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "rtk hook codex"}]}}),
            &[],
        );
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        let f = ctx.finish().findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Codex hook `rtk` runs on Stop");
        assert_eq!(f[0].signals, [Signal::Usage]);
        assert_eq!(f[0].level(), Level::Low);
        assert!(f[0].detail.contains("local token reducer"));
        assert!(f[0].evidence.iter().any(|line| {
            line == "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        }));
    }

    #[test]
    fn unresolved_rtk_hook_under_launchd_is_best_effort() {
        let h = fixture("claude-code-launchd");
        assert_eq!(h.env_kind, crate::harness::platform::EnvKind::Launchd);
        let cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "rtk hook codex"}]}}),
            &[],
        );
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        let findings = ctx.finish().findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].signals, [Signal::Usage]);
        assert_eq!(findings[0].level(), Level::Low);
        assert!(findings[0].best_effort);
        assert!(
            findings[0]
                .detail
                .contains("Couldn't tell which `rtk` runs")
        );
    }

    #[test]
    fn known_local_rtk_hook_is_medium_when_consent_enables_telemetry() {
        let h = fixture("rtk-telemetry-on");
        let cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "rtk hook codex"}]}}),
            &[],
        );
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        let f = ctx.finish().findings;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Traffic]);
        assert_eq!(f[0].level(), Level::Medium);
        assert!(f[0].detail.contains("rtk telemetry is on"));
        assert!(f[0].evidence.iter().any(|line| {
            line == "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        }));
    }

    #[test]
    fn other_rtk_commands_keep_normal_hook_exposure() {
        let cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "rtk proxy curl https://collector.example/x"}]}}),
            &[],
        );
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].level(), Level::High);
        assert!(f[0].signals.contains(&Signal::Transcript));
        assert!(f[0].title.contains("Codex hook `rtk` runs on Stop"));
    }

    #[test]
    fn hooks_network_wording_and_unresolved_target() {
        let cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "curl -s https://c.example-corp.com/x"}]}}),
            &[],
        );
        let f = run(&cfg);
        assert!(f[0].title.contains("c.example-corp.com"), "{}", f[0].title);
        assert!(
            f[0].evidence
                .iter()
                .any(|e| e.contains("couldn't tell which `curl` runs"))
        );
    }

    #[test]
    fn managed_hooks_only_blocks_user_hooks() {
        let mut cfg = hooks_cfg(
            json!({"hooks": {"Stop": [{"command": "/opt/acme/log.sh"}]}}),
            &[],
        );
        cfg.req.insert(
            "allow_managed_hooks_only".into(),
            setting(json!(true), CxLayerId::MdmReq),
        );
        let f = run(&cfg);
        assert!(!f[0].in_effect && f[0].signals.is_empty());
    }

    #[test]
    fn features_hooks_false_blocks_unless_requirements_pin_on() {
        let hooks = json!({"hooks": {"Stop": [{"command": "/opt/acme/log.sh"}]}});
        let off = [("features", json!({"hooks": false}), CxLayerId::UserCfg)];
        let cfg = hooks_cfg(hooks.clone(), &off);
        assert!(!run(&cfg)[0].in_effect);
        let mut pinned = hooks_cfg(hooks, &off);
        pinned.req.insert(
            "features".into(),
            setting(json!({"hooks": true}), CxLayerId::MdmReq),
        );
        assert!(
            run(&pinned)
                .iter()
                .any(|f| f.in_effect && f.title.contains("log.sh"))
        );
    }

    /// A config with managed hooks from the given requirements layers.
    fn req_hooks_cfg(layers: &[(CxLayerId, Origin, Value)]) -> CxConfig {
        let ids: Vec<(CxLayerId, Origin)> = layers.iter().map(|(i, o, _)| (*i, *o)).collect();
        let mut cfg = with_cfg(&ids, &[]);
        cfg.req_hooks = layers.iter().map(|(i, _, v)| (*i, v.clone())).collect();
        cfg
    }

    fn acme_hooks() -> Value {
        json!({"managed_dir": "/opt/acme", "Stop": [{"hooks": [{"command": "/opt/acme/log.sh"}]}]})
    }

    #[test]
    fn managed_hooks_from_one_layer_are_not_be_and_cite_that_layer() {
        let cfg = req_hooks_cfg(&[(CxLayerId::SysReq, Origin::System, acme_hooks())]);
        let f = run(&cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].in_effect && !f[0].best_effort);
        assert_eq!(f[0].source.origin, Origin::System);
    }

    #[test]
    fn managed_hooks_from_two_layers_keep_provenance_and_are_be() {
        let cfg = req_hooks_cfg(&[
            (
                CxLayerId::MdmReq,
                Origin::Mdm,
                json!({"managed_dir": "/opt/acme"}),
            ),
            (CxLayerId::SysReq, Origin::System, acme_hooks()),
        ]);
        let f = run(&cfg);
        assert_eq!(f.len(), 1, "a layer with no events adds nothing");
        assert_eq!(f[0].source.origin, Origin::System);
        assert!(!f[0].best_effort);

        let other = json!({"PreToolUse": [{"command": "/opt/acme/other.sh"}]});
        let cfg = req_hooks_cfg(&[
            (CxLayerId::MdmReq, Origin::Mdm, other),
            (CxLayerId::SysReq, Origin::System, acme_hooks()),
        ]);
        let f = run(&cfg);
        assert_eq!(f.len(), 2);
        let origin = |t: &str| {
            f.iter()
                .find(|x| x.title.contains(t))
                .unwrap()
                .source
                .origin
        };
        assert_eq!(origin("other.sh"), Origin::Mdm);
        assert_eq!(origin("log.sh"), Origin::System);
        assert!(f.iter().all(|x| x.best_effort));
    }

    #[test]
    fn cloud_managed_hooks_are_be() {
        let cfg = req_hooks_cfg(&[(CxLayerId::CloudReq, Origin::Server, acme_hooks())]);
        assert!(run(&cfg)[0].best_effort);
    }

    #[test]
    fn managed_hooks_skip_managed_only_but_not_the_feature_gate() {
        let hook_in_effect = |cfg: &CxConfig| {
            run(cfg)
                .iter()
                .find(|f| f.title.contains("log.sh"))
                .unwrap()
                .in_effect
        };
        let layers = [(CxLayerId::SysReq, Origin::System, acme_hooks())];
        let only = |cfg: &mut CxConfig| {
            cfg.req.insert(
                "allow_managed_hooks_only".into(),
                setting(json!(true), CxLayerId::SysReq),
            );
        };
        let mut cfg = req_hooks_cfg(&layers);
        only(&mut cfg);
        assert!(
            hook_in_effect(&cfg),
            "managed-only never blocks managed hooks"
        );

        // requirements pin features.hooks = false
        let mut cfg = req_hooks_cfg(&layers);
        cfg.req.insert(
            "features".into(),
            setting(json!({"hooks": false}), CxLayerId::SysReq),
        );
        assert!(!hook_in_effect(&cfg));

        // local features.hooks = false, not pinned on
        let mut cfg = req_hooks_cfg(&layers);
        cfg.cfg.insert(
            "features".into(),
            setting(json!({"hooks": false}), CxLayerId::UserCfg),
        );
        assert!(!hook_in_effect(&cfg));

        // pinned on overrides the local setting
        cfg.req.insert(
            "features".into(),
            setting(json!({"hooks": true}), CxLayerId::SysReq),
        );
        assert!(hook_in_effect(&cfg));
    }

    #[test]
    fn hooks_in_config_layers_are_found() {
        let mut cfg = with_cfg(
            &[(CxLayerId::ManagedCfg, Origin::System)],
            &[(
                "hooks",
                json!({"PostToolUse": [{"command": ["/opt/acme/log.sh"]}]}),
                CxLayerId::ManagedCfg,
            )],
        );
        cfg.req.insert(
            "allow_managed_hooks_only".into(),
            setting(json!(true), CxLayerId::MdmReq),
        );
        let f = run(&cfg);
        let hook = f.iter().find(|x| x.title.contains("log.sh")).unwrap();
        assert!(hook.in_effect, "a managed layer's hook isn't blocked");
        assert_eq!(hook.signals, [Signal::Transcript, Signal::ToolDetails]);
    }

    #[test]
    fn plugin_hook_sources_follow_manifest_overrides_and_skip_unsafe_handlers() {
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex-plugin-hooks");
        let h = Harness::from_fixture(&dir).unwrap();
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        // 10.0.0 beats 9.0.0; `.tmp`, disabled plugins, and invalid hook paths are skipped.
        assert_eq!(cfg.plugin_hooks.len(), 5);
        let sources: Vec<&str> = cfg
            .plugin_hooks
            .iter()
            .map(|(loc, _)| loc.shown.as_str())
            .collect();
        assert!(
            sources
                .iter()
                .any(|p| { p.ends_with("acme-audit/10.0.0/.codex-plugin/plugin.json") })
        );
        assert!(
            sources
                .iter()
                .any(|p| p.ends_with("acme-default/1.0.0/hooks/hooks.json"))
        );
        assert!(
            sources
                .iter()
                .any(|p| p.ends_with("acme-path/1.0.0/custom/h.json"))
        );
        assert!(
            !sources
                .iter()
                .any(|p| p.contains("acme-path/1.0.0/hooks/hooks.json"))
        );
        assert!(!sources.iter().any(|p| p.contains("acme-escape")));

        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan_config(&mut ctx, &cfg);
        let f = ctx.finish().findings;
        assert_eq!(f.len(), 5);
        let audit = f
            .iter()
            .find(|finding| finding.title.contains("acme_collector.turn_ended"))
            .unwrap();
        assert_eq!(
            audit.title,
            "Codex hook calls MCP tool `acme_collector.turn_ended` on Stop, Interrupt"
        );
        assert_eq!(audit.signals, [Signal::Responses, Signal::Transcript]);
        assert!(audit.source.path.ends_with(".codex-plugin/plugin.json"));
        assert!(
            f.iter()
                .all(|finding| finding.in_effect && finding.best_effort)
        );
        assert!(f.iter().all(|finding| finding.detail == PLUGIN_HOOK_DETAIL));
        let titles = f
            .iter()
            .map(|finding| finding.title.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "default-hook.sh",
            "path-hook.sh",
            "array-stop.sh",
            "array-interrupt.sh",
        ] {
            assert!(
                titles.iter().any(|title| title.contains(expected)),
                "{expected}"
            );
        }
        for ignored in ["ignored-default.sh", "ignored-prompt.sh", "acme-escape"] {
            assert!(
                titles.iter().all(|title| !title.contains(ignored)),
                "{ignored}"
            );
        }
    }

    #[test]
    fn plugin_names_cannot_escape_the_cache() {
        assert!(path_segment("acme-audit") && !path_segment("..") && !path_segment("a/b"));
    }

    #[test]
    fn hooks_table_uses_nested_object_and_otherwise_the_value() {
        let wrapped = json!({"hooks": {"Stop": []}, "metadata": true});
        assert_eq!(hooks_table(&wrapped), &json!({"Stop": []}));
        let plain = json!({"Stop": []});
        assert_eq!(hooks_table(&plain), &plain);
        let non_object = json!({"hooks": false, "Stop": []});
        assert_eq!(hooks_table(&non_object), &non_object);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_manifest_symlink_outside_root_is_rejected() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cainary-codex-plugin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let plugin_dir =
            dir.join("home/.codex/plugins/cache/acme-market/acme-demo/1.0.0/.codex-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::create_dir_all(dir.join("root")).unwrap();
        std::fs::write(
            dir.join("fixture.json"),
            r#"{"os":"macos","tools":["codex"]}"#,
        )
        .unwrap();
        let outside_manifest = dir.join("home/.codex/outside-plugin.json");
        std::fs::write(&outside_manifest, br#"{"hooks":{"Stop":[]}}"#).unwrap();
        symlink(&outside_manifest, plugin_dir.join("plugin.json")).unwrap();

        let outside_version = dir.join("home/.codex/outside-plugin/1.0.0");
        let escaped_version = dir.join("home/.codex/plugins/cache/acme-market/acme-escape/1.0.0");
        std::fs::create_dir_all(outside_version.join(".codex-plugin")).unwrap();
        std::fs::write(
            outside_version.join(".codex-plugin/plugin.json"),
            br#"{"hooks":{"Stop":[]}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(escaped_version.parent().unwrap()).unwrap();
        symlink(&outside_version, &escaped_version).unwrap();

        let h = Harness::from_fixture(&dir).unwrap();
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let settings = json!({
            "acme-demo@acme-market": {"enabled": true},
            "acme-escape@acme-market": {"enabled": true}
        });
        let plugins = plugin_manifests(&mut ctx, &h.tool_home(ToolHome::CodexHome), &settings);
        assert!(plugins.is_empty());
        assert!(
            ctx.finish()
                .sources
                .iter()
                .all(|source| !source.source.path.contains("outside-plugin"))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plugin_mcp_servers_use_default_and_manifest_paths_and_honor_disables() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex-plugin-mcp");
        let h = Harness::from_fixture(&dir).unwrap();
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        let cfg = resolve(&mut ctx);
        assert_eq!(cfg.plugin_mcp_servers.len(), 2);
        scan_config(&mut ctx, &cfg);
        let findings = ctx.finish().findings;
        assert_eq!(findings.len(), 2);

        let local = findings
            .iter()
            .find(|finding| finding.title.contains("local-collector"))
            .unwrap();
        assert!(local.signals.is_empty());
        assert!(!local.best_effort);
        assert!(local.source.path.ends_with("acme-local/1.0.0/.mcp.json"));

        let remote = findings
            .iter()
            .find(|finding| finding.title.contains("mcp.example-corp.com"))
            .unwrap();
        assert_eq!(remote.signals, [Signal::ToolDetails]);
        assert!(remote.best_effort);
        assert!(
            remote
                .source
                .path
                .ends_with("acme-remote/1.0.0/servers.json")
        );
        assert!(findings.iter().all(|finding| {
            !finding.title.contains("file-disabled") && !finding.title.contains("config-disabled")
        }));
    }

    #[test]
    fn plugin_mcp_tool_hooks_follow_the_same_gates_and_commands_still_work() {
        let table = json!({
            "Stop": [{"hooks": [
                {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"k": "v"}},
                {"type": "command", "command": "/opt/acme/log.sh"}
            ]}],
            "Interrupt": [{"hooks": [{"type": "mcp_tool", "server": "s", "tool": "t"}]}]
        });
        let mut cfg = with_cfg(&[(CxLayerId::UserCfg, Origin::User)], &[]);
        cfg.plugin_hooks = vec![(
            Loc::test("~/.codex/plugins/cache/m/p/1/.codex-plugin/plugin.json"),
            table,
        )];
        let f = run(&cfg);
        assert_eq!(f.len(), 2);
        let tool = f.iter().find(|x| x.title.contains("`s.t`")).unwrap();
        assert!(tool.in_effect && tool.best_effort);
        assert!(f.iter().any(|x| x.title.contains("log.sh")));

        // plugin hooks aren't managed: allow_managed_hooks_only blocks them
        cfg.req.insert(
            "allow_managed_hooks_only".into(),
            setting(json!(true), CxLayerId::MdmReq),
        );
        assert!(run(&cfg).iter().all(|x| !x.in_effect));
        cfg.req.clear();
        cfg.cfg.insert(
            "features".into(),
            setting(json!({"hooks": false}), CxLayerId::UserCfg),
        );
        assert!(run(&cfg).iter().all(|x| !x.in_effect));
    }
}
