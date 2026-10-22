//! claude_desktop scanner (rules.md §CD), macOS only: MDM keys, `claude_desktop_config.json`.

use crate::harness::platform::Os;
use crate::harness::{Loc, Probe, ScanCtx};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind, Tool};
use crate::redact;
use crate::rules::hooks::{self, Cmd};
use crate::rules::{mcp, vendor};
use crate::value::{self, Format, Value};

const DOMAIN: &str = "com.anthropic.claudefordesktop";
const REF_CONFIG: &str = "https://claude.com/docs/third-party/claude-desktop/configuration";
const REF_MDM: &str = "https://claude.com/docs/third-party/claude-desktop/mdm";
const REF_TELEMETRY: &str = "https://claude.com/docs/third-party/claude-desktop/telemetry";

/// Keys this scanner reads; every other MDM key is listed by name only.
const KNOWN: &[&str] = &[
    "otlpEndpoint",
    "otlpContentCapture",
    "otlpAuthMode",
    "otlpResourceAttributes",
    "endUserAttribution",
    "inferenceGatewayBaseUrl",
    "inferenceProvider",
    "egressProxyPacUrl",
    "egressProxyUrl",
    "managedMcpServers",
    "organizationInstructions",
    "forceLoginOrgUUID",
    "isClaudeCodeForDesktopEnabled",
    "chatTabEnabled",
    "disableBypassPermissionsMode",
    "blockReadsOutsideWorkingDirectories",
    "allowedWorkspaceFolders",
    "disableAutoUpdates",
    "isDesktopExtensionEnabled",
    "isLocalDevMcpEnabled",
    "disabledBuiltinTools",
    "disableEssentialTelemetry",
    "disableNonessentialTelemetry",
];

/// A policy key and the value that counts as set (`None`: any non-empty value).
type Rule = (&'static str, Option<bool>);

/// One effective MDM key and the plist it came from.
struct Key {
    name: String,
    value: Value,
    loc: Loc,
}

fn set(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

/// A boolean key, tolerating `"true"`/`"false"` strings.
fn flag(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_f64().map(|n| n != 0.0),
        Value::String(_) if value::truthy(v) => Some(true),
        Value::String(s)
            if ["0", "false", "no", "off"].contains(&s.trim().to_lowercase().as_str()) =>
        {
            Some(false)
        }
        _ => None,
    }
}

fn mdm_source(k: &Key) -> Source {
    Source::new(k.loc.shown.clone(), Origin::Mdm, SourceKind::File)
}

fn host_of(s: &str) -> String {
    redact::url_host(s).unwrap_or_else(|| "a remote host".to_string())
}

pub fn scan(ctx: &mut ScanCtx) {
    if ctx.h().os != Os::Macos {
        return;
    }
    let installed = [
        ctx.h().sys("/Applications/Claude.app"),
        ctx.h().home("Applications/Claude.app"),
    ]
    .iter()
    .any(|l| ctx.probe(l) != Probe::Missing && ctx.probe(l) != Probe::Failed);
    if installed {
        ctx.installed();
    }

    let keys = mdm_keys(ctx);
    let find = |name: &str| keys.iter().find(|k| k.name == name);
    let third_party = find("inferenceProvider").is_some_and(|k| set(&k.value));
    telemetry(ctx, &keys, third_party);
    routing(ctx, &keys);
    policy(ctx, &keys);
    other_keys(ctx, &keys);
    user_config(ctx);

    let off = |n: &str| find(n).and_then(|k| flag(&k.value)) == Some(true);
    if installed
        && !(off("disableEssentialTelemetry") && off("disableNonessentialTelemetry"))
        && let Some(b) = vendor::vendor_default(Tool::ClaudeDesktop, false)
    {
        ctx.emit(b.best_effort(!third_party));
    }
}

/// Per-user plist first; a device key shadowed by a per-user one is reported as not in effect.
fn mdm_keys(ctx: &mut ScanCtx) -> Vec<Key> {
    let mut keys: Vec<Key> = Vec::new();
    let mut shadowed: Vec<Key> = Vec::new();
    for (loc, v) in ctx.read_mdm(DOMAIN) {
        let Some(map) = v.as_object() else { continue };
        for (name, value) in map {
            let k = Key {
                name: name.clone(),
                value: value.clone(),
                loc: loc.clone(),
            };
            if keys.iter().any(|e| e.name == *name) {
                shadowed.push(k);
            } else {
                keys.push(k);
            }
        }
    }
    for k in shadowed {
        ctx.emit(
            FindingBuilder::new(format!(
                "`{}` in the device profile is overridden by the per-user profile",
                redact::text(&k.name)
            ))
            .in_effect(false)
            .source(mdm_source(&k))
            .reference(REF_MDM),
        );
    }
    keys
}

/// `otlpContentCapture` as a list of strings (a JSON-array string was decoded by `read_mdm`).
fn capture_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn telemetry(ctx: &mut ScanCtx, keys: &[Key], third_party: bool) {
    let find = |name: &str| keys.iter().find(|k| k.name == name);
    let endpoint = find("otlpEndpoint").filter(|k| set(&k.value));
    let host = endpoint
        .and_then(|k| k.value.as_str())
        .map(host_of)
        .unwrap_or_default();
    let otlp_keys: Vec<&Key> = keys
        .iter()
        .filter(|k| k.name.starts_with("otlp") || k.name == "endUserAttribution")
        .collect();

    if let Some(k) = endpoint {
        let mut evidence = vec![format!(
            "otlpEndpoint = {}",
            redact::url(k.value.as_str().unwrap_or_default())
        )];
        for name in ["endUserAttribution", "otlpAuthMode"] {
            if let Some(o) = find(name) {
                evidence.push(format!("{name} = {}", redact::value(name, &o.value)));
            }
        }
        if let Some(o) = find("otlpResourceAttributes") {
            for n in redact::header_names(&o.value) {
                evidence.push(format!("otlpResourceAttributes has {n}"));
            }
        }
        ctx.emit(
            FindingBuilder::new(format!("Claude Desktop sends usage telemetry to {host}"))
                .signals(&[Signal::Usage, Signal::Identity])
                .detail(
                    "The exported resource carries process.owner (your OS login). \
                     endUserAttribution = false removes only enduser.id, and \
                     otlpResourceAttributes can add more, so neither clears identity.",
                )
                .evidence(evidence)
                .source(mdm_source(k))
                .reference(REF_TELEMETRY),
        );
    } else if !third_party && let Some(k) = otlp_keys.first() {
        ctx.emit(
            FindingBuilder::new("Claude Desktop may send telemetry to a collector")
                .signals(&[Signal::Identity])
                .detail("OTLP keys are set but no endpoint; the collector may be set in the admin console.")
                .evidence(otlp_keys.iter().map(|k| format!("{} is set", k.name)))
                .best_effort(true)
                .source(mdm_source(k))
                .reference(REF_TELEMETRY),
        );
    }

    if let Some(k) = find("otlpContentCapture") {
        let list = capture_list(&k.value);
        let mut signals = Vec::new();
        for item in &list {
            match item.as_str() {
                "userPrompts" => signals.extend([Signal::Prompts, Signal::Responses]),
                "assistantResponses" => signals.push(Signal::Responses),
                "toolDetails" => signals.push(Signal::ToolDetails),
                "toolContent" => signals.push(Signal::FileContents),
                "rawApiBodies" => signals.extend([
                    Signal::Prompts,
                    Signal::Responses,
                    Signal::ToolDetails,
                    Signal::FileContents,
                ]),
                _ => {}
            }
        }
        // Only a collector (set here or in the admin console on 1P) receives the content.
        let sends = endpoint.is_some() || !third_party;
        let words: Vec<&str> = list
            .iter()
            .map(|i| match i.as_str() {
                "userPrompts" => "your prompts and the replies",
                "assistantResponses" => "the replies",
                "toolDetails" => "tool input",
                "toolContent" => "tool output",
                "rawApiBodies" => "raw API requests and responses",
                other => other,
            })
            .collect();
        let title = if list.is_empty() {
            "Claude Desktop telemetry content capture is empty".to_string()
        } else if endpoint.is_some() {
            format!("Claude Desktop sends {} to {host}", words.join(", "))
        } else {
            format!(
                "Claude Desktop may send {} to a collector",
                words.join(", ")
            )
        };
        let mut b = FindingBuilder::new(title)
            .evidence([format!("otlpContentCapture = {}", list.join(", "))])
            .source(mdm_source(k))
            .reference(REF_TELEMETRY);
        if sends && !list.is_empty() {
            b = b.signals(&signals).best_effort(endpoint.is_none());
        }
        ctx.emit(b);
    }

    if find("otlpAuthMode").and_then(|k| k.value.as_str()) == Some("inference-credential")
        && let Some(k) = find("otlpAuthMode")
    {
        ctx.emit(
            FindingBuilder::new("The telemetry collector receives your sign-in token")
                .signals(&[Signal::Identity])
                .best_effort(endpoint.is_none())
                .evidence(["otlpAuthMode = inference-credential"])
                .source(mdm_source(k))
                .reference(REF_TELEMETRY),
        );
    }
}

fn routing(ctx: &mut ScanCtx, keys: &[Key]) {
    let find = |name: &str| {
        keys.iter()
            .find(|k| k.name == name)
            .filter(|k| set(&k.value))
    };
    if let Some(k) = find("inferenceGatewayBaseUrl") {
        let url = k.value.as_str().unwrap_or_default();
        ctx.emit(
            FindingBuilder::new(format!("Model requests go through {}", host_of(url)))
                .signals(&[Signal::Traffic])
                .evidence([format!("inferenceGatewayBaseUrl = {}", redact::url(url))])
                .source(mdm_source(k))
                .reference(REF_MDM),
        );
    } else if let Some(k) = find("inferenceProvider") {
        let p = k.value.as_str().unwrap_or("a third-party provider");
        ctx.emit(
            FindingBuilder::new(format!("Model requests go to {p} instead of Anthropic"))
                .signals(&[Signal::Traffic])
                .evidence([format!("inferenceProvider = {p}")])
                .source(mdm_source(k))
                .reference(REF_MDM),
        );
    }
    for name in ["egressProxyPacUrl", "egressProxyUrl"] {
        if let Some(k) = find(name) {
            let url = k.value.as_str().unwrap_or_default();
            ctx.emit(
                FindingBuilder::new(format!(
                    "Claude Desktop traffic goes through a proxy at {}",
                    host_of(url)
                ))
                .signals(&[Signal::Traffic])
                .evidence([format!("{name} = {}", redact::url(url))])
                .source(mdm_source(k))
                .reference(REF_MDM),
            );
        }
    }
    if let Some(k) = find("managedMcpServers") {
        // An array of `{name, …}` entries or a `name → entry` object.
        let entries: Vec<(String, &Value)> = match &k.value {
            Value::Array(a) => a
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let name = e.get("name").and_then(Value::as_str);
                    (
                        name.map_or_else(|| format!("#{}", i + 1), str::to_string),
                        e,
                    )
                })
                .collect(),
            Value::Object(m) => m.iter().map(|(n, e)| (n.clone(), e)).collect(),
            _ => Vec::new(),
        };
        ctx.emit(
            FindingBuilder::new(format!(
                "Your organization added {} MCP servers",
                entries.len()
            ))
            .signals(&[Signal::ToolDetails])
            .evidence(entries.iter().map(|(n, _)| format!("server = {n}")))
            .source(mdm_source(k))
            .reference(REF_MDM),
        );
        for (name, entry) in entries {
            let remote = ["url", "http_url", "serverUrl"]
                .iter()
                .any(|u| entry.get(u).is_some());
            if remote {
                let b = mcp::server(&name, entry, Origin::Mdm, ctx);
                ctx.emit(b.source(mdm_source(k)).reference(REF_MDM));
            }
        }
    }
}

fn policy(ctx: &mut ScanCtx, keys: &[Key]) {
    let find = |name: &str| keys.iter().find(|k| k.name == name);
    if let Some(k) = find("organizationInstructions").filter(|k| set(&k.value)) {
        let n = k.value.as_str().map_or(0, |s| s.chars().count());
        ctx.emit(
            FindingBuilder::new(format!(
                "Your organization sets instructions for Claude ({n} characters)"
            ))
            .signals(&[Signal::Policy])
            .evidence([format!("organizationInstructions length = {n}")])
            .source(mdm_source(k))
            .reference(REF_MDM),
        );
    }
    // (finding title, [(key, value that counts as set)]); `None` means "present".
    let groups: [(&str, &[Rule]); 4] = [
        (
            "Your organization restricts sign-in",
            &[("forceLoginOrgUUID", None)],
        ),
        (
            "Your organization restricts Claude Desktop features",
            &[
                ("isClaudeCodeForDesktopEnabled", Some(false)),
                ("chatTabEnabled", Some(false)),
                ("disableBypassPermissionsMode", Some(true)),
                ("blockReadsOutsideWorkingDirectories", Some(true)),
                ("allowedWorkspaceFolders", None),
                ("disableAutoUpdates", Some(true)),
            ],
        ),
        (
            "Your organization restricts extensions and tools",
            &[
                ("isDesktopExtensionEnabled", Some(false)),
                ("isLocalDevMcpEnabled", Some(false)),
                ("disabledBuiltinTools", None),
            ],
        ),
        (
            "Your organization turns off Anthropic telemetry",
            &[
                ("disableEssentialTelemetry", Some(true)),
                ("disableNonessentialTelemetry", Some(true)),
            ],
        ),
    ];
    for (title, rules) in groups {
        let hits: Vec<&Key> = rules
            .iter()
            .filter_map(|(name, want)| {
                let k = find(name)?;
                match want {
                    None => set(&k.value).then_some(k),
                    Some(w) => (flag(&k.value) == Some(*w)).then_some(k),
                }
            })
            .collect();
        if let Some(first) = hits.first() {
            ctx.emit(
                FindingBuilder::new(title)
                    .signals(&[Signal::Policy])
                    .evidence(
                        hits.iter()
                            .map(|k| format!("{} = {}", k.name, redact::value(&k.name, &k.value))),
                    )
                    .source(mdm_source(first))
                    .reference(REF_MDM),
            );
        }
    }
}

fn other_keys(ctx: &mut ScanCtx, keys: &[Key]) {
    let others: Vec<&Key> = keys
        .iter()
        .filter(|k| !KNOWN.contains(&k.name.as_str()))
        .collect();
    if let Some(first) = others.first() {
        ctx.emit(
            FindingBuilder::new(format!(
                "Your organization sets {} other Claude Desktop setting{}",
                others.len(),
                if others.len() == 1 { "" } else { "s" }
            ))
            .evidence(others.iter().map(|k| format!("key = {}", k.name)))
            .source(mdm_source(first))
            .reference(REF_MDM),
        );
    }
}

fn user_config(ctx: &mut ScanCtx) {
    let loc = ctx
        .h()
        .app_support("Claude")
        .join("claude_desktop_config.json");
    let Some(cfg) = ctx.read(&loc, Origin::User, Format::Json) else {
        return;
    };
    let Some(servers) = cfg.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, entry) in servers {
        // H.3: a local server whose command is an org-installed binary has an org origin.
        let mut origin = Origin::User;
        if let Some(command) = entry.get("command").and_then(Value::as_str) {
            let mut argv = vec![command.to_string()];
            if let Some(args) = entry.get("args").and_then(Value::as_array) {
                argv.extend(args.iter().filter_map(Value::as_str).map(str::to_string));
            }
            let path = entry
                .get("env")
                .and_then(|e| e.get("PATH"))
                .and_then(Value::as_str);
            let target = hooks::target(&Cmd::Argv(argv), path, ctx);
            origin = hooks::origin(Origin::User, &target, ctx);
        }
        let b = mcp::server(name, entry, Origin::User, ctx);
        ctx.emit(
            b.source(Source::new(loc.shown.clone(), origin, SourceKind::File))
                .reference(REF_CONFIG),
        );
    }
}
