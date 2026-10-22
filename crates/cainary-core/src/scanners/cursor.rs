//! cursor scanner (rules.md §CU): hooks, CLI config, MDM, vendor default.

use crate::harness::platform::Os;
use crate::harness::{Loc, Probe, ScanCtx, Which};
use crate::model::{FindingBuilder, Origin, Signal, Source, SourceKind, Tool};
use crate::redact;
use crate::rules::hooks::{self, Cmd, Hit, Target};
use crate::rules::vendor;
use crate::value::{Format, Value};

const REF_HOOKS: &str = "https://cursor.com/docs/hooks";
const REF_DEPLOY: &str = "https://cursor.com/docs/enterprise/deployment-patterns";
const REF_CLI: &str = "https://cursor.com/docs/cli/reference/configuration";
const MDM_DOMAINS: [&str; 2] = [
    "com.todesktop.230313mzl4w4u92",
    "co.anysphere.cursor.nightly",
];
const MDM_POLICY_KEYS: [&str; 6] = [
    "AllowedTeamId",
    "AllowedExtensions",
    "ExtensionGalleryServiceUrl",
    "UpdateMode",
    "WorkspaceTrustEnabled",
    "NetworkDisableHttp2",
];

pub fn scan(ctx: &mut ScanCtx) {
    let installed = installed(ctx);
    if installed {
        ctx.installed();
    }

    let enterprise = match ctx.h().os {
        Os::Macos => ctx
            .h()
            .sys("/Library/Application Support/Cursor/hooks.json"),
        Os::Linux => ctx.h().sys("/etc/cursor/hooks.json"),
    };
    let mut rtk_telemetry = None;
    hooks_file(ctx, &enterprise, Origin::System, &mut rtk_telemetry);
    let user_hooks = ctx.h().home(".cursor/hooks.json");
    let origin = user_origin(ctx, &user_hooks);
    hooks_file(ctx, &user_hooks, origin, &mut rtk_telemetry);

    cli_config(ctx);
    mdm(ctx);

    if installed && let Some(b) = vendor::vendor_default(Tool::Cursor, false) {
        ctx.emit(b);
    }
}

fn installed(ctx: &ScanCtx) -> bool {
    let h = ctx.h();
    let mut markers = vec![h.app_support("Cursor")];
    if h.os == Os::Macos {
        markers.push(h.sys("/Applications/Cursor.app"));
        markers.push(h.home("Applications/Cursor.app"));
    }
    markers
        .iter()
        .any(|l| !matches!(ctx.probe(l), Probe::Missing | Probe::Failed))
        || (h.os == Os::Linux && matches!(h.which("cursor", None), Which::Found(_)))
}

/// A user-tier file owned by root is org-installed.
fn user_origin(ctx: &ScanCtx, loc: &Loc) -> Origin {
    if ctx.root_owned(loc) {
        Origin::OrgInstalled
    } else {
        Origin::User
    }
}

/// What a hook event sends to the hook command.
fn event_signals(event: &str) -> Vec<Signal> {
    let mut s = vec![Signal::Identity];
    if event != "workspaceOpen" {
        s.push(Signal::Transcript);
    }
    match event {
        "beforeSubmitPrompt" => s.push(Signal::Prompts),
        "beforeReadFile" | "beforeTabFileRead" | "afterFileEdit" | "afterTabFileEdit" => {
            s.push(Signal::FileContents)
        }
        "beforeShellExecution"
        | "afterShellExecution"
        | "beforeMCPExecution"
        | "afterMCPExecution"
        | "preToolUse"
        | "postToolUse"
        | "postToolUseFailure" => s.push(Signal::ToolDetails),
        "afterAgentResponse" | "afterAgentThought" => s.push(Signal::Responses),
        _ => {}
    }
    s
}

fn basename(s: &str) -> String {
    redact::text(s.rsplit('/').next().unwrap_or(s))
}

fn target_name(t: &Target) -> String {
    match t {
        Target::File(loc) => basename(&loc.shown),
        Target::Unresolved(s) => basename(s),
        Target::Inline { interpreter } => format!("an inline {}", basename(interpreter)),
    }
}

fn describe(s: Signal) -> &'static str {
    match s {
        Signal::Identity => "your email",
        Signal::Transcript => "the conversation transcript path",
        Signal::Prompts => "your prompts",
        Signal::FileContents => "file contents",
        Signal::ToolDetails => "tool calls",
        Signal::Responses => "the AI's replies",
        _ => "data",
    }
}

fn hooks_file(
    ctx: &mut ScanCtx,
    loc: &Loc,
    file_origin: Origin,
    rtk_telemetry: &mut Option<hooks::RtkTelemetry>,
) {
    let Some(doc) = ctx.read(loc, file_origin, Format::Jsonc) else {
        return;
    };
    let Some(events) = doc.get("hooks").and_then(Value::as_object) else {
        return;
    };
    let mut hits = Vec::new();
    let mut quiet = Vec::new();
    for (event, list) in events {
        for entry in list.as_array().into_iter().flatten() {
            if entry.get("type").and_then(Value::as_str) == Some("prompt") {
                continue;
            }
            let Some(command) = entry.get("command").and_then(Value::as_str) else {
                continue;
            };
            let cmd = Cmd::Shell(command.to_string());
            let target = hooks::target(&cmd, None, ctx);
            let hit = Hit {
                event: event.clone(),
                cmd: cmd.clone(),
                target,
                in_effect: true,
            };
            if hooks::is_local_notifier(&cmd, None, ctx) {
                quiet.push(hit);
            } else {
                hits.push(hit);
            }
        }
    }
    for (hits, notifier) in [(hits, false), (quiet, true)] {
        for g in hooks::group(hits, None, ctx) {
            let origin = hooks::origin(file_origin, &g.target, ctx);
            let name = target_name(&g.target);
            let rtk = g.known_local_tool_hook.then(|| {
                hooks::rtk_hook_finding(
                    hooks::rtk_telemetry(ctx, rtk_telemetry),
                    &g.events,
                    matches!(&g.target, Target::Unresolved(_)),
                )
            });
            let mut signals: Vec<Signal> = g.events.iter().flat_map(|e| event_signals(e)).collect();
            signals.sort();
            signals.dedup();
            let mut evidence = vec![format!("events = {}", g.events.join(", "))];
            evidence.extend(g.commands.iter().map(|c| format!("command = {c}")));
            let (title, detail, signals) = if notifier {
                (
                    format!("Cursor hook `{name}` plays a sound or shows a notification"),
                    "It runs on the events above and sends nothing off this Mac.".to_string(),
                    Vec::new(),
                )
            } else if let Some(rtk) = &rtk {
                evidence.push(rtk.evidence.clone());
                (
                    format!("Cursor hook `rtk` {}", rtk.title_suffix),
                    rtk.detail.clone(),
                    rtk.signals.clone(),
                )
            } else {
                let what: Vec<&str> = signals.iter().map(|s| describe(*s)).collect();
                let sends = g
                    .commands
                    .iter()
                    .find_map(|c| hooks::sends_to(&Cmd::Shell(c.clone())));
                let mut title = format!("Cursor hook `{name}` receives {}", what.join(", "));
                if let Some(host) = sends {
                    title.push_str(&format!(" and sends it to {host}"));
                }
                (
                    title,
                    "Cursor runs the command on these events and passes it this data.".to_string(),
                    signals,
                )
            };
            ctx.emit(
                FindingBuilder::new(title)
                    .detail(detail)
                    .signals(&signals)
                    .evidence(evidence)
                    .source(Source::new(loc.shown.clone(), origin, SourceKind::File))
                    .reference(REF_HOOKS)
                    .best_effort(rtk.as_ref().is_some_and(|finding| finding.best_effort)),
            );
        }
    }
}

fn cli_config(ctx: &mut ScanCtx) {
    let loc = ctx.h().home(".cursor/cli-config.json");
    let origin = user_origin(ctx, &loc);
    let Some(cfg) = ctx.read(&loc, origin, Format::Jsonc) else {
        return;
    };
    let mut evidence = Vec::new();
    for key in ["permissions.allow", "permissions.deny"] {
        if let Some(a) = crate::value::get(&cfg, key).and_then(Value::as_array) {
            evidence.push(format!("{key} = {} entries", a.len()));
        }
    }
    for key in ["approvalMode", "sandbox"] {
        if let Some(v) = cfg.get(key) {
            evidence.push(format!("{key} = {}", redact::value(key, v)));
        }
    }
    if evidence.is_empty() {
        return;
    }
    let policy = origin.is_org();
    ctx.emit(
        FindingBuilder::new(if policy {
            "Your organization sets Cursor CLI permissions"
        } else {
            "Cursor CLI permissions are configured"
        })
        .signals(if policy { &[Signal::Policy] } else { &[] })
        .evidence(evidence)
        .source(Source::new(loc.shown.clone(), origin, SourceKind::File))
        .reference(REF_CLI),
    );
}

fn mdm(ctx: &mut ScanCtx) {
    for domain in MDM_DOMAINS {
        for (loc, plist) in ctx.read_mdm(domain) {
            let Some(map) = plist.as_object() else {
                continue;
            };
            let source = Source::new(loc.shown.clone(), Origin::Mdm, SourceKind::File);
            let line = |k: &String, v: &Value| format!("{k} = {}", redact::value(k, v));
            let known: Vec<String> = map
                .iter()
                .filter(|(k, _)| MDM_POLICY_KEYS.contains(&k.as_str()))
                .map(|(k, v)| line(k, v))
                .collect();
            if !known.is_empty() {
                ctx.emit(
                    FindingBuilder::new("Your organization manages Cursor settings")
                        .signals(&[Signal::Policy])
                        .evidence(known)
                        .source(source.clone())
                        .reference(REF_DEPLOY),
                );
            }
            let other: Vec<String> = map
                .iter()
                .filter(|(k, _)| {
                    !MDM_POLICY_KEYS.contains(&k.as_str()) && !k.starts_with("Payload")
                })
                .map(|(k, v)| line(k, v))
                .collect();
            if !other.is_empty() {
                ctx.emit(
                    FindingBuilder::new(format!(
                        "Your organization sets {} other Cursor polic{}",
                        other.len(),
                        if other.len() == 1 { "y" } else { "ies" }
                    ))
                    .signals(&[Signal::Policy])
                    .best_effort(true)
                    .evidence(other)
                    .source(source)
                    .reference(REF_DEPLOY),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::model::{Level, Tool};
    use std::path::Path;

    fn fixture(name: &str) -> Harness {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resolve")
            .join(name);
        Harness::from_fixture(&dir).expect("fixture loads")
    }

    #[test]
    fn known_local_rtk_hook_is_low_when_telemetry_is_not_configured() {
        let h = fixture("rtk-telemetry-missing");
        let mut ctx = ScanCtx::new(&h, Tool::Cursor);
        scan(&mut ctx);
        let out = ctx.finish();
        let finding = out
            .findings
            .iter()
            .find(|f| f.title == "Cursor hook `rtk` runs on preToolUse")
            .expect("rtk hook finding");
        assert_eq!(finding.signals, [Signal::Usage]);
        assert_eq!(finding.level(), Level::Low);
        assert!(finding.detail.contains("local token reducer"));
        assert!(finding.evidence.iter().any(|line| {
            line == "rtk telemetry config = ~/Library/Application Support/rtk/config.toml"
        }));
    }
}
