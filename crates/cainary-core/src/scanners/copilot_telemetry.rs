//! Copilot OTel resolution per surface (rules.md §CP.2, CP.3).

use super::copilot::{CpConfig, MANAGED_REF, Surface, file_source, policy_origin, user_origin};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Signal, Source};
use crate::redact;
use crate::value::{self, Value};
use serde_json::Map;

const VSC_REF: &str = "https://code.visualstudio.com/docs/agents/guides/monitoring-agents";

/// The five content classes and what each exposes.
const CLASSES: [(&str, Signal); 5] = [
    ("prompts", Signal::Prompts),
    ("responses", Signal::Responses),
    ("toolArguments", Signal::ToolDetails),
    ("toolOutput", Signal::FileContents),
    ("policyDetail", Signal::ToolDetails),
];

/// A telemetry-shaped object (the managed `telemetry` fields) and where it came from.
struct Layer {
    v: Value,
    src: Source,
}

/// What one surface honors and the layers that feed it.
struct View {
    name: &'static str,
    reference: &'static str,
    /// Layers above the managed object (VS Code env beats managed values).
    pre: Vec<Layer>,
    /// Local layers below it, highest first.
    post: Vec<Layer>,
    /// Honors `capture.<class>`, not only the legacy `captureContent`.
    per_class: bool,
    identity: bool,
}

struct Outcome {
    host: String,
    source: Source,
    evidence: Vec<String>,
    sure: Vec<Signal>,
    maybe: Vec<Signal>,
}

enum Export {
    Off,
    LocalOnly(Source),
    Active(Outcome),
}

fn flag(v: &Value, path: &str) -> Option<bool> {
    match value::get(v, path)? {
        Value::Bool(b) => Some(*b),
        x @ (Value::String(_) | Value::Number(_)) => Some(value::truthy(x)),
        _ => None,
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// The first layer, in order, that sets `key`.
fn field<'a>(layers: &[&'a Layer], key: &str) -> Option<(&'a Value, &'a Layer)> {
    layers.iter().find_map(|l| {
        value::get(&l.v, key)
            .filter(|v| !is_empty(v))
            .map(|v| (v, *l))
    })
}

/// CP.2 `capture(class)`: the first of managed per-class, managed `captureContent`, the lock,
/// then the local value. The bool says it relied on env beating a managed object.
fn capture(v: &View, managed: Option<&Layer>, class: &str) -> (bool, bool) {
    for l in &v.pre {
        if let Some(b) = flag(&l.v, "captureContent") {
            return (b, managed.is_some());
        }
    }
    if let Some(m) = managed {
        if v.per_class
            && let Some(b) = flag(&m.v, &format!("capture.{class}"))
        {
            return (b, false);
        }
        if let Some(b) = flag(&m.v, "captureContent") {
            return (b, false);
        }
        if flag(&m.v, "lockCaptureContent") == Some(true) {
            return (false, false);
        }
    }
    for l in &v.post {
        if v.per_class
            && let Some(b) = flag(&l.v, &format!("capture.{class}"))
        {
            return (b, false);
        }
        if let Some(b) = flag(&l.v, "captureContent") {
            return (b, false);
        }
    }
    (false, false)
}

/// `identity` uses managed, then local, only.
fn identity(v: &View, managed: Option<&Layer>) -> bool {
    managed
        .into_iter()
        .chain(&v.post)
        .find_map(|l| flag(&l.v, "capture.identity"))
        .unwrap_or(false)
}

fn analyse(v: &View, managed: Option<&Layer>) -> Export {
    let all: Vec<&Layer> = v.pre.iter().chain(managed).chain(&v.post).collect();
    let no_env: Vec<&Layer> = managed.into_iter().chain(&v.post).collect();
    let enabled = field(&all, "enabled").is_some_and(|(x, _)| value::truthy(x));
    if !enabled {
        return Export::Off;
    }
    let endpoint = field(&all, "endpoint");
    let kind = ["exporterType", "protocol"]
        .iter()
        .find_map(|k| field(&all, k))
        .and_then(|(x, _)| x.as_str().map(str::to_ascii_lowercase));
    let local = matches!(kind.as_deref(), Some("file" | "console"))
        || (endpoint.is_none() && field(&all, "outfile").is_some());
    let Some((ep, ep_layer)) = endpoint else {
        return if local {
            Export::LocalOnly(
                field(&all, "outfile")
                    .map_or_else(|| file_source_of(managed, v), |(_, l)| l.src.clone()),
            )
        } else {
            Export::Off
        };
    };
    if local {
        return Export::LocalOnly(ep_layer.src.clone());
    }
    let url = ep.as_str().unwrap_or_default();
    let host = redact::url_host(url).unwrap_or_else(|| "your collector".to_string());

    let mut sure = vec![Signal::Usage];
    let mut maybe = Vec::new();
    let headers = field(&no_env, "headers");
    let has_ident = v.identity
        && (identity(v, managed)
            || headers.is_some()
            || field(&no_env, "headersProvider").is_some()
            || field(&no_env, "resourceAttributes").is_some());
    if has_ident {
        sure.push(Signal::Identity);
    }
    let mut env_beat = false;
    for (class, sig) in CLASSES {
        let (on, via_env) = capture(v, managed, class);
        env_beat |= on && via_env;
        if on {
            // `policyDetail` is not documented as tool-details.
            if class == "policyDetail" {
                maybe.push(sig);
            } else {
                sure.push(sig);
            }
        }
    }
    // An endpoint that env supplied over a managed one relies on env winning.
    let env_endpoint = v.pre.iter().any(|l| std::ptr::eq(l, ep_layer))
        && managed.is_some_and(|m| value::get(&m.v, "endpoint").is_some());
    if env_beat || env_endpoint {
        maybe.append(&mut sure);
    }

    let mut evidence = vec![format!("endpoint = {}", redact::url(url))];
    if let Some((p, _)) = field(&all, "protocol") {
        evidence.push(format!("protocol = {}", redact::value("protocol", p)));
    }
    if let Some((h, _)) = headers {
        evidence.push(format!("headers = {}", redact::value("headers", h)));
    }
    let captured: Vec<&str> = CLASSES
        .iter()
        .map(|(c, _)| *c)
        .filter(|c| capture(v, managed, c).0)
        .collect();
    if !captured.is_empty() {
        evidence.push(format!("captures = {}", captured.join(", ")));
    }
    if managed.is_some_and(|m| flag(&m.v, "lockCaptureContent") == Some(true)) {
        evidence.push("lockCaptureContent = true".to_string());
    }
    Export::Active(Outcome {
        host,
        source: ep_layer.src.clone(),
        evidence,
        sure,
        maybe,
    })
}

/// A source for a local-only export that has no layer of its own.
fn file_source_of(managed: Option<&Layer>, v: &View) -> Source {
    managed
        .or(v.post.first())
        .or(v.pre.first())
        .map(|l| l.src.clone())
        .expect("a view with an enabled export has a layer")
}

fn what(signals: &[Signal]) -> String {
    let mut words: Vec<&str> = signals
        .iter()
        .map(|s| match s {
            Signal::Prompts => "your prompts",
            Signal::Responses => "model responses",
            Signal::ToolDetails => "tool arguments",
            Signal::FileContents => "tool output",
            Signal::Identity => "your identity",
            _ => "usage data",
        })
        .collect();
    words.dedup();
    match words.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((last, _)) => last.to_string(),
        None => String::new(),
    }
}

fn emit_outcome(ctx: &mut ScanCtx, name: &str, reference: &str, o: &Outcome) {
    for (signals, be) in [(&o.sure, false), (&o.maybe, true)] {
        if signals.is_empty() {
            continue;
        }
        emit_one(ctx, name, reference, o, signals, be);
    }
}

fn emit_one(
    ctx: &mut ScanCtx,
    name: &str,
    reference: &str,
    o: &Outcome,
    signals: &[Signal],
    be: bool,
) {
    ctx.emit(
        FindingBuilder::new(format!("{name} sends {} to {}", what(signals), o.host))
            .signals(signals)
            .detail(
                "Telemetry export is on. cAInary can't see which Copilot surface you use, \
                 so it reports each installed one.",
            )
            .source(o.source.clone())
            .evidence(o.evidence.clone())
            .reference(reference)
            .best_effort(be),
    );
}

fn emit_local_only(ctx: &mut ScanCtx, name: &str, reference: &str, src: Source) {
    ctx.emit(
        FindingBuilder::new(format!("{name} telemetry is written locally only"))
            .detail(
                "The exporter writes to a local file or the console, so nothing leaves this Mac.",
            )
            .source(src)
            .reference(reference),
    );
}

/// `a.b` → `{a: {b: v}}` inside `m`.
fn set(m: &mut Map<String, Value>, path: &str, v: Value) {
    match path.split_once('.') {
        Some((head, rest)) => {
            let slot = m
                .entry(head.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(inner) = slot {
                set(inner, rest, v);
            }
        }
        None => {
            m.insert(path.to_string(), v);
        }
    }
}

/// The `COPILOT_OTEL_*` env layer (VS Code also reads the generic OTLP endpoint).
fn env_layer(ctx: &ScanCtx, vscode: bool) -> Option<Layer> {
    let h = ctx.h();
    let mut m = Map::new();
    let mut first = None;
    let mut ep_var = None;
    let mut take = |m: &mut Map<String, Value>, var: &'static str, key: &str| {
        if let Some(v) = h.env(var) {
            set(m, key, Value::String(v.to_string()));
            first.get_or_insert(var);
            if key == "endpoint" {
                ep_var.get_or_insert(var);
            }
        }
    };
    take(&mut m, "COPILOT_OTEL_ENABLED", "enabled");
    take(&mut m, "COPILOT_OTEL_ENDPOINT", "endpoint");
    if vscode {
        take(&mut m, "OTEL_EXPORTER_OTLP_ENDPOINT", "endpoint");
    }
    take(&mut m, "COPILOT_OTEL_PROTOCOL", "protocol");
    take(&mut m, "COPILOT_OTEL_EXPORTER_TYPE", "exporterType");
    take(&mut m, "COPILOT_OTEL_FILE_EXPORTER_PATH", "outfile");
    take(&mut m, "COPILOT_OTEL_CAPTURE_CONTENT", "captureContent");
    take(&mut m, "COPILOT_OTEL_HEADERS", "headers");
    take(&mut m, "COPILOT_OTEL_SERVICE_NAME", "serviceName");
    take(
        &mut m,
        "COPILOT_OTEL_RESOURCE_ATTRIBUTES",
        "resourceAttributes",
    );
    let var = ep_var.or(first)?;
    Some(Layer {
        v: Value::Object(m),
        src: ctx.env_source(var),
    })
}

fn cli_layer(cfg: &CpConfig, ctx: &ScanCtx) -> Option<Layer> {
    let (loc, m) = cfg.cli_settings.as_ref()?;
    let t = m.get("telemetry").filter(|t| t.is_object())?;
    Some(Layer {
        v: t.clone(),
        src: file_source(loc, user_origin(ctx, loc)),
    })
}

/// `CopilotOtel*` policies, then `github.copilot.chat.otel.*` user settings.
fn vscode_layers(cfg: &CpConfig, ctx: &ScanCtx) -> Vec<Layer> {
    const POLICY: [(&str, &str); 10] = [
        ("CopilotOtelEnabled", "enabled"),
        ("CopilotOtelEndpoint", "endpoint"),
        ("CopilotOtelExporterType", "exporterType"),
        ("CopilotOtelProtocol", "protocol"),
        ("CopilotOtelHeaders", "headers"),
        ("CopilotOtelOutfile", "outfile"),
        ("CopilotOtelResourceAttributes", "resourceAttributes"),
        ("CopilotOtelServiceName", "serviceName"),
        ("CopilotOtelCaptureContent", "captureContent"),
        ("CopilotOtelCaptureIdentity", "capture.identity"),
    ];
    const SETTING: [(&str, &str); 6] = [
        ("github.copilot.chat.otel.enabled", "enabled"),
        ("github.copilot.chat.otel.otlpEndpoint", "endpoint"),
        ("github.copilot.chat.otel.exporterType", "exporterType"),
        ("github.copilot.chat.otel.otlpProtocol", "protocol"),
        ("github.copilot.chat.otel.captureContent", "captureContent"),
        ("github.copilot.chat.otel.outfile", "outfile"),
    ];
    let mut out = Vec::new();
    let mut policy = Map::new();
    let mut src = None;
    for (loc, m) in &cfg.vscode_policy {
        for (k, to) in POLICY {
            if let Some(v) = m.get(k)
                && value::get(&Value::Object(policy.clone()), to).is_none()
            {
                set(&mut policy, to, v.clone());
                src.get_or_insert_with(|| file_source(loc, policy_origin(loc)));
            }
        }
    }
    if let Some(src) = src {
        out.push(Layer {
            v: Value::Object(policy),
            src,
        });
    }
    if let Some((loc, m)) = &cfg.vscode_user {
        let mut user = Map::new();
        for (k, to) in SETTING {
            if let Some(v) = m.get(k) {
                set(&mut user, to, v.clone());
            }
        }
        if !user.is_empty() {
            out.push(Layer {
                v: Value::Object(user),
                src: file_source(loc, user_origin(ctx, loc)),
            });
        }
    }
    out
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CpConfig) {
    let managed = cfg.managed.as_ref().and_then(|m| {
        let t = m.value.get("telemetry").filter(|t| t.is_object())?;
        Some(Layer {
            v: t.clone(),
            src: file_source(&m.loc, m.origin),
        })
    });
    let managed = managed.as_ref();

    let cli = |ctx: &ScanCtx| View {
        name: "Copilot CLI",
        reference: MANAGED_REF,
        pre: Vec::new(),
        post: env_layer(ctx, false)
            .into_iter()
            .chain(cli_layer(cfg, ctx))
            .collect(),
        per_class: true,
        identity: true,
    };
    let chat = |ctx: &ScanCtx| View {
        name: "Copilot in VS Code",
        reference: VSC_REF,
        pre: env_layer(ctx, true).into_iter().collect(),
        post: vscode_layers(cfg, ctx),
        per_class: false,
        identity: true,
    };
    let agent = |ctx: &ScanCtx| View {
        name: "Copilot agent sessions in VS Code",
        reference: VSC_REF,
        pre: env_layer(ctx, false).into_iter().collect(),
        post: cli_layer(cfg, ctx).into_iter().collect(),
        per_class: true,
        identity: false,
    };

    // No surface marker, but managed telemetry: one finding with the union of classes, BE.
    if cfg.surfaces.is_empty() {
        if managed.is_none() {
            return;
        }
        let mut union: Option<Outcome> = None;
        for v in [cli(ctx), chat(ctx), agent(ctx)] {
            if let Export::Active(o) = analyse(&v, managed) {
                match &mut union {
                    None => union = Some(o),
                    Some(u) => {
                        u.sure.extend(o.sure);
                        u.maybe.extend(o.maybe);
                    }
                }
            }
        }
        if let Some(mut u) = union {
            u.maybe.append(&mut u.sure);
            emit_outcome(ctx, "Copilot", MANAGED_REF, &u);
        }
        return;
    }

    for s in &cfg.surfaces {
        match s {
            Surface::Cli => {
                let v = cli(ctx);
                emit_export(ctx, &v, analyse(&v, managed));
            }
            Surface::VsCode => {
                let v = chat(ctx);
                let local_chat = analyse(&v, managed);
                // Classes only the Agent Host honors are added best-effort.
                let a = agent(ctx);
                if let Export::Active(ao) = analyse(&a, managed) {
                    let known: Vec<Signal> = match &local_chat {
                        Export::Active(o) => o.sure.iter().chain(&o.maybe).copied().collect(),
                        _ => Vec::new(),
                    };
                    let extra: Vec<Signal> = ao
                        .sure
                        .iter()
                        .chain(&ao.maybe)
                        .filter(|s| !known.contains(s))
                        .copied()
                        .collect();
                    if !extra.is_empty() {
                        emit_one(ctx, a.name, a.reference, &ao, &extra, true);
                    }
                }
                if let Export::Active(o) = &local_chat
                    && ctx
                        .h()
                        .env("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT")
                        .is_some_and(|x| value::truthy(&Value::String(x.to_string())))
                {
                    let o = Outcome {
                        sure: vec![Signal::Prompts, Signal::Responses, Signal::ToolDetails],
                        maybe: Vec::new(),
                        source: ctx
                            .env_source("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"),
                        evidence: vec![
                            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = true".into(),
                        ],
                        host: o.host.clone(),
                    };
                    emit_outcome(ctx, v.name, v.reference, &o);
                }
                emit_export(ctx, &v, local_chat);
            }
        }
    }
}

fn emit_export(ctx: &mut ScanCtx, v: &View, e: Export) {
    match e {
        Export::Off => {}
        Export::LocalOnly(src) => emit_local_only(ctx, v.name, v.reference, src),
        Export::Active(o) => emit_outcome(ctx, v.name, v.reference, &o),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::platform::Os;
    use crate::harness::{Harness, Loc};
    use crate::model::{Finding, Origin, SourceKind, Tool};
    use crate::scanners::copilot::CpManaged;
    use serde_json::json;

    fn layer(v: Value) -> Layer {
        Layer {
            v,
            src: Source::new("x", Origin::System, SourceKind::File),
        }
    }

    fn view(per_class: bool, pre: Vec<Layer>, post: Vec<Layer>) -> View {
        View {
            name: "t",
            reference: "r",
            pre,
            post,
            per_class,
            identity: true,
        }
    }

    // CP.2 capture(class)

    #[test]
    fn explicit_managed_false_beats_capture_content_true() {
        let m = layer(json!({ "capture": { "prompts": false }, "captureContent": true }));
        let v = view(true, vec![], vec![]);
        assert_eq!(capture(&v, Some(&m), "prompts"), (false, false));
        assert_eq!(capture(&v, Some(&m), "responses"), (true, false));
    }

    #[test]
    fn lock_covers_content_but_not_identity() {
        let m = layer(json!({ "lockCaptureContent": true, "capture": { "identity": true } }));
        let local = layer(json!({ "captureContent": true, "capture": { "prompts": true } }));
        let v = view(true, vec![], vec![local]);
        assert_eq!(capture(&v, Some(&m), "prompts"), (false, false));
        assert!(identity(&v, Some(&m)));
    }

    #[test]
    fn local_layers_apply_without_managed_and_per_class_only_when_honored() {
        let local = layer(json!({ "capture": { "prompts": true } }));
        assert!(capture(&view(true, vec![], vec![local]), None, "prompts").0);
        let local = layer(json!({ "capture": { "prompts": true } }));
        assert!(!capture(&view(false, vec![], vec![local]), None, "prompts").0);
    }

    #[test]
    fn vscode_env_beats_managed_and_is_best_effort() {
        let m = layer(json!({ "captureContent": false, "lockCaptureContent": true }));
        let env = layer(json!({ "captureContent": "true" }));
        let v = view(false, vec![env], vec![]);
        assert_eq!(capture(&v, Some(&m), "prompts"), (true, true));
    }

    // CP.3 surfaces

    fn managed(telemetry: Value) -> CpManaged {
        CpManaged {
            loc: Loc::test("/etc/github-copilot/managed-settings.json"),
            origin: Origin::System,
            value: json!({ "telemetry": telemetry })
                .as_object()
                .unwrap()
                .clone(),
        }
    }

    fn scan_with(cfg: &CpConfig, env: &[(&str, &str)]) -> Vec<Finding> {
        let h = Harness::test(Os::Macos, env);
        let mut ctx = ScanCtx::new(&h, Tool::Copilot);
        scan(&mut ctx, cfg);
        ctx.finish().findings
    }

    fn active() -> Value {
        json!({ "enabled": true, "endpoint": "https://otel.example-corp.com",
                "capture": { "prompts": true } })
    }

    #[test]
    fn each_installed_surface_gets_its_own_finding() {
        let cfg = CpConfig {
            surfaces: vec![Surface::Cli, Surface::VsCode],
            managed: Some(managed(active())),
            ..CpConfig::default()
        };
        let f = scan_with(&cfg, &[]);
        let cli = f.iter().find(|f| f.title.contains("Copilot CLI")).unwrap();
        assert!(cli.signals.contains(&Signal::Prompts));
        assert!(!cli.best_effort);
        let chat = f
            .iter()
            .find(|f| f.title.contains("Copilot in VS Code"))
            .unwrap();
        assert!(
            !chat.signals.contains(&Signal::Prompts),
            "chat has no per-class"
        );
        assert!(
            f.iter()
                .any(|f| f.title.contains("agent sessions") && f.best_effort)
        );
    }

    #[test]
    fn no_surface_with_managed_telemetry_is_one_best_effort_union() {
        let cfg = CpConfig {
            managed: Some(managed(active())),
            ..CpConfig::default()
        };
        let f = scan_with(&cfg, &[]);
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("Copilot"));
        assert!(f[0].best_effort);
        assert!(f[0].signals.contains(&Signal::Prompts));
    }

    #[test]
    fn disabled_or_endpointless_export_emits_nothing_and_file_export_is_local() {
        let mut cfg = CpConfig {
            surfaces: vec![Surface::Cli],
            managed: Some(managed(
                json!({ "enabled": false, "endpoint": "https://o.example-corp.com" }),
            )),
            ..CpConfig::default()
        };
        assert!(scan_with(&cfg, &[]).is_empty());
        cfg.managed = Some(managed(
            json!({ "enabled": true, "exporterType": "file", "outfile": "/tmp/o" }),
        ));
        let f = scan_with(&cfg, &[]);
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && f[0].in_effect);
    }

    #[test]
    fn vscode_env_capture_content_moves_findings_to_best_effort() {
        let cfg = CpConfig {
            surfaces: vec![Surface::VsCode],
            managed: Some(managed(
                json!({ "enabled": true, "endpoint": "https://o.example-corp.com",
                "captureContent": false }),
            )),
            ..CpConfig::default()
        };
        let f = scan_with(&cfg, &[("COPILOT_OTEL_CAPTURE_CONTENT", "true")]);
        let chat = f
            .iter()
            .find(|f| f.title.contains("Copilot in VS Code"))
            .unwrap();
        assert!(chat.best_effort);
        assert!(chat.signals.contains(&Signal::Prompts));
    }

    #[test]
    fn genai_env_adds_a_content_finding_when_chat_export_is_active() {
        let cfg = CpConfig {
            surfaces: vec![Surface::VsCode],
            managed: Some(managed(
                json!({ "enabled": true, "endpoint": "https://o.example-corp.com" }),
            )),
            ..CpConfig::default()
        };
        let f = scan_with(
            &cfg,
            &[("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true")],
        );
        assert!(
            f.iter()
                .any(|f| f.signals == [Signal::Prompts, Signal::Responses, Signal::ToolDetails])
        );
        assert!(
            scan_with(&cfg, &[])
                .iter()
                .all(|f| !f.signals.contains(&Signal::Responses))
        );
    }
}
