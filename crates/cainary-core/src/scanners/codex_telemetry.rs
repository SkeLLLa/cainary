//! Codex otel exporters, prompt logging and vendor metrics (rules.md §CX.4, CX.5).

use super::codex::{self, CxConfig, CxLayerId, CxSetting, layer_source};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Payload, Signal, Source, Tool};
use crate::redact;
use crate::rules::otel_catalog::{self, Export, Vendor};
use crate::rules::otel_preview::{self, FlagInput};
use crate::rules::vendor;
use crate::value::Value;

const REF: &str = "https://learn.chatgpt.com/docs/config-file/config-reference";
const REQUIREMENTS_DETAIL: &str = "Your organization enforces this; Codex CLI before 0.166.0 ignores it and uses your config instead.";
const CLOUD_CACHE_DETAIL: &str =
    "The cloud cache's shape is undocumented, so cAInary can't confirm this setting.";
const PAYLOAD_FLAG_KEYS: [&str; 3] = [
    "otel.log_user_prompt",
    "otel.log_agent_responses",
    "otel.log_guardian_assessments",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exporter {
    None,
    Statsig,
    OtlpHttp { endpoint: Option<String> },
    OtlpGrpc { endpoint: Option<String> },
    Unknown(String),
}

/// The `otlp-*` table of an exporter setting, when it has one.
fn otlp_table(v: &Value) -> Option<&Value> {
    let map = v.as_object()?;
    let mut it = map.iter();
    match (it.next(), it.next()) {
        (Some((k, t)), None) if k == "otlp-http" || k == "otlp-grpc" => Some(t),
        _ => None,
    }
}

/// Classify one exporter setting (rules.md §CX.4).
pub fn exporter(v: &Value) -> Exporter {
    match v {
        Value::String(s) => match s.as_str() {
            "none" => Exporter::None,
            "statsig" => Exporter::Statsig,
            "otlp-http" => Exporter::OtlpHttp { endpoint: None },
            "otlp-grpc" => Exporter::OtlpGrpc { endpoint: None },
            other => Exporter::Unknown(other.to_string()),
        },
        Value::Object(map) => {
            let endpoint = otlp_table(v)
                .and_then(|t| t.get("endpoint"))
                .and_then(Value::as_str)
                .map(str::to_string);
            match map.keys().next().map(String::as_str) {
                Some("otlp-http") if otlp_table(v).is_some() => Exporter::OtlpHttp { endpoint },
                Some("otlp-grpc") if otlp_table(v).is_some() => Exporter::OtlpGrpc { endpoint },
                _ => Exporter::Unknown(format!(
                    "table with keys {}",
                    map.keys().cloned().collect::<Vec<_>>().join(", ")
                )),
            }
        }
        Value::Array(_) => Exporter::Unknown("array".to_string()),
        Value::Bool(_) => Exporter::Unknown("boolean".to_string()),
        Value::Number(_) => Exporter::Unknown("number".to_string()),
        Value::Null => Exporter::Unknown("null".to_string()),
    }
}

fn endpoint(e: &Exporter) -> Option<&Option<String>> {
    match e {
        Exporter::OtlpHttp { endpoint } | Exporter::OtlpGrpc { endpoint } => Some(endpoint),
        _ => None,
    }
}

fn setting<'a>(cfg: &'a CxConfig, key: &str) -> Option<&'a CxSetting> {
    cfg.otel.get(key).or_else(|| cfg.cfg.get(key))
}

fn requirements_layer(layer: CxLayerId) -> bool {
    matches!(
        layer,
        CxLayerId::MdmReq | CxLayerId::LegacyReq | CxLayerId::CloudReq | CxLayerId::SysReq
    )
}

fn cloud_layer(layer: CxLayerId) -> bool {
    matches!(layer, CxLayerId::CloudCfg | CxLayerId::CloudReq)
}

fn comes_from(cfg: &CxConfig, keys: &[&str], predicate: impl Fn(CxLayerId) -> bool) -> bool {
    keys.iter()
        .filter_map(|key| setting(cfg, key))
        .any(|setting| predicate(setting.layer))
}

fn finding_source(cfg: &CxConfig, fallback: CxLayerId, keys: &[&str]) -> Source {
    keys.iter()
        .filter_map(|key| setting(cfg, key))
        .find(|setting| requirements_layer(setting.layer))
        .map(|setting| layer_source(cfg, setting.layer))
        .unwrap_or_else(|| layer_source(cfg, fallback))
}

fn provenance_detail(detail: &str, requirements: bool, cloud: bool) -> String {
    let mut out = detail.to_string();
    if cloud {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(CLOUD_CACHE_DETAIL);
    }
    if requirements {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(REQUIREMENTS_DETAIL);
    }
    out
}

fn host(endpoint: &Option<String>) -> String {
    endpoint
        .as_deref()
        .and_then(redact::url_host)
        .unwrap_or_else(|| "a collector".to_string())
}

/// Evidence for an OTLP exporter: the endpoint, header names, and whether a client certificate is set.
fn otlp_evidence(setting: &Value, endpoint: &Option<String>) -> Vec<String> {
    let mut ev = Vec::new();
    if let Some(e) = endpoint {
        ev.push(format!("endpoint = {}", redact::url(e)));
    }
    if let Some(t) = otlp_table(setting) {
        let names = redact::header_names(t.get("headers").unwrap_or(&Value::Null));
        ev.extend(names.iter().map(|n| format!("header {n} = <redacted>")));
        let tls = t.get("tls");
        if tls.is_some_and(|t| {
            t.get("client-certificate")
                .or(t.get("client_certificate"))
                .is_some()
        }) {
            ev.push("tls client certificate is set".to_string());
        }
    }
    ev
}

/// A config key as a preview flag: the TOML scalar as text, and the layer that set it.
fn flag_input(cfg: &CxConfig, name: &str) -> FlagInput {
    let Some(s) = setting(cfg, name) else {
        return FlagInput::default();
    };
    let source = layer_source(cfg, s.layer);
    FlagInput {
        // A TOML scalar as text: strings keep their quotes, so only a real boolean reads `true`.
        value: Some(s.value.to_string()),
        set_by: Some(source.origin),
        path: Some(source.path),
    }
}

fn payload_of(cfg: &CxConfig, export: Export) -> Payload {
    otel_preview::build(
        otel_catalog::catalog(Vendor::Codex),
        export,
        &|n| flag_input(cfg, n),
        &[],
    )
}

fn on(cfg: &CxConfig, key: &str) -> bool {
    setting(cfg, key).is_some_and(|s| s.value == Value::Bool(true))
}

fn join(list: &[&str]) -> String {
    match list {
        [] => String::new(),
        [a] => a.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

const LOG_DETAIL: &str = "Codex's log export is on. Each tool result carries the command's arguments and up to 2 KiB of its output (`otel.tool_result.max_bytes`), and events carry your account email and the conversation ID.";
const TRACE_DETAIL: &str = "Codex's trace export is on. Codex doesn't document span names or fields, so what they carry may differ from the log events.";

fn shadowed_config(ctx: &mut ScanCtx, cfg: &CxConfig) {
    for (key, layers) in &cfg.otel_shadowed {
        for layer in layers {
            let cloud = *layer == CxLayerId::CloudCfg;
            let title = if cloud {
                format!("Codex may have a shadowed cloud config setting for `{key}`")
            } else {
                format!("Codex has a shadowed config setting for `{key}`")
            };
            let mut detail =
                "A requirements setting takes precedence; Codex does not use this config value."
                    .to_string();
            if cloud {
                detail.push(' ');
                detail.push_str(CLOUD_CACHE_DETAIL);
            }
            ctx.emit(
                FindingBuilder::new(title)
                    .detail(detail)
                    .evidence([format!("key = {key}")])
                    .source(layer_source(cfg, *layer))
                    .best_effort(cloud)
                    .in_effect(false)
                    .reference(REF),
            );
        }
    }
}

/// `otel.exporter` or `otel.trace_exporter`. Returns true when it sends over OTLP.
fn sink(ctx: &mut ScanCtx, cfg: &CxConfig, key: &str, prompts: bool, responses: bool) -> bool {
    let Some(s) = setting(cfg, key) else {
        return false;
    };
    let log_related = [
        key,
        PAYLOAD_FLAG_KEYS[0],
        PAYLOAD_FLAG_KEYS[1],
        PAYLOAD_FLAG_KEYS[2],
    ];
    let exporter_related = [key];
    let related = if key == "otel.exporter" {
        &log_related[..]
    } else {
        &exporter_related[..]
    };
    let requirements = comes_from(cfg, related, requirements_layer);
    let cloud = comes_from(cfg, related, cloud_layer);
    let source = finding_source(cfg, s.layer, related);
    let e = exporter(&s.value);
    if let Some(ep) = endpoint(&e) {
        let host = host(ep);
        let logs = key == "otel.exporter";
        let mut signals = vec![Signal::ToolDetails, Signal::Usage, Signal::Identity];
        let (title, base_detail, export) = if logs {
            signals.push(Signal::FileContents);
            let mut parts = Vec::new();
            if prompts {
                parts.push("your prompts");
            }
            if responses {
                parts.push("its replies");
            }
            parts.extend(["your commands", "their output", "your account email"]);
            (
                format!(
                    "Codex {} {} to {host}",
                    if cloud { "may send" } else { "sends" },
                    join(&parts)
                ),
                LOG_DETAIL,
                Export::Logs,
            )
        } else {
            (
                format!(
                    "Codex {} traces of your session to {host}",
                    if cloud { "may send" } else { "sends" }
                ),
                TRACE_DETAIL,
                Export::Traces,
            )
        };
        let detail = provenance_detail(base_detail, requirements, cloud);
        if prompts {
            signals.push(Signal::Prompts);
        }
        if responses {
            signals.push(Signal::Responses);
        }
        ctx.emit(
            FindingBuilder::new(title)
                .signals(&signals)
                .detail(detail)
                .evidence(otlp_evidence(&s.value, ep))
                .source(source)
                .best_effort(!logs || cloud)
                .payload(payload_of(cfg, export))
                .reference(REF),
        );
        return true;
    }
    if let Exporter::Unknown(_) | Exporter::Statsig = e {
        let related = [key];
        let requirements = comes_from(cfg, &related, requirements_layer);
        let cloud = comes_from(cfg, &related, cloud_layer);
        let title = if cloud {
            format!("Codex may have an unrecognised exporter setting for `{key}`")
        } else {
            format!("Codex has an unrecognised exporter setting for `{key}`")
        };
        ctx.emit(
            FindingBuilder::new(title)
                .detail(provenance_detail("", requirements, cloud))
                .best_effort(true)
                .evidence([format!("{key} = {}", redact::value(key, &s.value))])
                .source(finding_source(cfg, s.layer, &related))
                .reference(REF),
        );
    }
    false
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CxConfig) {
    shadowed_config(ctx, cfg);
    let log_prompt = on(cfg, "otel.log_user_prompt");
    let log_replies = on(cfg, "otel.log_agent_responses");
    let logs_otlp = has_otlp(cfg, "otel.exporter");
    let log_sent = sink(
        ctx,
        cfg,
        "otel.exporter",
        log_prompt && logs_otlp,
        log_replies && logs_otlp,
    );
    let trace_sent = sink(ctx, cfg, "otel.trace_exporter", false, false);
    if !log_sent && trace_sent {
        for (key, on) in [
            ("otel.log_user_prompt", log_prompt),
            ("otel.log_agent_responses", log_replies),
        ] {
            if let Some(s) = setting(cfg, key).filter(|_| on) {
                let related = [key];
                let requirements = comes_from(cfg, &related, requirements_layer);
                let cloud = comes_from(cfg, &related, cloud_layer);
                let title = match (key, cloud) {
                    ("otel.log_user_prompt", true) => {
                        "Codex may log prompts only through `otel.exporter`, which is off"
                    }
                    ("otel.log_agent_responses", true) => {
                        "Codex may log its replies only through `otel.exporter`, which is off"
                    }
                    ("otel.log_user_prompt", false) => {
                        "Codex would log prompts only through `otel.exporter`, which is off"
                    }
                    (_, false) => {
                        "Codex would log its replies only through `otel.exporter`, which is off"
                    }
                    _ => unreachable!(),
                };
                ctx.emit(
                    FindingBuilder::new(title)
                        .detail(provenance_detail("", requirements, cloud))
                        .source(finding_source(cfg, s.layer, &related))
                        .best_effort(cloud)
                        .reference(REF),
                );
            }
        }
    }
    metrics(ctx, cfg);
}

fn has_otlp(cfg: &CxConfig, key: &str) -> bool {
    setting(cfg, key).is_some_and(|s| endpoint(&exporter(&s.value)).is_some())
}

/// CX.5.
fn metrics(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let off = |ctx: &mut ScanCtx, layer| {
        if let Some(b) = vendor::vendor_default(Tool::Codex, true) {
            ctx.emit(b.source(layer_source(cfg, layer)));
        }
    };
    if let Some(s) = cfg.cfg.get("analytics.enabled")
        && s.value == Value::Bool(false)
    {
        off(ctx, s.layer);
        return;
    }
    let metrics_setting = setting(cfg, "otel.metrics_exporter");
    let e = metrics_setting.map_or(Exporter::Statsig, |s| exporter(&s.value));
    match e {
        Exporter::None => {
            if let Some(s) = metrics_setting {
                metrics_vendor_finding(ctx, cfg, s, true, false);
            }
        }
        Exporter::Statsig | Exporter::Unknown(_) => {
            if !codex::is_installed(ctx) {
                return;
            }
            let Some(mut b) = vendor::vendor_default(Tool::Codex, false) else {
                return;
            };
            if let Some(s) = metrics_setting {
                let related = ["otel.metrics_exporter"];
                let requirements = comes_from(cfg, &related, requirements_layer);
                let cloud = comes_from(cfg, &related, cloud_layer);
                if requirements || cloud {
                    metrics_vendor_finding(ctx, cfg, s, false, matches!(e, Exporter::Unknown(_)));
                    return;
                }
                b = b.source(layer_source(cfg, s.layer));
            }
            ctx.emit(b.best_effort(matches!(e, Exporter::Unknown(_))));
        }
        Exporter::OtlpHttp { endpoint } | Exporter::OtlpGrpc { endpoint } => {
            if let Some(s) = metrics_setting {
                let related = ["otel.metrics_exporter"];
                let requirements = comes_from(cfg, &related, requirements_layer);
                let cloud = comes_from(cfg, &related, cloud_layer);
                ctx.emit(
                    FindingBuilder::new(format!(
                        "Codex {} usage metrics to {}",
                        if cloud { "may send" } else { "sends" },
                        host(&endpoint)
                    ))
                    .signals(&[Signal::Usage])
                    .detail(provenance_detail("", requirements, cloud))
                    .evidence(otlp_evidence(&s.value, &endpoint))
                    .source(finding_source(cfg, s.layer, &related))
                    .best_effort(cloud)
                    .payload(payload_of(cfg, Export::Metrics))
                    .reference(REF),
                );
            }
        }
    }
}

fn metrics_vendor_finding(
    ctx: &mut ScanCtx,
    cfg: &CxConfig,
    setting: &CxSetting,
    opted_out: bool,
    unknown: bool,
) {
    let related = ["otel.metrics_exporter"];
    let requirements = comes_from(cfg, &related, requirements_layer);
    let cloud = comes_from(cfg, &related, cloud_layer);
    if !requirements && !cloud {
        let Some(b) = vendor::vendor_default(Tool::Codex, opted_out) else {
            return;
        };
        ctx.emit(
            b.source(layer_source(cfg, setting.layer))
                .best_effort(unknown),
        );
        return;
    }

    let (title, base_detail) = if opted_out {
        (
            if cloud {
                "OpenAI usage metrics may be turned off"
            } else {
                "OpenAI usage metrics is turned off"
            },
            "A setting turns off the vendor's default telemetry, so nothing is sent by default.",
        )
    } else {
        (
            if cloud {
                "OpenAI may receive anonymous usage metrics by default"
            } else {
                "OpenAI receives anonymous usage metrics by default"
            },
            if cloud {
                "Codex may send anonymous usage metrics to OpenAI unless the metrics exporter is turned off."
            } else {
                "Codex sends anonymous usage metrics to OpenAI unless the metrics exporter is turned off."
            },
        )
    };
    let mut b = FindingBuilder::new(title)
        .detail(provenance_detail(base_detail, requirements, cloud))
        .source(finding_source(cfg, setting.layer, &related))
        .reference(REF)
        .best_effort(cloud || unknown);
    b = if opted_out {
        b.in_effect(false)
    } else {
        b.signals(&[Signal::Vendor])
    };
    ctx.emit(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::Loc;
    use crate::harness::platform::Os;
    use crate::model::{Finding, Origin, Sent};
    use crate::scanners::codex::{CxLayer, CxLayerId, CxSetting};
    use serde_json::json;

    fn run(settings: &[(&str, Value)]) -> Vec<Finding> {
        let cfg = CxConfig {
            layers: vec![CxLayer {
                id: CxLayerId::UserCfg,
                loc: Loc::test("~/.codex/config.toml"),
                origin: Origin::User,
            }],
            cfg: settings
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        CxSetting {
                            value: v.clone(),
                            layer: CxLayerId::UserCfg,
                            shadowed: vec![],
                        },
                    )
                })
                .collect(),
            ..CxConfig::default()
        };
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::Codex);
        scan(&mut ctx, &cfg);
        ctx.finish().findings
    }

    fn otlp(endpoint: &str) -> Value {
        json!({"otlp-http": {"endpoint": endpoint, "headers": {"Authorization": "Bearer sk-test-EXAMPLE"}}})
    }

    #[test]
    fn exporter_shapes() {
        assert_eq!(exporter(&json!("none")), Exporter::None);
        assert_eq!(exporter(&json!("statsig")), Exporter::Statsig);
        assert_eq!(
            exporter(&json!("otlp-http")),
            Exporter::OtlpHttp { endpoint: None }
        );
        assert_eq!(
            exporter(&json!("otlp-grpc")),
            Exporter::OtlpGrpc { endpoint: None }
        );
        assert_eq!(
            exporter(&json!({"otlp-grpc": {"endpoint": "https://c.example-corp.com"}})),
            Exporter::OtlpGrpc {
                endpoint: Some("https://c.example-corp.com".into())
            }
        );
        assert_eq!(
            exporter(&json!({"otlp-http": {}})),
            Exporter::OtlpHttp { endpoint: None }
        );
        for bad in [
            json!("zipkin"),
            json!({"otlp-http": {}, "otlp-grpc": {}}),
            json!({"zipkin": {}}),
            json!(3),
        ] {
            assert!(matches!(exporter(&bad), Exporter::Unknown(_)), "{bad}");
        }
    }

    #[test]
    fn log_exporter_sends_tool_details_usage_identity() {
        let f = run(&[(
            "otel.exporter",
            otlp("https://otel.example-corp.com/v1/logs"),
        )]);
        assert_eq!(f.len(), 1);
        let log = &f[0];
        assert_eq!(
            log.title,
            "Codex sends your commands, their output and your account email to otel.example-corp.com"
        );
        for s in [
            Signal::ToolDetails,
            Signal::FileContents,
            Signal::Usage,
            Signal::Identity,
        ] {
            assert!(log.signals.contains(&s), "{s:?}");
        }
        assert_eq!(log.signals.len(), 4);
        assert!(log.detail.contains("up to 2 KiB of its output"));
        assert!(!log.best_effort);
        let p = log.payload.as_ref().unwrap();
        assert_eq!(p.export, Export::Logs);
        assert_eq!(p.catalog, "codex 0.166.0");
        assert!(!p.maybe);
        let ev = log.evidence.join("\n");
        assert!(ev.contains("header Authorization") && !ev.contains("sk-test-EXAMPLE"));
    }

    #[test]
    fn trace_exporter_and_missing_endpoint() {
        let f = run(&[("otel.trace_exporter", json!("otlp-grpc"))]);
        let t = f.iter().find(|x| x.title.contains("traces")).unwrap();
        assert_eq!(t.title, "Codex sends traces of your session to a collector");
        assert_eq!(
            t.signals,
            [Signal::ToolDetails, Signal::Usage, Signal::Identity]
        );
        assert!(t.best_effort && t.detail.contains("doesn't document span names"));
        let p = t.payload.as_ref().unwrap();
        assert_eq!(p.export, Export::Traces);
        assert!(p.maybe);
    }

    #[test]
    fn prompt_logging_needs_the_log_exporter() {
        let with = run(&[
            ("otel.exporter", otlp("https://otel.example-corp.com")),
            ("otel.log_user_prompt", json!(true)),
        ]);
        assert!(with.iter().any(|x| x.signals.contains(&Signal::Prompts)));

        let only_traces = run(&[
            ("otel.trace_exporter", otlp("https://otel.example-corp.com")),
            ("otel.log_user_prompt", json!(true)),
        ]);
        assert!(
            only_traces
                .iter()
                .all(|x| !x.signals.contains(&Signal::Prompts))
        );
        let info = only_traces
            .iter()
            .find(|x| x.title.contains("only through"))
            .unwrap();
        assert!(info.signals.is_empty());
    }

    #[test]
    fn prompts_and_replies_extend_the_title() {
        let f = run(&[
            ("otel.exporter", otlp("https://otel.example-corp.com")),
            ("otel.log_user_prompt", json!(true)),
            ("otel.log_agent_responses", json!(true)),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].title,
            "Codex sends your prompts, its replies, your commands, their output and your account email to otel.example-corp.com"
        );
        assert!(f[0].signals.contains(&Signal::Responses));
        let p = f[0].payload.as_ref().unwrap();
        let gate = |name: &str| p.gates.iter().find(|g| g.flag == name).unwrap();
        assert!(gate("otel.log_user_prompt").on);
        assert_eq!(gate("otel.log_agent_responses").sent, Sent::Yes);
        assert_eq!(gate("otel.log_guardian_assessments").sent, Sent::No);
        assert_eq!(
            gate("otel.log_user_prompt").text,
            "Prompt text: sent, because otel.log_user_prompt = true (set by you)"
        );
        assert_eq!(
            gate("otel.log_user_prompt").path.as_deref(),
            Some("~/.codex/config.toml")
        );
    }

    #[test]
    fn only_a_toml_true_turns_prompt_and_reply_logging_on() {
        for v in [json!(1), json!("yes"), json!("true")] {
            let f = run(&[
                ("otel.exporter", otlp("https://otel.example-corp.com")),
                ("otel.log_user_prompt", v.clone()),
                ("otel.log_agent_responses", v.clone()),
            ]);
            assert_eq!(
                f[0].title,
                "Codex sends your commands, their output and your account email to otel.example-corp.com",
                "{v}"
            );
            let p = f[0].payload.as_ref().unwrap();
            for g in &p.gates {
                assert!(!g.on, "{} for {v}", g.flag);
            }
        }
    }

    #[test]
    fn replies_with_only_traces_is_info() {
        let f = run(&[
            ("otel.trace_exporter", otlp("https://otel.example-corp.com")),
            ("otel.log_agent_responses", json!(true)),
        ]);
        let info = f.iter().find(|x| x.title.contains("its replies")).unwrap();
        assert_eq!(
            info.title,
            "Codex would log its replies only through `otel.exporter`, which is off"
        );
        assert!(info.signals.is_empty() && info.payload.is_none());
        assert!(f.iter().all(|x| !x.signals.contains(&Signal::Responses)));
    }

    #[test]
    fn tls_client_certificate_is_evidence() {
        let v = json!({"otlp-http": {"endpoint": "https://c.example-corp.com",
                       "tls": {"client-certificate": "/etc/acme/c.pem"}}});
        let f = run(&[("otel.exporter", v)]);
        assert!(
            f[0].evidence
                .iter()
                .any(|e| e.contains("client certificate"))
        );
    }

    #[test]
    fn unknown_exporter_is_info_be() {
        let f = run(&[("otel.exporter", json!("zipkin"))]);
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && f[0].best_effort);
    }

    #[test]
    fn analytics_off_and_metrics_none_are_info() {
        for settings in [
            vec![("analytics.enabled", json!(false))],
            vec![("otel.metrics_exporter", json!("none"))],
        ] {
            let f = run(&settings);
            assert_eq!(f.len(), 1);
            assert!(f[0].signals.is_empty() && !f[0].in_effect);
        }
    }

    #[test]
    fn otlp_metrics_are_usage_without_a_vendor_finding() {
        let f = run(&[("otel.metrics_exporter", otlp("https://m.example-corp.com"))]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Usage]);
        assert!(f[0].title.contains("m.example-corp.com"));
        assert_eq!(f[0].payload.as_ref().unwrap().export, Export::Metrics);
    }

    #[test]
    fn vendor_default_needs_codex_installed() {
        // Harness::test points at nothing, so Codex is not installed; the golden fixtures cover
        // the installed case.
        assert!(run(&[]).is_empty());
        assert!(run(&[("otel.metrics_exporter", json!("statsig"))]).is_empty());
        assert!(run(&[("otel.metrics_exporter", json!("zipkin"))]).is_empty());
    }
    fn scan_fixture(name: &str) -> (Vec<Finding>, String) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let h = Harness::from_fixture(&dir).unwrap();
        let report = crate::scan(&h, &crate::ScanOptions::default());
        let text = serde_json::to_string(&report).unwrap();
        let findings = report
            .apps
            .into_iter()
            .chain(report.others)
            .flat_map(|e| e.findings)
            .collect();
        (findings, text)
    }

    fn find<'a>(f: &'a [Finding], needle: &str) -> &'a Finding {
        f.iter()
            .find(|x| x.title.contains(needle))
            .unwrap_or_else(|| panic!("no finding containing {needle}"))
    }

    #[test]
    fn req_otel_overrides_config() {
        let (f, _) = scan_fixture("codex-req-otel");
        let logs = find(&f, "logs.mdm.example.com");
        assert!(logs.title.starts_with("Codex sends your prompts"));
        assert!(logs.detail.ends_with("uses your config instead."));
        assert!(logs.source.path.contains("com.openai.codex.plist"));
        // the config exporter and its flags are shadowed, and every setter is info
        for key in [
            "otel.exporter",
            "otel.log_user_prompt",
            "otel.log_agent_responses",
        ] {
            let s = find(&f, &format!("shadowed config setting for `{key}`"));
            assert!(!s.in_effect && s.signals.is_empty());
        }
        assert!(!f.iter().any(|x| x.title.contains("logs.user.example.com")));
        // a key requirements leave alone resolves from config, with no requirements note
        let traces = find(&f, "traces.user.example.com");
        assert!(!traces.detail.contains("organization enforces"));
    }

    #[test]
    fn req_otel_exporter_not_merged() {
        let (f, text) = scan_fixture("codex-req-otel");
        // MDM wins whole: the system layer's endpoint and `protocol` never combine with it
        assert!(!text.contains("logs.sys.example.com"));
        assert!(!text.contains("protocol"));
        let logs = find(&f, "logs.mdm.example.com");
        assert!(logs.evidence.iter().all(|e| !e.contains("binary")));
    }

    #[test]
    fn mdm_req_otel_beats_cloud() {
        let (f, text) = scan_fixture("codex-cloud-req-otel");
        assert!(
            find(&f, "logs.mdm.example.com")
                .source
                .path
                .contains("com.openai.codex.plist")
        );
        assert!(!text.contains("logs.cloud.example.com"));
        assert!(!text.contains("logs.user.example.com"));
    }

    #[test]
    fn cloud_otel_is_best_effort() {
        let (f, _) = scan_fixture("codex-cloud-req-otel");
        let traces = find(&f, "traces.cloud.example.com");
        assert!(traces.title.starts_with("Codex may send traces"));
        assert!(traces.best_effort);
        // the log finding's prompt flag comes from the cloud config
        let logs = find(&f, "logs.mdm.example.com");
        assert!(logs.title.starts_with("Codex may send your prompts"));
        assert!(logs.best_effort);
    }

    #[test]
    fn cloud_cache_ids_never_reported() {
        let (_, text) = scan_fixture("codex-cloud-req-otel");
        for secret in [
            "fake-account-id-0001",
            "fake-user-id-0002",
            "fake-signature-0003",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
        let h = Harness::from_fixture(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/codex-cloud-req-otel"),
        )
        .unwrap();
        let report = crate::scan(&h, &crate::ScanOptions::default());
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("fake-account-id-0001"));
    }
}
