//! Codex otel exporters, prompt logging and vendor metrics (rules.md §CX.4, CX.5).

use super::codex::{self, CxConfig, layer_source};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Signal, Tool};
use crate::redact;
use crate::rules::vendor;
use crate::value::{self, Value};

const REF: &str = "https://learn.chatgpt.com/docs/config-file/config-reference";

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

/// `otel.exporter` or `otel.trace_exporter`. Returns true when it sends over OTLP.
fn sink(ctx: &mut ScanCtx, cfg: &CxConfig, key: &str, prompts: bool) -> bool {
    let Some(s) = cfg.cfg.get(key) else {
        return false;
    };
    let source = layer_source(cfg, s.layer);
    let e = exporter(&s.value);
    if let Some(ep) = endpoint(&e) {
        let host = host(ep);
        let (title, mut signals) = if key == "otel.exporter" {
            let what = if prompts {
                "tool results, session data and your prompts"
            } else {
                "tool results and session data"
            };
            (
                format!("Codex sends {what} to {host}"),
                vec![Signal::ToolDetails, Signal::Usage, Signal::Identity],
            )
        } else {
            (
                format!("Codex sends traces to {host}"),
                vec![Signal::ToolDetails, Signal::Usage, Signal::Identity],
            )
        };
        if prompts {
            signals.push(Signal::Prompts);
        }
        ctx.emit(
            FindingBuilder::new(title)
                .signals(&signals)
                .evidence(otlp_evidence(&s.value, ep))
                .source(source)
                .reference(REF),
        );
        return true;
    }
    if let Exporter::Unknown(_) | Exporter::Statsig = e {
        ctx.emit(
            FindingBuilder::new(format!(
                "Codex has an unrecognised exporter setting for `{key}`"
            ))
            .best_effort(true)
            .evidence([format!("{key} = {}", redact::value(key, &s.value))])
            .source(source)
            .reference(REF),
        );
    }
    false
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CxConfig) {
    let log_prompt = cfg
        .cfg
        .get("otel.log_user_prompt")
        .is_some_and(|s| value::truthy(&s.value));
    let log_sent = sink(
        ctx,
        cfg,
        "otel.exporter",
        log_prompt && has_otlp(cfg, "otel.exporter"),
    );
    let trace_sent = sink(ctx, cfg, "otel.trace_exporter", false);
    if log_prompt
        && !log_sent
        && trace_sent
        && let Some(s) = cfg.cfg.get("otel.log_user_prompt")
    {
        ctx.emit(
            FindingBuilder::new(
                "Codex would log prompts only through `otel.exporter`, which is off",
            )
            .source(layer_source(cfg, s.layer))
            .reference(REF),
        );
    }
    metrics(ctx, cfg);
}

fn has_otlp(cfg: &CxConfig, key: &str) -> bool {
    cfg.cfg
        .get(key)
        .is_some_and(|s| endpoint(&exporter(&s.value)).is_some())
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
    let setting = cfg.cfg.get("otel.metrics_exporter");
    let e = setting.map_or(Exporter::Statsig, |s| exporter(&s.value));
    match e {
        Exporter::None => {
            if let Some(s) = setting {
                off(ctx, s.layer);
            }
        }
        Exporter::Statsig | Exporter::Unknown(_) => {
            if !codex::is_installed(ctx) {
                return;
            }
            let Some(mut b) = vendor::vendor_default(Tool::Codex, false) else {
                return;
            };
            if let Some(s) = setting {
                b = b.source(layer_source(cfg, s.layer));
            }
            ctx.emit(b.best_effort(matches!(e, Exporter::Unknown(_))));
        }
        Exporter::OtlpHttp { endpoint } | Exporter::OtlpGrpc { endpoint } => {
            if let Some(s) = setting {
                ctx.emit(
                    FindingBuilder::new(format!(
                        "Codex sends usage metrics to {}",
                        host(&endpoint)
                    ))
                    .signals(&[Signal::Usage])
                    .evidence(otlp_evidence(&s.value, &endpoint))
                    .source(layer_source(cfg, s.layer))
                    .reference(REF),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::Loc;
    use crate::harness::platform::Os;
    use crate::model::{Finding, Origin};
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
        let log = f.iter().find(|x| x.title.contains("tool results")).unwrap();
        assert_eq!(
            log.signals,
            [Signal::ToolDetails, Signal::Usage, Signal::Identity]
        );
        assert!(log.title.contains("otel.example-corp.com"));
        let ev = log.evidence.join("\n");
        assert!(ev.contains("header Authorization") && !ev.contains("sk-test-EXAMPLE"));
    }

    #[test]
    fn trace_exporter_and_missing_endpoint() {
        let f = run(&[("otel.trace_exporter", json!("otlp-grpc"))]);
        let t = f.iter().find(|x| x.title.contains("traces")).unwrap();
        assert!(t.title.contains("a collector"));
        assert_eq!(
            t.signals,
            [Signal::ToolDetails, Signal::Usage, Signal::Identity]
        );
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
    }

    #[test]
    fn vendor_default_needs_codex_installed() {
        // Harness::test points at nothing, so Codex is not installed; the golden fixtures cover
        // the installed case.
        assert!(run(&[]).is_empty());
        assert!(run(&[("otel.metrics_exporter", json!("statsig"))]).is_empty());
        assert!(run(&[("otel.metrics_exporter", json!("zipkin"))]).is_empty());
    }
}
