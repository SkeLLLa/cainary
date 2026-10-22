//! Claude Code the telemetry unit and OTel findings (rules.md §CC.3).

use super::claude_code::{self, CcConfig, CcEnvVar, CcFrom, doc, from_finding, is_unit};
use crate::harness::ScanCtx;
use crate::model::{FindingBuilder, Signal};
use crate::redact;
use crate::rules::otel::{self, Kind, OtelSignal};
use crate::value::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    Metrics,
    Logs,
    Traces,
    Beta,
}

const CONTENT_FLAGS: [&str; 5] = [
    "OTEL_LOG_USER_PROMPTS",
    "OTEL_LOG_ASSISTANT_RESPONSES",
    "OTEL_LOG_TOOL_DETAILS",
    "OTEL_LOG_TOOL_CONTENT",
    "OTEL_LOG_RAW_API_BODIES",
];

fn val<'a>(cfg: &'a CcConfig, name: &str) -> Option<&'a str> {
    claude_code::env_value(cfg, name)
}

fn flag(cfg: &CcConfig, name: &str) -> bool {
    val(cfg, name).is_some_and(|v| value::truthy(&Value::from(v)))
}

fn counting(cfg: &CcConfig, name: &str) -> bool {
    val(cfg, name).is_some_and(|l| otel::sends(&otel::exporters(l)))
}

fn line(v: &CcEnvVar) -> String {
    format!(
        "{} = {}",
        v.name,
        redact::value(&v.name, &Value::from(v.value.as_str()))
    )
}

/// A content flag that is on, with the signals it adds to destination `d`.
fn content(cfg: &CcConfig, d: Dest) -> Vec<(&CcEnvVar, Vec<Signal>)> {
    use Signal::{FileContents, Prompts, Responses, ToolDetails};
    let on = |n: &str| claude_code::env(cfg, n).filter(|v| flag(cfg, &v.name));
    let mut out = Vec::new();
    if let Some(v) = on("OTEL_LOG_USER_PROMPTS") {
        let mut s = match d {
            Dest::Metrics => vec![],
            Dest::Logs | Dest::Traces => vec![Prompts],
            Dest::Beta => vec![Prompts, Responses, FileContents],
        };
        if d == Dest::Logs && val(cfg, "OTEL_LOG_ASSISTANT_RESPONSES").is_none() {
            s.push(Responses);
        }
        out.push((v, s));
    }
    if let Some(v) = on("OTEL_LOG_ASSISTANT_RESPONSES")
        && d == Dest::Logs
    {
        out.push((v, vec![Responses]));
    }
    if let Some(v) = on("OTEL_LOG_TOOL_DETAILS")
        && d != Dest::Metrics
    {
        out.push((v, vec![ToolDetails]));
    }
    if let Some(v) = on("OTEL_LOG_TOOL_CONTENT")
        && matches!(d, Dest::Traces | Dest::Beta)
    {
        out.push((v, vec![FileContents]));
    }
    if let Some(v) = claude_code::env(cfg, "OTEL_LOG_RAW_API_BODIES")
        && d == Dest::Logs
        && matches!(v.value.to_ascii_lowercase().as_str(), "1" | "true")
    {
        out.push((v, vec![Prompts, Responses, ToolDetails, FileContents]));
    }
    out.retain(|(_, s)| !s.is_empty());
    out
}

/// What contributes to one destination from one source.
struct Contrib {
    from: CcFrom,
    var: String,
    signals: Vec<Signal>,
    evidence: Vec<String>,
}

fn group<'a>(all: &'a mut Vec<Contrib>, v: &CcEnvVar) -> &'a mut Contrib {
    let i = all
        .iter()
        .position(|c| c.from == v.from)
        .unwrap_or_else(|| {
            all.push(Contrib {
                from: v.from.clone(),
                var: v.name.clone(),
                signals: Vec::new(),
                evidence: Vec::new(),
            });
            all.len() - 1
        });
    &mut all[i]
}

fn push_line(c: &mut Contrib, l: String) {
    if !c.evidence.contains(&l) {
        c.evidence.push(l);
    }
}

fn phrases(signals: &[Signal]) -> Vec<&'static str> {
    let mut out = Vec::new();
    if signals.contains(&Signal::Usage) {
        out.push("usage data");
    }
    for (s, p) in [
        (Signal::Prompts, "your prompts"),
        (Signal::Responses, "Claude's responses"),
        (Signal::ToolDetails, "tool details"),
        (Signal::FileContents, "file contents"),
    ] {
        if signals.contains(&s) {
            out.push(p);
        }
    }
    out
}

fn join(list: &[&str]) -> String {
    match list {
        [] => String::new(),
        [a] => a.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn signal_of(d: Dest) -> Option<(OtelSignal, &'static str, &'static str)> {
    match d {
        Dest::Metrics => Some((OtelSignal::Metrics, "METRICS", "OTEL_METRICS_EXPORTER")),
        Dest::Logs => Some((OtelSignal::Logs, "LOGS", "OTEL_LOGS_EXPORTER")),
        Dest::Traces => Some((OtelSignal::Traces, "TRACES", "OTEL_TRACES_EXPORTER")),
        Dest::Beta => None,
    }
}

fn dest_detail(d: Dest) -> &'static str {
    match d {
        Dest::Metrics => "Claude Code's metrics export is on",
        Dest::Logs => "Claude Code's log export is on",
        Dest::Traces => "Claude Code's trace export (beta) is on",
        Dest::Beta => {
            "Claude Code's detailed trace export is on. Anthropic allowlists it, so it may not apply"
        }
    }
}

/// The host, and the variables that name it.
fn host_of(cfg: &CcConfig, d: Dest) -> (String, Vec<&CcEnvVar>) {
    let Some((sig, name, _)) = signal_of(d) else {
        let v = claude_code::env(cfg, "BETA_TRACING_ENDPOINT");
        let host = v
            .and_then(|v| redact::url_host(&v.value))
            .unwrap_or_else(|| "an unknown host".to_string());
        return (host, v.into_iter().collect());
    };
    let get = |n: &str| val(cfg, n).map(str::to_string);
    let host = otel::endpoint_host(&get, sig).unwrap_or_else(|| "a local collector".to_string());
    let mut vars: Vec<&CcEnvVar> = Vec::new();
    for n in [
        format!("OTEL_EXPORTER_OTLP_{name}_ENDPOINT"),
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
        format!("OTEL_EXPORTER_OTLP_{name}_HEADERS"),
        "OTEL_EXPORTER_OTLP_HEADERS".to_string(),
    ] {
        vars.extend(claude_code::env(cfg, &n));
    }
    (host, vars)
}

pub fn scan(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let enabled = flag(cfg, "CLAUDE_CODE_ENABLE_TELEMETRY");
    let trace_switch = flag(cfg, "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA")
        || flag(cfg, "ENABLE_ENHANCED_TELEMETRY_BETA");
    let managed_unit = cfg
        .env
        .iter()
        .any(|v| v.in_effect && is_unit(&v.name) && matches!(v.from, CcFrom::Tier(_)));
    let mut used: Vec<&str> = Vec::new();
    let active = [
        (
            Dest::Metrics,
            enabled && counting(cfg, "OTEL_METRICS_EXPORTER"),
        ),
        (Dest::Logs, enabled && counting(cfg, "OTEL_LOGS_EXPORTER")),
        (
            Dest::Traces,
            enabled && trace_switch && counting(cfg, "OTEL_TRACES_EXPORTER"),
        ),
        (
            Dest::Beta,
            enabled
                && flag(cfg, "ENABLE_BETA_TRACING_DETAILED")
                && val(cfg, "BETA_TRACING_ENDPOINT").is_some(),
        ),
    ];
    for (d, on) in active {
        if !on {
            continue;
        }
        let (host, endpoint_vars) = host_of(cfg, d);
        let base = match signal_of(d) {
            Some((_, _, exporter)) => claude_code::env(cfg, exporter),
            None => claude_code::env(cfg, "BETA_TRACING_ENDPOINT"),
        };
        let Some(base) = base else { continue };
        let mut all: Vec<Contrib> = Vec::new();
        let account_uuid_off = val(cfg, "OTEL_METRICS_INCLUDE_ACCOUNT_UUID")
            .is_some_and(|v| v.eq_ignore_ascii_case("false"));
        let resource = claude_code::env(cfg, "OTEL_RESOURCE_ATTRIBUTES");
        let identity = d != Dest::Metrics || resource.is_some() || !account_uuid_off;
        let c = group(&mut all, base);
        c.signals.push(Signal::Usage);
        if identity {
            c.signals.push(Signal::Identity);
        }
        for v in [
            claude_code::env(cfg, "CLAUDE_CODE_ENABLE_TELEMETRY"),
            Some(base),
            resource,
        ]
        .into_iter()
        .flatten()
        .chain(endpoint_vars)
        {
            push_line(c, line(v));
        }
        if d == Dest::Beta {
            c.evidence
                .extend(claude_code::env(cfg, "ENABLE_BETA_TRACING_DETAILED").map(line));
        }
        if d == Dest::Traces {
            let switch = [
                "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
                "ENABLE_ENHANCED_TELEMETRY_BETA",
            ]
            .iter()
            .find_map(|n| claude_code::env(cfg, n));
            c.evidence.extend(switch.map(line));
        }
        for (v, signals) in content(cfg, d) {
            used.push(&v.name);
            let c = group(&mut all, v);
            c.signals.extend(signals);
            push_line(c, line(v));
        }
        for c in all {
            let list = phrases(&c.signals);
            let local = !matches!(c.from, CcFrom::Tier(_));
            let b = FindingBuilder::new(format!("Claude Code sends {} to {host}", join(&list)))
                .signals(&c.signals)
                .detail(format!("{}.", dest_detail(d)))
                .reference(doc("monitoring-usage"));
            ctx.emit(from_finding(
                ctx,
                cfg,
                &c.from,
                &c.var,
                b,
                c.evidence,
                d == Dest::Beta || (local && managed_unit),
            ));
        }
    }
    orphan_flags(ctx, cfg, &used);
    raw_bodies(ctx, cfg);
    exporter_notes(ctx, cfg, enabled, trace_switch);
    present_but_off(ctx, cfg, enabled);
    replaced(ctx, cfg);
}

/// A content flag that is on while none of its destinations is.
fn orphan_flags(ctx: &mut ScanCtx, cfg: &CcConfig, used: &[&str]) {
    if !flag(cfg, "CLAUDE_CODE_ENABLE_TELEMETRY") {
        return;
    }
    for name in CONTENT_FLAGS {
        let Some(v) = claude_code::env(cfg, name) else {
            continue;
        };
        let on = if name == "OTEL_LOG_RAW_API_BODIES" {
            matches!(v.value.to_ascii_lowercase().as_str(), "1" | "true")
        } else {
            flag(cfg, name)
        };
        if !on || used.contains(&name) {
            continue;
        }
        let (what, exports) = match name {
            "OTEL_LOG_USER_PROMPTS" => ("your prompts", "log or trace"),
            "OTEL_LOG_ASSISTANT_RESPONSES" => ("Claude's responses", "log"),
            "OTEL_LOG_TOOL_DETAILS" => ("tool details", "log or trace"),
            "OTEL_LOG_TOOL_CONTENT" => ("file contents", "trace"),
            _ => ("raw API bodies", "log"),
        };
        let b = FindingBuilder::new(format!(
            "Claude Code would export {what} if {exports} export were on"
        ))
        .detail("No export that carries it is on, so nothing is sent.")
        .reference(doc("monitoring-usage"))
        .in_effect(false);
        ctx.emit(from_finding(
            ctx,
            cfg,
            &v.from,
            &v.name,
            b,
            vec![line(v)],
            false,
        ));
    }
}

/// `OTEL_LOG_RAW_API_BODIES=file:<dir>` writes locally; anything else unknown is flagged.
fn raw_bodies(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let Some(v) = claude_code::env(cfg, "OTEL_LOG_RAW_API_BODIES") else {
        return;
    };
    let lower = v.value.to_ascii_lowercase();
    let b = if let Some(dir) = v.value.strip_prefix("file:") {
        FindingBuilder::new(format!(
            "Claude Code writes raw API bodies to {} on this machine",
            redact::text(dir)
        ))
        .detail("The bodies stay on local disk and aren't sent anywhere.")
    } else if ["1", "true", "0", "false", "no", "off"].contains(&lower.as_str()) {
        return;
    } else {
        FindingBuilder::new("Claude Code's raw API body setting has an unrecognised value")
            .detail("cAInary doesn't know this value, so it can't say where the bodies go.")
    };
    let b = b.reference(doc("monitoring-usage"));
    ctx.emit(from_finding(
        ctx,
        cfg,
        &v.from,
        &v.name,
        b,
        vec![line(v)],
        true,
    ));
}

/// Prometheus is pull-only; traces need the beta switch.
fn exporter_notes(ctx: &mut ScanCtx, cfg: &CcConfig, enabled: bool, trace_switch: bool) {
    if !enabled {
        return;
    }
    if let Some(v) = claude_code::env(cfg, "OTEL_METRICS_EXPORTER")
        && otel::exporters(&v.value).contains(&Kind::Prometheus)
    {
        let b = FindingBuilder::new("Claude Code serves metrics for a local scraper")
            .detail("Prometheus metrics are pulled by something on this machine, not pushed out.")
            .reference(doc("monitoring-usage"));
        ctx.emit(from_finding(
            ctx,
            cfg,
            &v.from,
            &v.name,
            b,
            vec![line(v)],
            false,
        ));
    }
    if !trace_switch
        && counting(cfg, "OTEL_TRACES_EXPORTER")
        && let Some(v) = claude_code::env(cfg, "OTEL_TRACES_EXPORTER")
    {
        let b = FindingBuilder::new("Claude Code's trace export is set up but switched off")
            .detail("Trace export sends nothing without the enhanced telemetry beta switch.")
            .reference(doc("monitoring-usage"))
            .in_effect(false);
        ctx.emit(from_finding(
            ctx,
            cfg,
            &v.from,
            &v.name,
            b,
            vec![line(v)],
            false,
        ));
    }
}

fn is_telemetry_var(name: &str) -> bool {
    name.starts_with("OTEL_")
        || matches!(
            name,
            "ENABLE_BETA_TRACING_DETAILED"
                | "BETA_TRACING_ENDPOINT"
                | "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"
                | "ENABLE_ENHANCED_TELEMETRY_BETA"
        )
}

/// Telemetry variables are set but `CLAUDE_CODE_ENABLE_TELEMETRY` isn't.
fn present_but_off(ctx: &mut ScanCtx, cfg: &CcConfig, enabled: bool) {
    if enabled {
        return;
    }
    let vars: Vec<&CcEnvVar> = cfg
        .env
        .iter()
        .filter(|v| {
            v.in_effect && (is_telemetry_var(&v.name) || v.name == "CLAUDE_CODE_ENABLE_TELEMETRY")
        })
        .collect();
    if !vars.iter().any(|v| is_telemetry_var(&v.name)) {
        return;
    }
    let mut froms: Vec<&CcFrom> = Vec::new();
    for v in &vars {
        if !froms.contains(&&v.from) {
            froms.push(&v.from);
        }
    }
    for from in froms {
        let mine: Vec<&&CcEnvVar> = vars.iter().filter(|v| &v.from == from).collect();
        let b =
            FindingBuilder::new("Claude Code telemetry settings are present but telemetry is off")
                .detail("Telemetry only starts when it is switched on, so nothing is sent.")
                .reference(doc("monitoring-usage"))
                .in_effect(false);
        let evidence = mine.iter().map(|v| line(v)).collect();
        ctx.emit(from_finding(
            ctx,
            cfg,
            from,
            &mine[0].name,
            b,
            evidence,
            false,
        ));
    }
}

/// Variables an administrator's settings replace.
fn replaced(ctx: &mut ScanCtx, cfg: &CcConfig) {
    let gone: Vec<&CcEnvVar> = cfg
        .env
        .iter()
        .filter(|v| !v.in_effect && is_unit(&v.name))
        .collect();
    let mut froms: Vec<&CcFrom> = Vec::new();
    for v in &gone {
        if !froms.contains(&&v.from) {
            froms.push(&v.from);
        }
    }
    for from in froms {
        let mine: Vec<&&CcEnvVar> = gone.iter().filter(|v| &v.from == from).collect();
        let b = FindingBuilder::new("Some telemetry settings are replaced by your organization's")
            .detail(
                "An administrator's telemetry settings take precedence, so these have no effect.",
            )
            .reference(doc("monitoring-usage"))
            .in_effect(false);
        let evidence = mine
            .iter()
            .map(|v| format!("{} ({})", line(v), v.why.as_deref().unwrap_or("replaced")))
            .collect();
        ctx.emit(from_finding(
            ctx,
            cfg,
            from,
            &mine[0].name,
            b,
            evidence,
            false,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use crate::harness::platform::Os;
    use crate::model::{Finding, Origin, Tool};
    use crate::scanners::claude_code::{CcSetting, CcTier, CcTierId, effective_env, is_policy_doc};
    use serde_json::{Map, json};

    fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn run(cfg: &CcConfig) -> Vec<Finding> {
        let h = Harness::test(Os::Macos, &[]);
        let mut ctx = ScanCtx::new(&h, Tool::ClaudeCode);
        scan(&mut ctx, cfg);
        ctx.finish().findings
    }

    /// Process-level variables only.
    fn proc_cfg(pairs: &[(&str, &str)]) -> CcConfig {
        CcConfig {
            env: effective_env(Vec::new(), Vec::new(), env_of(pairs)),
            ..CcConfig::default()
        }
    }

    const ON: (&str, &str) = ("CLAUDE_CODE_ENABLE_TELEMETRY", "1");

    #[test]
    fn metrics_only_is_usage_and_identity() {
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_METRICS_EXPORTER", "otlp"),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://otel.example-corp.com:4318",
            ),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "Authorization=Bearer sk-test-EXAMPLE",
            ),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].signals, [Signal::Usage, Signal::Identity]);
        assert!(f[0].title.contains("otel.example-corp.com"));
        assert_eq!(f[0].source.origin, Origin::Environment);
        let ev = f[0].evidence.join("\n");
        assert!(ev.contains("OTEL_EXPORTER_OTLP_HEADERS = Authorization"));
        assert!(!ev.contains("sk-test"));
        // account uuid off and no resource attributes: usage only
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_METRICS_EXPORTER", "otlp"),
            ("OTEL_METRICS_INCLUDE_ACCOUNT_UUID", "false"),
        ]));
        assert_eq!(f[0].signals, [Signal::Usage]);
        assert!(f[0].title.contains("a local collector"));
    }

    #[test]
    fn not_enabled_is_info() {
        let f = run(&proc_cfg(&[("OTEL_METRICS_EXPORTER", "otlp")]));
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && !f[0].in_effect);
        assert!(run(&proc_cfg(&[])).is_empty());
    }

    #[test]
    fn console_and_prometheus_send_nothing() {
        let f = run(&proc_cfg(&[ON, ("OTEL_METRICS_EXPORTER", "console")]));
        assert!(f.is_empty());
        let f = run(&proc_cfg(&[ON, ("OTEL_METRICS_EXPORTER", "prometheus")]));
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && f[0].title.contains("local scraper"));
    }

    #[test]
    fn logs_prompts_and_responses() {
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_LOG_USER_PROMPTS", "1"),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].signals,
            [
                Signal::Prompts,
                Signal::Responses,
                Signal::Usage,
                Signal::Identity
            ]
        );
        // an explicit responses switch off keeps only prompts
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_LOG_USER_PROMPTS", "1"),
            ("OTEL_LOG_ASSISTANT_RESPONSES", "0"),
        ]));
        assert_eq!(
            f[0].signals,
            [Signal::Prompts, Signal::Usage, Signal::Identity]
        );
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_LOG_TOOL_DETAILS", "true"),
        ]));
        assert!(f[0].signals.contains(&Signal::ToolDetails));
    }

    #[test]
    fn prompts_with_only_metrics_is_info_not_in_effect() {
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_METRICS_EXPORTER", "otlp"),
            ("OTEL_LOG_USER_PROMPTS", "1"),
        ]));
        assert_eq!(f.len(), 2);
        let info = f.iter().find(|f| !f.in_effect).unwrap();
        assert!(info.signals.is_empty());
        assert!(info.title.contains("would export your prompts"));
        let live = f.iter().find(|f| f.in_effect).unwrap();
        assert!(!live.signals.contains(&Signal::Prompts));
    }

    #[test]
    fn traces_need_the_beta_switch() {
        let f = run(&proc_cfg(&[ON, ("OTEL_TRACES_EXPORTER", "otlp")]));
        assert_eq!(f.len(), 1);
        assert!(f[0].signals.is_empty() && !f[0].in_effect);
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_TRACES_EXPORTER", "otlp"),
            ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1"),
            ("OTEL_LOG_TOOL_CONTENT", "1"),
            ("OTEL_LOG_USER_PROMPTS", "1"),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].signals,
            [
                Signal::Prompts,
                Signal::FileContents,
                Signal::Usage,
                Signal::Identity
            ]
        );
    }

    #[test]
    fn beta_tracing_is_best_effort_and_carries_everything() {
        let f = run(&proc_cfg(&[
            ON,
            ("ENABLE_BETA_TRACING_DETAILED", "1"),
            ("BETA_TRACING_ENDPOINT", "https://beta.example-corp.com/v1"),
            ("OTEL_LOG_USER_PROMPTS", "1"),
        ]));
        assert_eq!(f.len(), 1);
        assert!(f[0].best_effort);
        assert!(f[0].title.contains("beta.example-corp.com"));
        for s in [Signal::Prompts, Signal::Responses, Signal::FileContents] {
            assert!(f[0].signals.contains(&s));
        }
    }

    #[test]
    fn raw_api_bodies_modes() {
        let f = run(&proc_cfg(&[
            ON,
            ("OTEL_LOGS_EXPORTER", "otlp"),
            ("OTEL_LOG_RAW_API_BODIES", "1"),
        ]));
        assert_eq!(f.len(), 1);
        for s in [
            Signal::Prompts,
            Signal::Responses,
            Signal::ToolDetails,
            Signal::FileContents,
        ] {
            assert!(f[0].signals.contains(&s));
        }
        let f = run(&proc_cfg(&[(
            "OTEL_LOG_RAW_API_BODIES",
            "file:/tmp/acme-bodies",
        )]));
        let local = f
            .iter()
            .find(|f| f.title.contains("on this machine"))
            .unwrap();
        assert!(local.signals.is_empty() && local.best_effort);
        assert!(local.title.contains("/tmp/acme-bodies"));
        let f = run(&proc_cfg(&[("OTEL_LOG_RAW_API_BODIES", "maybe")]));
        let odd = f.iter().find(|f| f.title.contains("unrecognised")).unwrap();
        assert!(odd.signals.is_empty() && odd.best_effort);
    }

    fn admin_tier(env: Value, extra: Value) -> CcTier {
        let mut value: Map<String, Value> = extra.as_object().cloned().unwrap_or_default();
        value.insert("env".into(), env);
        CcTier {
            id: CcTierId::File,
            loc: crate::harness::Loc::test("/etc/claude-code/managed-settings.json"),
            origin: Origin::System,
            policy: is_policy_doc(&value),
            value,
        }
    }

    #[test]
    fn admin_unit_with_local_content_flag_is_org_plus_be_local() {
        let t = admin_tier(
            json!({
                "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
                "OTEL_LOGS_EXPORTER": "otlp",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example-corp.com"
            }),
            json!({}),
        );
        let managed = crate::scanners::claude_code::managed_env(std::slice::from_ref(&t));
        let cfg = CcConfig {
            env: effective_env(
                managed,
                Vec::new(),
                env_of(&[
                    ("OTEL_LOG_USER_PROMPTS", "1"),
                    (
                        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                        "https://evil.example.com",
                    ),
                ]),
            ),
            managed: vec![CcSetting {
                key: "env".into(),
                value: Value::Null,
                tier: CcTierId::File,
                in_effect: true,
            }],
            tiers: vec![t],
            ..CcConfig::default()
        };
        let dropped = cfg
            .env
            .iter()
            .find(|v| v.name == "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
            .unwrap();
        assert!(!dropped.in_effect && dropped.why.is_some());
        let f = run(&cfg);
        let admin = f
            .iter()
            .find(|f| f.source.origin == Origin::System)
            .unwrap();
        assert_eq!(admin.signals, [Signal::Usage, Signal::Identity]);
        assert!(admin.title.contains("otel.example-corp.com"));
        let local = f
            .iter()
            .find(|f| f.source.origin == Origin::Environment && f.in_effect)
            .unwrap();
        assert!(local.signals.contains(&Signal::Prompts) && local.best_effort);
        assert!(
            f.iter()
                .any(|f| !f.in_effect && f.title.contains("replaced"))
        );
    }
}
