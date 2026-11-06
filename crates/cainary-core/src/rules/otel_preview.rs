//! The catalog plus the resolved flags become a [`Payload`]: what one telemetry export carries
//! (architecture.md §3.7). Pure: the scanners resolve each flag and pass it in.

use super::otel_catalog::{Attr, Catalog, Export, Flag, Gate, Item, Off, Rule, Vendor};
use crate::model::{AttrOut, GateState, Origin, Payload, RecordOut, Sent};
use crate::redact;
use crate::value::{self, Value};

/// A flag as resolved in this scan.
#[derive(Debug, Clone, Default)]
pub struct FlagInput {
    /// The in-effect raw value; `None` = unset.
    pub value: Option<String>,
    pub set_by: Option<Origin>,
    pub path: Option<String>,
}

type Lookup<'a> = &'a dyn Fn(&str) -> FlagInput;

fn find_flag<'a>(cat: &'a Catalog, name: &str) -> Option<&'a Flag> {
    cat.flags.iter().find(|f| f.name == name)
}

/// Is the flag on under `rule`?
fn on_under(cat: &Catalog, rule: Rule, name: &str, flag: Lookup, depth: u8) -> bool {
    let input = flag(name);
    let v = input.value.as_deref();
    match rule {
        Rule::Truthy => v.is_some_and(|v| value::truthy(&Value::from(v))),
        Rule::NotFalse => v.is_none_or(|v| !v.trim().eq_ignore_ascii_case("false")),
        Rule::FallbackTo(other) => match v {
            Some(v) => value::truthy(&Value::from(v)),
            None if depth < 4 => {
                find_flag(cat, other).is_some_and(|f| on_under(cat, f.rule, other, flag, depth + 1))
            }
            None => false,
        },
        Rule::RawInline => v.is_some_and(is_inline),
        Rule::RawFile => v.is_some_and(is_file),
        Rule::RawAny => v.is_some_and(|v| is_inline(v) || is_file(v)),
        Rule::TomlTrue => v.is_some_and(|v| v.trim() == "true"),
    }
}

/// `OTEL_LOG_RAW_API_BODIES` asks for bodies inline: `1` or `true`, trimmed, any case.
pub fn is_inline(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true")
}

fn is_file(v: &str) -> bool {
    v.trim().starts_with("file:")
}

fn gate_on(cat: &Catalog, g: &Gate, flag: Lookup) -> bool {
    let rule = g
        .rule
        .or_else(|| find_flag(cat, g.flag).map(|f| f.rule))
        .unwrap_or(Rule::Truthy);
    on_under(cat, rule, g.flag, flag, 0)
}

fn sent_of(cat: &Catalog, g: &Gate, flag: Lookup) -> Sent {
    if gate_on(cat, g, flag) {
        return Sent::Yes;
    }
    match g.off {
        Off::Redacted(_) => Sent::Redacted,
        Off::Omitted => Sent::No,
        Off::Generic(_) => Sent::Generic,
    }
}

fn accepts(only: Option<&[Export]>, export: Export) -> bool {
    only.is_none_or(|e| e.contains(&export))
}

fn items_of(cat: &Catalog, export: Export) -> impl Iterator<Item = &'static Item> + '_ {
    cat.items
        .iter()
        .filter(move |i| i.exports.contains(&export))
}

fn attrs_of(list: &'static [Attr], export: Export) -> impl Iterator<Item = &'static Attr> {
    list.iter().filter(move |a| accepts(a.only, export))
}

/// Every gate that applies to `export`, with the flag it names. The `*` identity entry stands
/// for the names in `OTEL_RESOURCE_ATTRIBUTES`; with none set its gate has nothing to send.
fn gates_of(cat: &Catalog, export: Export, extra: &[String]) -> Vec<Gate> {
    let mut out = Vec::new();
    for a in attrs_of(cat.identity, export)
        .chain(attrs_of(cat.resource, export))
        .chain(attrs_of(cat.common, export))
    {
        if a.key == "*" && extra.is_empty() {
            continue;
        }
        out.extend(a.gate);
    }
    for i in items_of(cat, export) {
        out.extend(i.gate);
        for a in attrs_of(i.attrs, export) {
            out.extend(a.gate);
        }
    }
    out
}

fn quoted(a: &Attr) -> String {
    match a.value {
        Some(v) => format!("\"{v}\""),
        None => a.what.to_string(),
    }
}

fn attr_out(cat: &Catalog, key: &str, what: String, a: &Attr, flag: Lookup) -> AttrOut {
    AttrOut {
        key: key.to_string(),
        what,
        group: a.group,
        maybe: a.best_effort,
        when: a.when.map(str::to_string),
        flag: a.gate.map(|g| g.flag.to_string()),
        sent: a.gate.map(|g| sent_of(cat, &g, flag)),
    }
}

/// Identity attributes. The catalog's `*` entry stands for the names set by
/// `OTEL_RESOURCE_ATTRIBUTES`; it is dropped when there are none.
fn identity_out(cat: &Catalog, export: Export, flag: Lookup, extra: &[String]) -> Vec<AttrOut> {
    let mut out = Vec::new();
    for a in attrs_of(cat.identity, export) {
        if a.key == "*" {
            for name in extra {
                let what = "set by OTEL_RESOURCE_ATTRIBUTES".to_string();
                out.push(attr_out(cat, name, what, a, flag));
            }
        } else {
            out.push(attr_out(cat, a.key, quoted(a), a, flag));
        }
    }
    out
}

fn record_out(cat: &Catalog, item: &Item, export: Export, flag: Lookup) -> RecordOut {
    RecordOut {
        name: item.name.to_string(),
        kind: item.kind,
        what: item.what.to_string(),
        unit: item.unit.map(str::to_string),
        maybe: item.best_effort,
        observed: item.observed,
        flag: item.gate.map(|g| g.flag.to_string()),
        sent: item.gate.map(|g| sent_of(cat, &g, flag)),
        attrs: attrs_of(item.attrs, export)
            .map(|a| attr_out(cat, a.key, quoted(a), a, flag))
            .collect(),
    }
}

/// How a flag reads when it is off: the strongest change any of its gates makes.
fn off_of(gates: &[Gate], name: &str) -> Off {
    let mine = || gates.iter().filter(|g| g.flag == name);
    mine()
        .find(|g| matches!(g.off, Off::Redacted(_)))
        .or_else(|| mine().find(|g| matches!(g.off, Off::Omitted)))
        .or_else(|| mine().next())
        .map_or(Off::Omitted, |g| g.off)
}

fn gate_state(cat: &Catalog, f: &Flag, export: Export, off: Off, flag: Lookup) -> GateState {
    let label = f
        .labels
        .iter()
        .find(|(e, _)| *e == export)
        .map_or(f.label, |(_, l)| *l);
    let input = flag(f.name);
    let on = on_under(cat, f.rule, f.name, flag, 0);
    let raw = input.value.as_deref().unwrap_or("");
    let local = on && matches!(f.rule, Rule::RawAny) && is_file(raw) && !is_inline(raw);
    let (sent, state) = if local {
        let dir = raw.trim().strip_prefix("file:").unwrap_or("");
        (
            Sent::Local,
            format!(
                "kept on this machine ({}); only a pointer is sent",
                redact::text(dir)
            ),
        )
    } else if on {
        (Sent::Yes, "sent".to_string())
    } else {
        match off {
            Off::Redacted(s) => (Sent::Redacted, format!("sent as {s}")),
            Off::Generic(s) => (Sent::Generic, format!("replaced by \"{s}\"")),
            Off::Omitted => (Sent::No, "not sent".to_string()),
        }
    };
    let why = why_text(cat, f, &input, flag);
    GateState {
        flag: f.name.to_string(),
        label: label.to_string(),
        on,
        sent,
        value: input
            .value
            .as_deref()
            .map(|v| redact::value(f.name, &Value::from(v))),
        set_by: input.set_by,
        path: input.path.clone(),
        text: format!("{label}: {state}, because {why}"),
    }
}

fn set_text(name: &str, input: &FlagInput) -> String {
    let v = redact::value(name, &Value::from(input.value.as_deref().unwrap_or("")));
    match input.set_by {
        Some(o) => format!("{name} = {v} (set by {})", o.set_by()),
        None => format!("{name} = {v}"),
    }
}

fn why_text(cat: &Catalog, f: &Flag, input: &FlagInput, flag: Lookup) -> String {
    if input.value.is_some() {
        return set_text(f.name, input);
    }
    match f.rule {
        Rule::NotFalse => format!("{} is unset (on by default)", f.name),
        Rule::FallbackTo(other) => {
            let o = flag(other);
            if o.value.is_some() {
                format!("{} is unset, so it follows {}", f.name, set_text(other, &o))
            } else {
                let _ = cat;
                format!("{} is unset, so it follows {other}, which is unset", f.name)
            }
        }
        _ => format!("{} is unset", f.name),
    }
}

fn sample_line(cat: &Catalog, a: &Attr, key: &str, flag: Lookup) -> Option<String> {
    let mut shown = match a.value {
        Some(v) => format!("\"{v}\""),
        None => format!("<{}>", a.what),
    };
    let mut suffix = String::new();
    if let Some(g) = a.gate {
        if gate_on(cat, &g, flag) {
            suffix = format!("   (sent: {})", g.flag);
        } else {
            match g.off {
                Off::Omitted => return None,
                Off::Redacted(s) => shown = s.to_string(),
                Off::Generic(s) => shown = format!("\"{s}\""),
            }
        }
    }
    Some(format!("  {key} = {shown}{suffix}"))
}

fn sample_of(cat: &Catalog, export: Export, flag: Lookup, extra: &[String]) -> Vec<String> {
    let mut out = vec!["resource:".to_string()];
    out.extend(attrs_of(cat.resource, export).filter_map(|a| sample_line(cat, a, a.key, flag)));
    let Some(item) = items_of(cat, export).find(|i| i.sample) else {
        return out;
    };
    out.push(format!("{}:", item.name));
    for a in attrs_of(cat.identity, export) {
        if a.key == "*" {
            out.extend(extra.iter().filter_map(|n| sample_line(cat, a, n, flag)));
        } else {
            out.extend(sample_line(cat, a, a.key, flag));
        }
    }
    for a in attrs_of(cat.common, export).chain(attrs_of(item.attrs, export)) {
        out.extend(sample_line(cat, a, a.key, flag));
    }
    out
}

fn docs_of(cat: &Catalog, export: Export) -> String {
    let page = cat.doc.split('#').next().unwrap_or(cat.doc);
    match (cat.vendor, export) {
        (Vendor::ClaudeCode, Export::Logs) => format!("{page}#events"),
        (Vendor::ClaudeCode, Export::Metrics) => format!("{page}#metrics"),
        (Vendor::ClaudeCode, Export::Traces | Export::Beta) => format!("{page}#span-attributes"),
        (Vendor::Codex, Export::Metrics) => format!("{page}#otel-metrics-emitted"),
        (Vendor::Codex, _) => cat.doc.to_string(),
    }
}

/// What `export` carries, for the flags `flag` resolves. `extra_identity` names the attributes
/// `OTEL_RESOURCE_ATTRIBUTES` adds (names only).
pub fn build(cat: &Catalog, export: Export, flag: Lookup, extra_identity: &[String]) -> Payload {
    let all = gates_of(cat, export, extra_identity);
    let gates: Vec<GateState> = cat
        .flags
        .iter()
        .filter(|f| all.iter().any(|g| g.flag == f.name))
        .map(|f| gate_state(cat, f, export, off_of(&all, f.name), flag))
        .collect();
    let records: Vec<RecordOut> = items_of(cat, export)
        .map(|i| record_out(cat, i, export, flag))
        .collect();
    let maybe = export == Export::Beta || (!records.is_empty() && records.iter().all(|r| r.maybe));
    Payload {
        export,
        catalog: cat.label(),
        docs: docs_of(cat, export),
        maybe,
        gates,
        identity: identity_out(cat, export, flag, extra_identity),
        resource: attrs_of(cat.resource, export)
            .map(|a| attr_out(cat, a.key, quoted(a), a, flag))
            .collect(),
        records,
        sample: sample_of(cat, export, flag, extra_identity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::otel_catalog::{CLAUDE_CODE, CODEX};
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> FlagInput {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |n| match m.get(n) {
            Some(v) => FlagInput {
                value: Some(v.clone()),
                set_by: Some(Origin::Mdm),
                path: Some(format!("mdm:{n}")),
            },
            None => FlagInput::default(),
        }
    }

    fn gate<'a>(p: &'a Payload, name: &str) -> &'a GateState {
        p.gates.iter().find(|g| g.flag == name).unwrap()
    }

    #[test]
    fn truthy_set_and_unset() {
        let p = build(
            &CLAUDE_CODE,
            Export::Logs,
            &lookup(&[("OTEL_LOG_USER_PROMPTS", "1")]),
            &[],
        );
        let g = gate(&p, "OTEL_LOG_USER_PROMPTS");
        assert!(g.on && g.sent == Sent::Yes && g.set_by == Some(Origin::Mdm));
        assert_eq!(
            g.text,
            "Prompt text: sent, because OTEL_LOG_USER_PROMPTS = 1 (set by organization (MDM profile))"
        );
        let g = gate(&p, "OTEL_LOG_TOOL_DETAILS");
        assert!(!g.on && g.sent == Sent::No && g.value.is_none());
        assert_eq!(
            g.text,
            "Full shell commands, tool input, and MCP, skill and plugin names: not sent, because OTEL_LOG_TOOL_DETAILS is unset"
        );
    }

    #[test]
    fn truthy_set_to_zero_is_off() {
        let p = build(
            &CLAUDE_CODE,
            Export::Logs,
            &lookup(&[("OTEL_LOG_USER_PROMPTS", "0")]),
            &[],
        );
        let g = gate(&p, "OTEL_LOG_USER_PROMPTS");
        assert!(!g.on && g.sent == Sent::Redacted);
        assert_eq!(
            g.text,
            "Prompt text: sent as <REDACTED>, because OTEL_LOG_USER_PROMPTS = 0 (set by organization (MDM profile))"
        );
    }

    #[test]
    fn not_false_is_on_by_default() {
        let p = build(&CLAUDE_CODE, Export::Metrics, &lookup(&[]), &[]);
        let g = gate(&p, "OTEL_METRICS_INCLUDE_SESSION_ID");
        assert!(g.on && g.sent == Sent::Yes);
        assert_eq!(
            g.text,
            "Session ID on metrics: sent, because OTEL_METRICS_INCLUDE_SESSION_ID is unset (on by default)"
        );
        let p = build(
            &CLAUDE_CODE,
            Export::Metrics,
            &lookup(&[("OTEL_METRICS_INCLUDE_SESSION_ID", "FALSE")]),
            &[],
        );
        assert!(!gate(&p, "OTEL_METRICS_INCLUDE_SESSION_ID").on);
        let sid = p.identity.iter().find(|a| a.key == "session.id").unwrap();
        assert_eq!(sid.sent, Some(Sent::No));
        assert_eq!(sid.flag.as_deref(), Some("OTEL_METRICS_INCLUDE_SESSION_ID"));
    }

    #[test]
    fn fallback_follows_the_other_flag() {
        let p = build(
            &CLAUDE_CODE,
            Export::Logs,
            &lookup(&[("OTEL_LOG_USER_PROMPTS", "1")]),
            &[],
        );
        let g = gate(&p, "OTEL_LOG_ASSISTANT_RESPONSES");
        assert!(g.on);
        assert_eq!(
            g.text,
            "Claude's response text: sent, because OTEL_LOG_ASSISTANT_RESPONSES is unset, so it follows OTEL_LOG_USER_PROMPTS = 1 (set by organization (MDM profile))"
        );
        let p = build(
            &CLAUDE_CODE,
            Export::Logs,
            &lookup(&[
                ("OTEL_LOG_USER_PROMPTS", "1"),
                ("OTEL_LOG_ASSISTANT_RESPONSES", "0"),
            ]),
            &[],
        );
        assert!(!gate(&p, "OTEL_LOG_ASSISTANT_RESPONSES").on);
        let p = build(&CLAUDE_CODE, Export::Logs, &lookup(&[]), &[]);
        let g = gate(&p, "OTEL_LOG_ASSISTANT_RESPONSES");
        assert!(!g.on && g.sent == Sent::Redacted);
        assert!(
            g.text
                .ends_with("so it follows OTEL_LOG_USER_PROMPTS, which is unset")
        );
    }

    #[test]
    fn raw_bodies_inline_file_and_off() {
        let at = |v: &[(&str, &str)]| build(&CLAUDE_CODE, Export::Logs, &lookup(v), &[]);
        let p = at(&[("OTEL_LOG_RAW_API_BODIES", "1")]);
        let g = gate(&p, "OTEL_LOG_RAW_API_BODIES");
        assert!(g.on && g.sent == Sent::Yes);
        let body = p
            .records
            .iter()
            .find(|r| r.name == "claude_code.api_request_body")
            .unwrap();
        assert_eq!(body.sent, Some(Sent::Yes));
        let attr = |k: &str| body.attrs.iter().find(|a| a.key == k).unwrap().sent;
        assert_eq!(attr("body"), Some(Sent::Yes));
        assert_eq!(attr("body_ref"), Some(Sent::No));

        let p = at(&[("OTEL_LOG_RAW_API_BODIES", "file:/tmp/acme-bodies")]);
        let g = gate(&p, "OTEL_LOG_RAW_API_BODIES");
        assert!(g.on && g.sent == Sent::Local);
        assert!(
            g.text
                .contains("kept on this machine (/tmp/acme-bodies); only a pointer is sent")
        );
        let body = p
            .records
            .iter()
            .find(|r| r.name == "claude_code.api_request_body")
            .unwrap();
        let attr = |k: &str| body.attrs.iter().find(|a| a.key == k).unwrap().sent;
        assert_eq!(attr("body"), Some(Sent::No));
        assert_eq!(attr("body_ref"), Some(Sent::Yes));

        let p = at(&[("OTEL_LOG_RAW_API_BODIES", "maybe")]);
        let g = gate(&p, "OTEL_LOG_RAW_API_BODIES");
        assert!(!g.on && g.sent == Sent::No);
        assert!(
            g.text
                .starts_with("Full model requests and responses, the whole conversation: not sent")
        );
    }

    #[test]
    fn toml_flags_use_the_redacted_off_string() {
        let p = build(
            &CODEX,
            Export::Logs,
            &lookup(&[("otel.log_user_prompt", "false")]),
            &[],
        );
        let g = gate(&p, "otel.log_user_prompt");
        assert!(!g.on && g.sent == Sent::Redacted);
        assert!(g.text.contains("sent as [REDACTED]"));
        let g = gate(&p, "otel.log_agent_responses");
        assert_eq!(g.sent, Sent::No);
        let p = build(
            &CODEX,
            Export::Logs,
            &lookup(&[("otel.log_agent_responses", "true")]),
            &[],
        );
        assert!(gate(&p, "otel.log_agent_responses").on);
    }

    #[test]
    fn codex_traces_are_maybe_and_resource_attributes_follow_the_gate() {
        let p = build(&CODEX, Export::Traces, &lookup(&[]), &[]);
        assert!(p.maybe);
        let p = build(&CLAUDE_CODE, Export::Beta, &lookup(&[]), &[]);
        assert!(p.maybe);
        let p = build(&CLAUDE_CODE, Export::Logs, &lookup(&[]), &[]);
        assert!(!p.maybe);
        let names = ["team".to_string()];
        let p = build(&CLAUDE_CODE, Export::Metrics, &lookup(&[]), &names);
        let a = p.identity.iter().find(|a| a.key == "team").unwrap();
        assert_eq!(a.sent, Some(Sent::Yes));
        assert_eq!(a.what, "set by OTEL_RESOURCE_ATTRIBUTES");
        assert!(!p.identity.iter().any(|a| a.key == "*"));
        let p = build(&CLAUDE_CODE, Export::Metrics, &lookup(&[]), &[]);
        assert!(!p.identity.iter().any(|a| a.key == "*"));
    }

    #[test]
    fn sample_has_resource_then_one_record() {
        let p = build(
            &CLAUDE_CODE,
            Export::Logs,
            &lookup(&[("OTEL_LOG_TOOL_DETAILS", "1")]),
            &[],
        );
        assert_eq!(p.sample[0], "resource:");
        assert!(
            p.sample
                .contains(&"  service.name = \"claude-code\"".to_string())
        );
        assert!(p.sample.contains(&"claude_code.tool_result:".to_string()));
        let tp = p
            .sample
            .iter()
            .find(|l| l.contains("tool_parameters"))
            .unwrap();
        assert!(tp.ends_with("   (sent: OTEL_LOG_TOOL_DETAILS)"));
        assert!(
            p.sample
                .iter()
                .any(|l| l.starts_with("  user.email = <your account email"))
        );
        let p = build(&CLAUDE_CODE, Export::Logs, &lookup(&[]), &[]);
        assert!(!p.sample.iter().any(|l| l.contains("tool_parameters")));
        // never a raw value
        assert!(p.sample.iter().all(|l| !l.contains("sk-")));
    }

    #[test]
    fn identity_carries_its_condition() {
        let p = build(&CLAUDE_CODE, Export::Logs, &lookup(&[]), &[]);
        let id = |k: &str| p.identity.iter().find(|a| a.key == k).unwrap();
        assert_eq!(id("user.email").when, None);
        assert_eq!(id("session.id").when, None);
        assert_eq!(id("ccr.session.id").when.as_deref(), Some("cloud sessions"));
        assert_eq!(
            id("user.groups").when.as_deref(),
            Some("Claude apps gateway sessions")
        );
        assert_eq!(
            id("vcs.owner.name").when.as_deref(),
            Some("inside a git repository")
        );
        assert!(id("app.version").maybe);
        let p = build(&CLAUDE_CODE, Export::Metrics, &lookup(&[]), &[]);
        let ccr = p
            .identity
            .iter()
            .find(|a| a.key == "ccr.session.id")
            .unwrap();
        assert_eq!(ccr.when.as_deref(), Some("cloud sessions"));
        let json = serde_json::to_string(&p.identity[0]).unwrap();
        assert!(!json.contains("\"when\""));
    }

    #[test]
    fn gate_labels_follow_the_export() {
        let label = |e: Export| {
            build(
                &CLAUDE_CODE,
                e,
                &lookup(&[("OTEL_LOG_TOOL_DETAILS", "1")]),
                &[],
            )
            .gates
            .iter()
            .find(|g| g.flag == "OTEL_LOG_TOOL_DETAILS")
            .map(|g| g.text.clone())
        };
        assert!(
            label(Export::Logs)
                .unwrap()
                .starts_with("Full shell commands, tool input")
        );
        assert!(
            label(Export::Traces)
                .unwrap()
                .starts_with("Full shell commands, tool input")
        );
        let m = label(Export::Metrics).unwrap();
        assert!(m.starts_with("Agent, MCP, skill and plugin names on metrics (no commands): sent"));
        assert!(!m.contains("shell command"));
        assert!(!label(Export::Beta).unwrap().contains("Full shell commands"));
    }

    #[test]
    fn only_flags_that_gate_something_in_the_export_are_listed() {
        let flags = |c: &Catalog, e: Export| -> Vec<String> {
            build(c, e, &lookup(&[]), &[])
                .gates
                .into_iter()
                .map(|g| g.flag)
                .collect()
        };
        let m = flags(&CLAUDE_CODE, Export::Metrics);
        assert!(!m.contains(&"OTEL_LOG_USER_PROMPTS".to_string()));
        assert!(!m.contains(&"OTEL_LOG_RAW_API_BODIES".to_string()));
        let t = flags(&CLAUDE_CODE, Export::Traces);
        assert!(!t.iter().any(|f| f.starts_with("OTEL_METRICS_INCLUDE")));
        assert!(
            !flags(&CODEX, Export::Traces)
                .iter()
                .any(|f| f.starts_with("otel."))
        );
        assert!(
            !flags(&CODEX, Export::Metrics)
                .iter()
                .any(|f| f.starts_with("otel."))
        );
    }

    #[test]
    fn the_custom_attributes_gate_needs_attributes() {
        let none = build(&CLAUDE_CODE, Export::Metrics, &lookup(&[]), &[]);
        assert!(
            !none
                .gates
                .iter()
                .any(|g| g.flag == "OTEL_METRICS_INCLUDE_RESOURCE_ATTRIBUTES")
        );
        let some = build(
            &CLAUDE_CODE,
            Export::Metrics,
            &lookup(&[]),
            &["team".into()],
        );
        assert!(
            some.gates
                .iter()
                .any(|g| g.flag == "OTEL_METRICS_INCLUDE_RESOURCE_ATTRIBUTES")
        );
    }
}
