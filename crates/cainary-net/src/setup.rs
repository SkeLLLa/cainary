//! The "point an agent at it" lines (design §8.7): `--help`, the text-mode startup note on
//! stderr, and `hello.setup`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub claude_code: Vec<String>,
    pub codex: Vec<String>,
    pub notes: Vec<String>,
}

pub fn setup(port: u16) -> Setup {
    let e = format!("http://127.0.0.1:{port}");
    Setup {
        claude_code: [
            "CLAUDE_CODE_ENABLE_TELEMETRY=1".to_string(),
            "OTEL_LOGS_EXPORTER=otlp".into(),
            "OTEL_METRICS_EXPORTER=otlp".into(),
            "OTEL_EXPORTER_OTLP_PROTOCOL=http/json".into(),
            format!("OTEL_EXPORTER_OTLP_ENDPOINT={e}"),
            "OTEL_LOGS_EXPORT_INTERVAL=1000".into(),
            "OTEL_METRIC_EXPORT_INTERVAL=10000".into(),
        ]
        .into(),
        codex: vec![
            format!("otel.exporter={{otlp-http={{endpoint=\"{e}/v1/logs\",protocol=\"json\"}}}}"),
            format!("otel.metrics_exporter={{otlp-http={{endpoint=\"{e}/v1/metrics\",protocol=\"json\"}}}}"),
            format!("otel.trace_exporter={{otlp-http={{endpoint=\"{e}/v1/traces\",protocol=\"json\"}}}}"),
        ],
        notes: vec![
            "Claude Code: an env block in ~/.claude/settings.json overwrites the same shell variable, and managed settings override both. A managed OTEL_EXPORTER_OTLP_ENDPOINT, _PROTOCOL or _HEADERS also removes your local endpoints, so Claude Code keeps sending to your organization's collector. A per-signal *_ENDPOINT overrides the general one. https://code.claude.com/docs/en/monitoring-usage#how-managed-settings-lock-the-otlp-destination".into(),
            "Codex: requirements.toml [otel] overrides config.toml.".into(),
            "`cainary scan` shows which of these your organization sets.".into(),
            "The collector is unauthenticated: any local process can post to it, so the stream shows what was received, and the vendor is inferred from the payload.".into(),
        ],
    }
}

/// The text block, from an already built `Setup` (so it carries the real port).
pub fn text(s: &Setup) -> String {
    let mut t = String::from("Point an agent at it.\n\nClaude Code (start it from this shell):\n");
    for l in &s.claude_code {
        t.push_str(&format!("  {l}\n"));
    }
    t.push_str("Codex (~/.codex/config.toml [otel], or one -c per line: codex -c '<line>' …):\n");
    for l in &s.codex {
        t.push_str(&format!("  {l}\n"));
    }
    t.push_str("\nSettings can override these:\n");
    for n in &s.notes {
        t.push_str(&format!("- {n}\n"));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_real_port() {
        let s = setup(4999);
        assert!(
            s.claude_code
                .contains(&"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4999".to_string())
        );
        assert!(s.codex[0].contains("http://127.0.0.1:4999/v1/logs"));
        assert!(text(&s).contains("4999"));
        assert!(!text(&s).contains("<port>"));
    }

    #[test]
    fn text_has_the_documented_sections() {
        let t = text(&setup(4318));
        for needle in [
            "Point an agent at it.",
            "Claude Code (start",
            "Codex (~/.codex",
            "Settings can override",
            "unauthenticated",
        ] {
            assert!(t.contains(needle), "{needle}");
        }
    }
}
