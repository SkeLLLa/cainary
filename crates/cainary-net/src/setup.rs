//! The "point an agent at it" lines (design §8.7): `--help`, the text-mode startup note on
//! stderr, and `hello.setup`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub claude_code: Vec<String>,
    pub codex: Vec<String>,
    pub notes: Vec<String>,
    /// Takeover mode only: the instructions of design §16 (hosts lines, redirect, trust, undo).
    pub takeover: Option<Vec<String>>,
}

/// `endpoint` is the base URL of the first bound address (`http://[::1]:4318` under
/// `--listen ::1`), the same string as `hello.endpoint`.
pub fn setup(endpoint: &str) -> Setup {
    plain(endpoint)
}

fn plain(endpoint: &str) -> Setup {
    let e = endpoint;
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
        takeover: None,
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
    if let Some(lines) = &s.takeover {
        return lines.iter().map(|l| format!("{l}\n")).collect();
    }
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

/// What the takeover instructions are about.
pub struct Takeover<'a> {
    pub hosts: &'a [String],
    pub ca_path: &'a str,
    pub fingerprint: &'a str,
    pub port: u16,
    /// The port the exporter's URL uses (443): where the redirect points from.
    pub public_port: u16,
    pub v4: bool,
    pub v6: bool,
}

/// The takeover instructions (design §16.4, §16.7.5, §16.7.7), as lines. Printed, never run:
/// the program calls neither sudo, setcap, nft nor anything that edits `/etc/hosts`. Commands
/// are valid in fish and in sh.
pub fn takeover(t: &Takeover<'_>) -> Vec<String> {
    let mut l: Vec<String> = Vec::new();
    let p = t.port;
    let redirect = p != t.public_port;
    let mut step = 0;
    let mut next = || {
        step += 1;
        step
    };
    l.push("TLS takeover: read this first.".into());
    l.push("Nothing is forwarded. While this runs, your organization's collector receives nothing from this machine, and every other request to the listed host names fails.".into());
    l.push("Other programs that talk to these host names will fail their TLS handshake here; that is expected.".into());
    l.push(
        "The host names below are what you configured here, not an authenticated sender identity."
            .into(),
    );
    l.push(String::new());
    l.push(format!(
        "{}. Point the host names at loopback (add these lines to /etc/hosts as root):",
        next()
    ));
    for h in t.hosts {
        if t.v4 {
            l.push(format!("  127.0.0.1 {h}"));
        }
        if t.v6 {
            l.push(format!("  ::1 {h}"));
        }
    }
    if redirect {
        l.push(format!(
            "{}. Redirect port {} to {p}, for connections this machine makes to loopback (run these yourself; they are not run for you):",
            next(),
            t.public_port
        ));
        l.push("  sudo nft add table inet cainary_otel_debug".into());
        l.push("  sudo nft 'add chain inet cainary_otel_debug out { type nat hook output priority -100 ; }'".into());
        if t.v4 {
            l.push(format!("  sudo nft add rule inet cainary_otel_debug out oifname lo ip daddr 127.0.0.1 tcp dport {} redirect to :{p}", t.public_port));
        }
        if t.v6 {
            l.push(format!("  sudo nft add rule inet cainary_otel_debug out oifname lo ip6 daddr ::1 tcp dport {} redirect to :{p}", t.public_port));
        }
        l.push(format!("   Or listen on {} directly: install this binary in a root-owned directory such as /usr/bin and run `sudo setcap cap_net_bind_service=+ep /usr/bin/cainary-otel-debug`. A rebuilt or copied file loses the capability, and the program drops it right after binding. Never run it as root.", t.public_port));
    }
    l.push(format!("{}. Trust the certificate, for the exporting process only (never disable certificate verification):", next()));
    l.push(format!(
        "  Claude Code: env NODE_EXTRA_CA_CERTS={} claude",
        t.ca_path
    ));
    l.push(format!("  Codex: set SSL_CERT_FILE={} or CODEX_CA_CERTIFICATE={} for the codex process (see its documentation for which it honors)", t.ca_path, t.ca_path));
    l.push(format!("  Certificate SHA-256: {}", t.fingerprint));
    l.push(format!("{}. Start the exporting process after this certificate is published, and restart it after every run of this program: each run creates a new CA. Deleting the file does not revoke trust a process already loaded; `cainary-otel-debug --delete-ca` removes the file.", next()));
    if redirect {
        l.push(
            "Undo: remove the /etc/hosts lines, stop this program, and remove the redirect:".into(),
        );
        l.push("  sudo nft delete table inet cainary_otel_debug".into());
    } else {
        l.push("Undo: remove the /etc/hosts lines and stop this program.".into());
    }
    l.push("The restriction to these names is enforced by this program: it issues certificates only for them and completes a handshake only for them. The certificate also carries name constraints, but those cover subdomains and depend on the client enforcing them. Its key exists only in this process's memory, and it is never installed in a system trust store.".into());
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_real_endpoint() {
        let s = setup("http://127.0.0.1:4999");
        assert!(
            s.claude_code
                .contains(&"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4999".to_string())
        );
        assert!(s.codex[0].contains("http://127.0.0.1:4999/v1/logs"));
        assert!(text(&s).contains("4999"));
        assert!(!text(&s).contains("<port>"));
        let v6 = setup("http://[::1]:4999");
        assert!(v6.codex[0].contains("http://[::1]:4999/v1/logs"));
        assert!(
            v6.claude_code
                .iter()
                .any(|l| l == "OTEL_EXPORTER_OTLP_ENDPOINT=http://[::1]:4999")
        );
    }

    #[test]
    fn text_has_the_documented_sections() {
        let t = text(&setup("http://127.0.0.1:4318"));
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

#[cfg(test)]
mod takeover_tests {
    use super::*;

    fn t<'a>(hosts: &'a [String], port: u16, v6: bool) -> Takeover<'a> {
        Takeover {
            hosts,
            ca_path: "/home/u/.local/state/cainary/otel-debug-ca.pem",
            fingerprint: "ab",
            port,
            public_port: 443,
            v4: true,
            v6,
        }
    }

    #[test]
    fn lists_hosts_for_the_bound_families_only() {
        let hosts = vec!["otel.example-corp.test".to_string()];
        let both = takeover(&t(&hosts, 8443, true)).join("\n");
        assert!(
            both.contains("127.0.0.1 otel.example-corp.test")
                && both.contains("::1 otel.example-corp.test")
        );
        let v4 = takeover(&t(&hosts, 8443, false)).join("\n");
        assert!(!v4.contains("::1 otel") && !v4.contains("ip6 daddr"));
    }

    #[test]
    fn redirect_and_teardown_only_when_not_on_443() {
        let hosts = vec!["a.example.test".to_string()];
        let r = takeover(&t(&hosts, 8443, true)).join("\n");
        assert!(r.contains("tcp dport 443 redirect to :8443"));
        assert!(r.contains("sudo nft delete table inet cainary_otel_debug"));
        assert!(r.contains("/usr/bin/cainary-otel-debug") && !r.contains("command -v"));
        let direct = takeover(&t(&hosts, 443, true)).join("\n");
        assert!(!direct.contains("nft"));
    }

    fn numbered(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|l| l.split_once(". ").map(|(n, _)| n.to_string()))
            .filter(|n| n.len() == 1 && n.chars().all(|c| c.is_ascii_digit()))
            .collect()
    }

    #[test]
    fn steps_are_numbered_without_gaps_and_undo_matches_the_redirect() {
        let hosts = vec!["a.example.test".to_string()];
        let with = takeover(&t(&hosts, 8443, true));
        assert_eq!(numbered(&with), ["1", "2", "3", "4"]);
        let u = with.iter().position(|l| l.starts_with("Undo:")).unwrap();
        assert!(with[u].ends_with("remove the redirect:"));
        assert_eq!(
            with[u + 1],
            "  sudo nft delete table inet cainary_otel_debug"
        );
        // Listening on the public port directly: no redirect step, no redirect in the undo.
        let direct = takeover(&t(&hosts, 443, true));
        assert_eq!(numbered(&direct), ["1", "2", "3"]);
        let u = direct.iter().position(|l| l.starts_with("Undo:")).unwrap();
        assert_eq!(
            direct[u],
            "Undo: remove the /etc/hosts lines and stop this program."
        );
        assert!(
            !direct[u..]
                .iter()
                .any(|l| l.contains("redirect") && !l.contains("name constraints"))
        );
        assert!(!direct.iter().any(|l| l.contains("nft")));
    }

    #[test]
    fn carries_the_warning_the_trust_lines_and_the_lifecycle() {
        let hosts = vec!["a.example.test".to_string()];
        let s = takeover(&t(&hosts, 8443, true)).join("\n");
        for needle in [
            "Nothing is forwarded",
            "NODE_EXTRA_CA_CERTS=/home/u/.local/state/cainary/otel-debug-ca.pem",
            "SSL_CERT_FILE=",
            "CODEX_CA_CERTIFICATE=",
            "restart it after every run",
            "does not revoke",
            "--delete-ca",
            "never disable certificate verification",
            "Never run it as root",
        ] {
            assert!(s.contains(needle), "{needle}");
        }
        assert!(!s.to_lowercase().contains("private key:"));
        assert!(s.contains("Other programs that talk to these host names will fail their TLS handshake here; that is expected."));
        // The old over-promise is gone: the restriction is the program's, the constraints advisory.
        assert!(!s.contains("only trusted for the names above"));
        assert!(s.contains("depend on the client enforcing them"));
    }
}
