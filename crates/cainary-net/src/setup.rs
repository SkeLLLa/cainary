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
            "On Linux only programs run by your own user can send: connections from another local user are refused.".into(),
            "http/protobuf and gzip are accepted too; gRPC isn't.".into(),
            "If the exporting process uses HTTPS_PROXY, add 127.0.0.1, ::1 and localhost to its NO_PROXY, or the proxy gets the request instead of this collector.".into(),
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
    t.push_str("\nNotes:\n");
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
/// the program calls neither sudo, nft nor anything that edits `/etc/hosts`. Commands
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
    l.push("If the exporting process uses HTTPS_PROXY, add these host names to its NO_PROXY; otherwise the proxy resolves them itself and nothing arrives here.".into());
    l.push("Your organization's settings choose the format: OTLP over HTTP as JSON or protobuf, gzip or uncompressed, is read; gRPC is not.".into());
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

/// What the "can't bind a privileged port" note is about.
pub struct PortNote<'a> {
    pub port: u16,
    /// The running executable, when it could be found.
    pub exe: Option<&'a str>,
    /// The command-line arguments of this run, to show the run command with the same flags.
    pub args: &'a [String],
    pub linux: bool,
}

/// A word as both fish and bash read it: bare when plain, else in single quotes with each
/// single quote written `'\''` (close, an escaped quote, reopen), which both shells accept. A
/// control character can't be shown safely at all, so such a word becomes a placeholder.
pub fn quote(a: &str) -> String {
    let plain = !a.is_empty()
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if plain {
        return a.to_string();
    }
    if a.chars().any(char::is_control) {
        return "'<edit: this word contained control characters>'".to_string();
    }
    format!("'{}'", a.replace('\'', "'\\''"))
}

fn command(exe: &str, args: &[String]) -> String {
    std::iter::once(quote(exe))
        .chain(args.iter().map(|a| quote(a)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn digits(v: &str) -> bool {
    !v.is_empty() && v.len() <= 5 && v.bytes().all(|b| b.is_ascii_digit())
}

/// The arguments of this run, reduced to what is safe to show: flags that name no secret keep
/// their (validated) values; anything that can carry a pattern, a path or free text becomes a
/// placeholder, and anything unknown is dropped. Printed commands are copied into terminals and
/// bug reports, so a `--red-flag hidden=<value>` must never come back out.
pub fn safe_args(args: &[String]) -> Vec<String> {
    // flag → how its value is shown: Some(validator) keeps it, None replaces it by the placeholder.
    type Check = fn(&str) -> bool;
    const KEEP: [(&str, Check); 7] = [
        ("--port", digits),
        ("--tls-public-port", digits),
        ("--log-max-mib", digits),
        ("--log-keep", digits),
        ("--listen", |v| {
            !v.is_empty()
                && v.len() <= 45
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        }),
        ("--tls-host", crate::host::valid_host),
        ("--preset", |v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }),
    ];
    const HIDE: [(&str, &str); 5] = [
        ("--red-flag", "<name>=<pattern>"),
        ("--red-flag-re", "<name>=<pattern>"),
        ("--match-case", "<name>"),
        ("--red-flags", "<file>"),
        ("--log-file", "<path>"),
    ];
    const BARE: [&str; 8] = [
        "--json",
        "--show-values",
        "--once",
        "--tls",
        "--exit-on-stdin-eof",
        "--config-stdin",
        "--no-default-red-flags",
        "--list-presets",
    ];
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        if BARE.contains(&flag) && inline.is_none() {
            out.push(flag.to_string());
        } else if let Some((_, check)) = KEEP.iter().find(|(f, _)| *f == flag) {
            let v = inline.or_else(|| it.next().cloned());
            if let Some(v) = v.filter(|v| check(v)) {
                out.push(flag.to_string());
                out.push(v);
            }
        } else if let Some((_, placeholder)) = HIDE.iter().find(|(f, _)| *f == flag) {
            if inline.is_none() {
                it.next();
            }
            out.push(flag.to_string());
            out.push((*placeholder).to_string());
        }
    }
    out
}

/// `args` with the port set to `port` (replacing `--port <n>` / `--port=<n>`, adding it if absent).
fn with_port(args: &[String], port: u16) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--port" {
            it.next();
        } else if a.starts_with("--port=") {
        } else {
            out.push(a.clone());
        }
    }
    out.push("--port".into());
    out.push(port.to_string());
    out
}

/// The unprivileged port to suggest for `n`: `n + 8000` (443 gives 8443), or 8443 when that
/// doesn't fit.
pub fn alternative_port(n: u16) -> u16 {
    n.checked_add(8000).filter(|p| *p >= 1024).unwrap_or(8443)
}

/// The note printed (on stderr) after a refused bind to a privileged port: the ways to listen
/// on it, concrete for this run, in commands that work in fish and in bash. Printed, never run.
/// No option puts a capability on a file: the program never runs as root and is never given
/// `CAP_NET_BIND_SERVICE` by file.
pub fn privileged_port_note(n: &PortNote<'_>) -> Vec<String> {
    let port = n.port;
    let mut l = vec![format!(
        "Port {port} is privileged{}. Ways to listen on it, most to least recommended:",
        if n.linux { " on Linux" } else { "" }
    )];
    if !n.linux {
        l.clear();
        l.push(format!(
            "Port {port} needs a privilege on this system. Listen on a port from 1024 up (for example --port {}) and point the client there.",
            alternative_port(port)
        ));
        return l;
    }
    let exe = n.exe.unwrap_or("cainary-otel-debug");
    let args = safe_args(n.args);
    let alt = alternative_port(port);
    l.push("1. Listen on an unprivileged port (1024 and up) and point the client there:".into());
    l.push(format!("   {}", command(exe, &with_port(&args, alt))));
    l.push(format!(
        "2. In the cAInary tray, use \"Open port {port}\": an administrator approves once and the root helper cainary-bind-helper (from your distribution's package, or \"mise run linux:helper\" for a development build) hands this program the loopback sockets. Nothing is installed on this program, and it never runs as root."
    ));
    l.push(format!(
        "3. Administrators only: redirect {port} to that port, for connections this machine makes to loopback, both address families (run these yourself; they are not run for you):"
    ));
    l.push("   sudo nft add table inet cainary_port_redirect".into());
    l.push("   sudo nft 'add chain inet cainary_port_redirect out { type nat hook output priority -100 ; }'".into());
    l.push(format!("   sudo nft add rule inet cainary_port_redirect out oifname lo ip daddr 127.0.0.1 tcp dport {port} redirect to :{alt}"));
    l.push(format!("   sudo nft add rule inet cainary_port_redirect out oifname lo ip6 daddr ::1 tcp dport {port} redirect to :{alt}"));
    l.push("   To undo: sudo nft delete table inet cainary_port_redirect".into());
    l.push(format!("4. Administrators only, system-wide, the least recommended: every program on this machine can then listen on ports {port} and up."));
    l.push(format!(
        "   sudo sysctl net.ipv4.ip_unprivileged_port_start={port}"
    ));
    l.push("   To undo: sudo sysctl net.ipv4.ip_unprivileged_port_start=1024".into());
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
            "Notes:",
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
        assert!(!r.contains("setcap") && !r.contains("cap_net_bind_service"));
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

#[cfg(test)]
mod port_note_tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn note(port: u16, exe: Option<&str>, a: &[&str]) -> String {
        privileged_port_note(&PortNote {
            port,
            exe,
            args: &args(a),
            linux: true,
        })
        .join("\n")
    }

    #[test]
    fn no_option_puts_a_capability_on_a_file() {
        for exe in [Some("/usr/bin/x"), Some("/home/u/x"), None] {
            let n = note(443, exe, &["--port", "443"]);
            for bad in ["setcap", "cap_net_bind_service", "sudo install", "COPY"] {
                assert!(!n.contains(bad), "{bad}\n{n}");
            }
        }
    }

    #[test]
    fn the_helper_option_names_the_tray_and_the_helper() {
        let n = note(443, Some("/usr/bin/x"), &["--port", "443"]);
        assert!(n.contains("1. Listen on an unprivileged port"), "{n}");
        assert!(n.contains("/usr/bin/x --port 8443"), "{n}");
        assert!(n.contains("\"Open port 443\""), "{n}");
        assert!(n.contains("cainary-bind-helper") && n.contains("mise run linux:helper"));
        assert!(n.contains("3. Administrators only"));
        assert!(n.contains("4. Administrators only, system-wide"));
    }

    #[test]
    fn the_redirect_option_uses_the_alternative_port_and_both_families() {
        let n = note(443, Some("/usr/bin/x"), &["--port", "443", "--json"]);
        assert!(n.contains("/usr/bin/x --json --port 8443"), "{n}");
        assert!(n.contains("ip daddr 127.0.0.1 tcp dport 443 redirect to :8443"));
        assert!(n.contains("ip6 daddr ::1 tcp dport 443 redirect to :8443"));
        assert!(n.contains("oifname lo"));
        assert!(n.contains("sudo nft delete table inet cainary_port_redirect"));
        let n = note(80, Some("/usr/bin/x"), &["--port=80"]);
        assert!(n.contains("/usr/bin/x --port 8080"), "{n}");
        assert!(n.contains("tcp dport 80 redirect to :8080"));
        assert_eq!(alternative_port(443), 8443);
        assert_eq!(alternative_port(80), 8080);
        assert_eq!(alternative_port(1), 8001);
        assert_eq!(alternative_port(60000), 8443, "past 65535 falls back");
        assert_eq!(alternative_port(1000), 9000);
    }

    #[test]
    fn the_sysctl_option_names_the_risk_and_the_revert() {
        let n = note(443, Some("/usr/bin/x"), &[]);
        assert!(n.contains("sudo sysctl net.ipv4.ip_unprivileged_port_start=443"));
        assert!(n.contains("every program on this machine"));
        assert!(n.contains("sudo sysctl net.ipv4.ip_unprivileged_port_start=1024"));
    }

    #[test]
    fn commands_work_in_fish_and_bash() {
        let n = note(
            443,
            Some("/usr/bin/x"),
            &["--red-flag", "customer=acme corp", "--listen", "127.0.0.1"],
        );
        for bad in ["$(", "export ", "`", "<(", "[[", "; then", "&&"] {
            assert!(!n.contains(bad), "{bad:?} in {n}");
        }
        // Placeholders contain `<` and `>`, so they are single-quoted and read as one word.
        assert!(
            n.contains("--red-flag '<name>=<pattern>' --listen 127.0.0.1"),
            "{n}"
        );
        // The path is escaped like any printed path.
        let e = note(443, Some("/tmp/evil\u{1b}]52;c;AAAA\u{7}/x"), &[]);
        assert!(!e.contains('\u{1b}') && !e.contains('\u{7}'));
    }

    #[test]
    fn quoting_is_one_word_in_fish_and_bash() {
        assert_eq!(
            quote("/usr/bin/cainary-otel-debug"),
            "/usr/bin/cainary-otel-debug"
        );
        assert_eq!(quote("/home/my user/x"), "'/home/my user/x'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote("a;b"), "'a;b'");
        assert_eq!(quote("$(id)"), "'$(id)'");
        assert_eq!(quote("`id`"), "'`id`'");
        assert_eq!(quote("a\\b"), "'a\\b'");
        assert_eq!(quote(""), "''");
        assert!(quote("a\nb").contains("<edit"));
        assert!(quote("a\u{1b}b").contains("<edit"));
    }

    #[test]
    fn every_path_in_the_commands_is_quoted() {
        for exe in [
            "/home/my user/bin/x",
            "/tmp/a;touch pwned/x",
            "/tmp/it's/x",
            "/tmp/$(id)/x",
        ] {
            let q = quote(exe);
            let n = note(443, Some(exe), &["--json"]);
            assert!(
                n.contains(&format!("   {q} --json --port 8443\n")),
                "{exe}\n{n}"
            );
        }
    }

    #[test]
    fn secrets_in_the_arguments_never_come_back_out() {
        let a = [
            "--red-flag",
            "hidden=SECRET-VALUE",
            "--red-flag-re=db=SECRET-REGEX",
            "--match-case",
            "SECRET-NAME",
            "--red-flags",
            "/home/u/SECRET-FILE.toml",
            "--log-file=/home/u/SECRET-LOG.jsonl",
            "--port",
            "443",
            "--listen",
            "127.0.0.1",
            "--tls",
            "--tls-host",
            "otel.example-corp.test",
            "--json",
            "--tls-host",
            "SECRET-NOT-A-HOST",
            "--preset",
            "SECRET_PRESET",
            "stray-SECRET-positional",
            "--unknown=SECRET-UNKNOWN",
        ];
        let n = note(443, Some("/usr/bin/x"), &a);
        assert!(!n.contains("SECRET"), "{n}");
        // The safe flags are kept verbatim; the secret-bearing ones are placeholders.
        assert!(
            n.contains(
                "--port 443 --listen 127.0.0.1 --tls --tls-host otel.example-corp.test --json"
            ) || n.contains("--tls-host otel.example-corp.test"),
            "{n}"
        );
        assert!(
            n.contains("'<name>=<pattern>'")
                && n.contains("'<file>'")
                && n.contains("'<path>'")
                && n.contains("'<name>'"),
            "{n}"
        );
        let kept = safe_args(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(kept.contains(&"--port".to_string()) && kept.contains(&"443".to_string()));
        assert!(!kept.iter().any(|k| k.contains("SECRET")));
    }

    #[test]
    fn other_systems_get_one_plain_line() {
        let n = privileged_port_note(&PortNote {
            port: 443,
            exe: None,
            args: &[],
            linux: false,
        });
        assert_eq!(n.len(), 1);
        assert!(!n[0].contains("setcap") && !n[0].contains("nft"));
        assert!(n[0].contains("--port 8443"));
    }
}
