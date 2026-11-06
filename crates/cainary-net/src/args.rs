//! Argument parser for `cainary-otel-debug` (design §8.3). Parsed by hand, like `cainary`.

use crate::redflag::{self, Kind, Pattern, presets};
use crate::server;
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 4318;
/// `--tls` listens here unless `--port` says otherwise; a redirect maps 443 to it (design §16.7.5).
pub const DEFAULT_TLS_PORT: u16 = 8443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run(Box<Options>),
    ListPresets,
    /// `--delete-ca`: remove the takeover CA's certificate file and exit.
    DeleteCa,
    /// `--trust <target> [--dry-run] [--undo]` (design §17).
    Trust {
        target: TrustTarget,
        dry_run: bool,
        undo: bool,
        json: bool,
    },
    /// `--trust-status`.
    TrustStatus {
        json: bool,
    },
    Version,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub port: u16,
    /// Validated loopback addresses; empty means the defaults (127.0.0.1, then ::1).
    pub listen: Vec<String>,
    pub json: bool,
    pub show_values: bool,
    pub once: bool,
    pub log_file: Option<PathBuf>,
    pub log_max_mib: u64,
    pub log_keep: u32,
    /// `--red-flag` and `--red-flag-re`, in order. `--match-case` is already applied.
    pub patterns: Vec<Pattern>,
    /// `--match-case` names that weren't a CLI pattern: they must name a file pattern.
    pub file_match_case: Vec<String>,
    pub red_flags_file: Option<PathBuf>,
    pub presets: Vec<String>,
    pub no_default_red_flags: bool,
    pub exit_on_stdin_eof: bool,
    /// The first stdin line is the JSON config; implies `exit_on_stdin_eof` (design §14.7).
    pub config_stdin: bool,
    /// `--tls`: the endpoint takeover (design §16); needs the `tls` cargo feature to run.
    pub tls: bool,
    /// Validated, lowercased, deduplicated.
    pub tls_hosts: Vec<String>,
    /// The port the exporter's URL uses, when it isn't 443.
    pub tls_public_port: Option<u16>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            port: DEFAULT_PORT,
            listen: Vec::new(),
            json: false,
            show_values: false,
            once: false,
            log_file: None,
            log_max_mib: 10,
            log_keep: 3,
            patterns: Vec::new(),
            file_match_case: Vec::new(),
            red_flags_file: None,
            presets: Vec::new(),
            no_default_red_flags: false,
            exit_on_stdin_eof: false,
            config_stdin: false,
            tls: false,
            tls_hosts: Vec::new(),
            tls_public_port: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTarget {
    ClaudeCode,
    Codex,
}

/// A parse failure; `code` is the process exit code (2 for usage errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError {
    pub code: u8,
    pub message: String,
}

fn usage(message: impl Into<String>) -> ArgError {
    ArgError {
        code: 2,
        message: message.into(),
    }
}

fn number<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    flag: &str,
    v: &str,
    lo: T,
    hi: T,
) -> Result<T, ArgError> {
    match v.parse::<T>() {
        Ok(n) if n >= lo && n <= hi => Ok(n),
        _ => Err(usage(format!(
            "{flag} must be a number from {lo} to {hi}, not '{v}'"
        ))),
    }
}

fn split_pattern(flag: &str, v: &str) -> Result<(String, String), ArgError> {
    let Some((name, pat)) = v.split_once('=') else {
        return Err(usage(format!("{flag} needs <name>=<pattern>, not '{v}'")));
    };
    if !redflag::valid_name(name) {
        return Err(usage(format!(
            "red flag name '{name}' is invalid: use a-z, 0-9, '-' and '_' (up to 64 characters, starting with a letter or digit)"
        )));
    }
    if pat.is_empty() {
        return Err(usage(format!("red flag '{name}': the pattern is empty")));
    }
    Ok((name.to_string(), pat.to_string()))
}

pub fn parse(args: &[String]) -> Result<Action, ArgError> {
    let mut o = Options::default();
    let mut match_case: Vec<String> = Vec::new();
    let mut port_set = false;
    let mut delete_ca = false;
    let mut trust: Option<TrustTarget> = None;
    let mut dry_run = false;
    let mut undo = false;
    let mut trust_status = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || -> Result<String, ArgError> {
            match inline.clone().or_else(|| rest.next().cloned()) {
                Some(v) => Ok(v),
                None => Err(usage(format!("{flag} needs a value"))),
            }
        };
        let bare = inline.is_none();
        match flag {
            "--help" | "-h" if bare => return Ok(Action::Help),
            "--version" | "-V" if bare => return Ok(Action::Version),
            "--list-presets" if bare => return Ok(Action::ListPresets),
            "--json" if bare => o.json = true,
            "--show-values" if bare => o.show_values = true,
            "--once" if bare => o.once = true,
            "--exit-on-stdin-eof" if bare => o.exit_on_stdin_eof = true,
            "--config-stdin" if bare => {
                o.config_stdin = true;
                o.exit_on_stdin_eof = true;
            }
            "--no-default-red-flags" if bare => o.no_default_red_flags = true,
            "--port" => {
                o.port = number(flag, &value()?, 0u16, u16::MAX)?;
                port_set = true;
            }
            "--tls" if bare => o.tls = true,
            "--delete-ca" if bare => delete_ca = true,
            "--trust" => {
                let v = value()?;
                trust = Some(match v.as_str() {
                    "claude-code" => TrustTarget::ClaudeCode,
                    "codex" => TrustTarget::Codex,
                    _ => return Err(usage("--trust takes claude-code or codex")),
                });
            }
            "--dry-run" if bare => dry_run = true,
            "--undo" if bare => undo = true,
            "--trust-status" if bare => trust_status = true,
            "--tls-host" => {
                let h = value()?.to_ascii_lowercase();
                if !crate::host::valid_host(&h) {
                    return Err(usage(
                        "--tls-host needs a DNS name with at least two labels (no wildcard, no IP address, at most 253 bytes)",
                    ));
                }
                if !o.tls_hosts.contains(&h) {
                    if o.tls_hosts.len() >= crate::host::MAX_HOSTS {
                        return Err(usage("at most 32 --tls-host names"));
                    }
                    o.tls_hosts.push(h);
                }
            }
            "--tls-public-port" => {
                o.tls_public_port = Some(number(flag, &value()?, 1u16, u16::MAX)?)
            }
            "--listen" => {
                let v = value()?;
                server::check_listen(&v).map_err(usage)?;
                o.listen.push(v);
            }
            "--log-file" => o.log_file = Some(PathBuf::from(value()?)),
            "--log-max-mib" => o.log_max_mib = number(flag, &value()?, 1u64, 1024)?,
            "--log-keep" => o.log_keep = number(flag, &value()?, 0u32, 9)?,
            "--red-flag" | "--red-flag-re" => {
                let (name, pattern) = split_pattern(flag, &value()?)?;
                o.patterns.push(Pattern {
                    name,
                    kind: if flag == "--red-flag" {
                        Kind::Text
                    } else {
                        Kind::Regex
                    },
                    pattern,
                    case_sensitive: false,
                    preset: false,
                });
            }
            "--match-case" => match_case.push(value()?),
            "--red-flags" => o.red_flags_file = Some(PathBuf::from(value()?)),
            "--preset" => {
                let v = value()?;
                if presets::find(&v).is_none() {
                    return Err(usage(format!("unknown preset '{v}' (try --list-presets)")));
                }
                o.presets.push(v);
            }
            other if other.starts_with('-') => {
                return Err(usage(format!("unknown or misplaced option '{other}'")));
            }
            other => return Err(usage(format!("unexpected argument '{other}'"))),
        }
    }

    if delete_ca {
        return Ok(Action::DeleteCa);
    }
    if trust_status {
        if trust.is_some() || dry_run || undo {
            return Err(usage("--trust-status stands alone (with --json)"));
        }
        return Ok(Action::TrustStatus { json: o.json });
    }
    if let Some(target) = trust {
        if dry_run && target == TrustTarget::Codex {
            return Err(usage("--dry-run applies to --trust claude-code only"));
        }
        return Ok(Action::Trust {
            target,
            dry_run,
            undo,
            json: o.json,
        });
    }
    if dry_run || undo {
        return Err(usage(
            "--dry-run and --undo go with --trust <claude-code|codex>",
        ));
    }
    if o.tls && o.tls_hosts.is_empty() {
        return Err(usage("--tls needs at least one --tls-host <name>"));
    }
    if !o.tls && (!o.tls_hosts.is_empty() || o.tls_public_port.is_some()) {
        return Err(usage("--tls-host and --tls-public-port need --tls"));
    }
    if o.tls && !port_set {
        o.port = DEFAULT_TLS_PORT;
    }
    for (i, p) in o.patterns.iter().enumerate() {
        if o.patterns[..i].iter().any(|q| q.name == p.name) {
            return Err(usage(format!(
                "red flag '{}' is defined more than once",
                p.name
            )));
        }
        if presets::find(&p.name).is_some() {
            return Err(usage(format!(
                "red flag '{}' has the name of a preset; pick another",
                p.name
            )));
        }
    }
    for name in match_case {
        match o.patterns.iter_mut().find(|p| p.name == name) {
            Some(p) => p.case_sensitive = true,
            // May be defined in the --red-flags file; checked once that is loaded.
            None if o.red_flags_file.is_some() && redflag::valid_name(&name) => {
                o.file_match_case.push(name);
            }
            None => {
                return Err(usage(format!(
                    "--match-case names '{name}', which no --red-flag or --red-flag-re defines"
                )));
            }
        }
    }
    Ok(Action::Run(Box::new(o)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(a: &[&str]) -> Result<Options, ArgError> {
        let args: Vec<String> = a.iter().map(|s| s.to_string()).collect();
        match parse(&args)? {
            Action::Run(o) => Ok(*o),
            other => panic!("expected Run, got {other:?}"),
        }
    }
    fn err(a: &[&str]) -> ArgError {
        run(a).unwrap_err()
    }

    #[test]
    fn defaults() {
        let o = run(&[]).unwrap();
        assert_eq!(o, Options::default());
        assert_eq!((o.port, o.log_max_mib, o.log_keep), (4318, 10, 3));
    }

    #[test]
    fn simple_commands() {
        let c = |a: &[&str]| parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(c(&["--version"]), Action::Version);
        assert_eq!(c(&["-V"]), Action::Version);
        assert_eq!(c(&["--help"]), Action::Help);
        assert_eq!(c(&["--json", "-h"]), Action::Help);
        assert_eq!(c(&["--list-presets"]), Action::ListPresets);
    }

    #[test]
    fn flags_and_values() {
        let o = run(&[
            "--port",
            "0",
            "--listen=127.0.0.2",
            "--listen",
            "::1",
            "--json",
            "--show-values",
            "--once",
            "--exit-on-stdin-eof",
            "--log-file=/tmp/x.jsonl",
            "--log-max-mib",
            "1024",
            "--log-keep=0",
            "--no-default-red-flags",
            "--preset",
            "ipv4",
            "--red-flags",
            "f.toml",
        ])
        .unwrap();
        assert_eq!(o.port, 0);
        assert_eq!(o.listen, vec!["127.0.0.2", "::1"]);
        assert!(o.json && o.show_values && o.once && o.exit_on_stdin_eof);
        assert_eq!(o.log_file, Some(PathBuf::from("/tmp/x.jsonl")));
        assert_eq!((o.log_max_mib, o.log_keep), (1024, 0));
        assert!(o.no_default_red_flags);
        assert_eq!(o.presets, vec!["ipv4"]);
        assert_eq!(o.red_flags_file, Some(PathBuf::from("f.toml")));
    }

    #[test]
    fn config_stdin_implies_the_lifeline() {
        let o = run(&["--config-stdin"]).unwrap();
        assert!(o.config_stdin && o.exit_on_stdin_eof);
        assert!(!run(&["--exit-on-stdin-eof"]).unwrap().config_stdin);
        assert_eq!(err(&["--config-stdin=1"]).code, 2);
    }

    #[test]
    fn number_ranges() {
        for bad in [
            &["--port", "65536"][..],
            &["--port", "-1"],
            &["--port", "x"],
            &["--log-max-mib", "0"],
            &["--log-max-mib", "1025"],
            &["--log-keep", "10"],
        ] {
            assert_eq!(err(bad).code, 2, "{bad:?}");
        }
        assert_eq!(err(&["--port"]).message, "--port needs a value");
    }

    #[test]
    fn listen_must_be_loopback() {
        for bad in [
            "0.0.0.0",
            "::",
            "192.168.1.1",
            "::ffff:127.0.0.1",
            "localhost",
            "8.8.8.8",
        ] {
            let e = err(&["--listen", bad]);
            assert_eq!(e.code, 2, "{bad}");
        }
        assert_eq!(
            err(&["--listen", "0.0.0.0"]).message,
            "refusing to listen on 0.0.0.0: only loopback addresses (127.0.0.0/8, ::1)"
        );
        assert!(run(&["--listen", "127.9.9.9"]).is_ok());
    }

    #[test]
    fn red_flags_and_match_case() {
        let o = run(&[
            "--red-flag",
            "customer=acme=internal",
            "--red-flag-re=db=\\bdb-[0-9]+\\b",
            "--match-case",
            "customer",
        ])
        .unwrap();
        assert_eq!(o.patterns.len(), 2);
        assert_eq!(o.patterns[0].pattern, "acme=internal");
        assert_eq!(o.patterns[0].kind, Kind::Text);
        assert!(o.patterns[0].case_sensitive);
        assert_eq!(o.patterns[1].kind, Kind::Regex);
        assert!(!o.patterns[1].case_sensitive);
    }

    #[test]
    fn red_flag_errors() {
        for bad in [
            &["--red-flag", "noequals"][..],
            &["--red-flag", "Bad=x"],
            &["--red-flag", "=x"],
            &["--red-flag", "a="],
            &["--red-flag", "a=x", "--red-flag-re", "a=y"],
            &["--red-flag", "email=x"],
            &["--match-case", "ghost"],
            &["--preset", "nope"],
        ] {
            assert_eq!(err(bad).code, 2, "{bad:?}");
        }
    }

    #[test]
    fn match_case_may_name_a_file_pattern() {
        let o = run(&["--red-flags", "f.toml", "--match-case", "from-file"]).unwrap();
        assert_eq!(o.file_match_case, vec!["from-file"]);
        assert_eq!(err(&["--match-case", "from-file"]).code, 2);
    }

    #[test]
    fn unknown_things() {
        assert!(err(&["--nope"]).message.contains("--nope"));
        assert!(err(&["stray"]).message.contains("stray"));
        assert_eq!(err(&["--json=1"]).code, 2);
        assert_eq!(err(&["--once=1"]).code, 2);
    }

    #[test]
    fn tls_flags() {
        let o = run(&[
            "--tls",
            "--tls-host",
            "Otel.Example-Corp.test",
            "--tls-host=otel.example-corp.test",
            "--tls-host",
            "b.example.test",
        ])
        .unwrap();
        assert!(o.tls);
        assert_eq!(
            o.tls_hosts,
            vec!["otel.example-corp.test", "b.example.test"]
        );
        assert_eq!(o.port, DEFAULT_TLS_PORT, "the takeover defaults to 8443");
        let o = run(&[
            "--tls",
            "--tls-host",
            "a.example.test",
            "--port",
            "443",
            "--tls-public-port",
            "8444",
        ])
        .unwrap();
        assert_eq!((o.port, o.tls_public_port), (443, Some(8444)));
        assert_eq!(run(&[]).unwrap().port, DEFAULT_PORT);
        assert_eq!(err(&["--tls"]).code, 2);
        assert_eq!(err(&["--tls-host", "a.example.test"]).code, 2);
        assert_eq!(err(&["--tls-public-port", "443"]).code, 2);
        assert_eq!(
            err(&[
                "--tls",
                "--tls-public-port",
                "0",
                "--tls-host",
                "a.example.test"
            ])
            .code,
            2
        );
        for bad in ["localhost", "*.example.com", "1.2.3.4", "a..b", "[::1]", ""] {
            assert_eq!(err(&["--tls", "--tls-host", bad]).code, 2, "{bad}");
        }
        let many: Vec<String> = (0..33)
            .flat_map(|i| ["--tls-host".to_string(), format!("h{i}.example.test")])
            .collect();
        let args: Vec<String> = ["--tls".to_string()].into_iter().chain(many).collect();
        assert_eq!(parse(&args).unwrap_err().code, 2);
        assert_eq!(
            parse(&["--delete-ca".to_string()]).unwrap(),
            Action::DeleteCa
        );
    }

    #[test]
    fn trust_flags() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            p(&["--trust", "claude-code"]).unwrap(),
            Action::Trust {
                target: TrustTarget::ClaudeCode,
                dry_run: false,
                undo: false,
                json: false
            }
        );
        assert_eq!(
            p(&["--trust=claude-code", "--dry-run", "--undo", "--json"]).unwrap(),
            Action::Trust {
                target: TrustTarget::ClaudeCode,
                dry_run: true,
                undo: true,
                json: true
            }
        );
        assert_eq!(
            p(&["--trust", "codex", "--undo"]).unwrap(),
            Action::Trust {
                target: TrustTarget::Codex,
                dry_run: false,
                undo: true,
                json: false
            }
        );
        assert_eq!(
            p(&["--trust-status", "--json"]).unwrap(),
            Action::TrustStatus { json: true }
        );
        for bad in [
            vec!["--trust", "nope"],
            vec!["--trust"],
            vec!["--trust", "codex", "--dry-run"],
            vec!["--dry-run"],
            vec!["--undo"],
            vec!["--trust-status", "--trust", "codex"],
            vec!["--trust-status", "--undo"],
        ] {
            assert_eq!(p(&bad).unwrap_err().code, 2, "{bad:?}");
        }
    }
}
