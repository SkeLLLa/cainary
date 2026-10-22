//! CLI argument parser (architecture.md §8). Parsed by hand: the grammar is small and the CLI
//! takes no dependencies.

use crate::status::Format;
use cainary_core::harness::platform::{EnvKind, Os};
use cainary_core::model::{AlertMode, App, Tool};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Scan {
        json: bool,
        summary: bool,
        since: Option<String>,
    },
    Status {
        format: Format,
    },
    Sources {
        json: bool,
    },
    Version,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Common {
    pub alert: AlertMode,
    /// Empty means no filter (all tools).
    pub tools: Vec<Tool>,
    pub fixture: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub os: Option<Os>,
    pub env_kind: EnvKind,
    pub no_color: bool,
}

impl Default for Common {
    fn default() -> Common {
        Common {
            alert: AlertMode::default(),
            tools: Vec::new(),
            fixture: None,
            root: None,
            home: None,
            os: None,
            env_kind: EnvKind::Shell,
            no_color: false,
        }
    }
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

/// Which command's flags are being parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Scan,
    Status,
    Sources,
}

pub fn parse(args: &[String]) -> Result<(Command, Common), ArgError> {
    let Some(first) = args.first() else {
        return Err(usage("missing command (scan, status, sources)"));
    };
    let kind = match first.as_str() {
        "--version" | "-V" => return Ok((Command::Version, Common::default())),
        "--help" | "-h" => return Ok((Command::Help, Common::default())),
        "scan" => Kind::Scan,
        "status" => Kind::Status,
        "sources" => Kind::Sources,
        other => return Err(usage(format!("unknown command '{other}'"))),
    };

    let mut common = Common::default();
    let mut json = false;
    let mut summary = false;
    let mut since = None;
    let mut format = Format::Emoji;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        // Split `--flag=value`; a bare `--flag` takes its value from the next argument.
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
        match flag {
            "--help" | "-h" if inline.is_none() => return Ok((Command::Help, common)),
            "--json" if kind != Kind::Status && inline.is_none() => json = true,
            "--summary" if kind == Kind::Scan && inline.is_none() => summary = true,
            "--since" if kind == Kind::Scan => since = Some(value()?),
            "--format" if kind == Kind::Status => {
                let v = value()?;
                format = match v.as_str() {
                    "emoji" => Format::Emoji,
                    "text" => Format::Text,
                    "nerd" => Format::Nerd,
                    "json" => Format::Json,
                    _ => return Err(usage(format!("unknown status format '{v}'"))),
                };
            }
            "--alert" => {
                let v = value()?;
                common.alert = AlertMode::parse(&v)
                    .ok_or_else(|| usage(format!("unknown alert mode '{v}'")))?;
            }
            "--tool" => {
                let v = value()?;
                let tools = match (App::from_slug(&v), Tool::from_slug(&v)) {
                    (Some(app), _) => app.tools(),
                    (None, Some(tool)) => vec![tool],
                    _ => return Err(usage(format!("unknown tool '{v}'"))),
                };
                for tool in tools {
                    if !common.tools.contains(&tool) {
                        common.tools.push(tool);
                    }
                }
            }
            "--fixture" => common.fixture = Some(PathBuf::from(value()?)),
            "--root" => common.root = Some(PathBuf::from(value()?)),
            "--home" => common.home = Some(PathBuf::from(value()?)),
            "--os" => {
                let v = value()?;
                common.os = Some(Os::parse(&v).ok_or_else(|| usage(format!("unknown os '{v}'")))?);
            }
            "--env-kind" => {
                let v = value()?;
                common.env_kind =
                    EnvKind::parse(&v).ok_or_else(|| usage(format!("unknown env kind '{v}'")))?;
            }
            "--no-color" if inline.is_none() => common.no_color = true,
            _ => return Err(usage(format!("unknown option '{arg}'"))),
        }
    }

    if common.fixture.is_some() && common.root.is_some() {
        return Err(usage("--fixture and --root can't be used together"));
    }
    if common.os.is_some() && common.fixture.is_none() && common.root.is_none() {
        return Err(usage("--os needs --root or --fixture"));
    }

    let command = match kind {
        Kind::Scan => Command::Scan {
            json,
            summary,
            since,
        },
        Kind::Status => Command::Status { format },
        Kind::Sources => Command::Sources { json },
    };
    Ok((command, common))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<(Command, Common), ArgError> {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&v)
    }

    fn err(args: &[&str]) -> String {
        let e = p(args).unwrap_err();
        assert_eq!(e.code, 2, "{args:?}");
        e.message
    }

    #[test]
    fn commands_and_defaults() {
        let (c, common) = p(&["scan"]).unwrap();
        assert_eq!(
            c,
            Command::Scan {
                json: false,
                summary: false,
                since: None
            }
        );
        assert_eq!(common, Common::default());
        assert_eq!(common.alert, AlertMode::OrgUnknown);
        assert_eq!(common.env_kind, EnvKind::Shell);
        assert_eq!(
            p(&["status"]).unwrap().0,
            Command::Status {
                format: Format::Emoji
            }
        );
        assert_eq!(p(&["sources"]).unwrap().0, Command::Sources { json: false });
    }

    #[test]
    fn version_and_help() {
        assert_eq!(p(&["--version"]).unwrap().0, Command::Version);
        assert_eq!(p(&["-V"]).unwrap().0, Command::Version);
        assert_eq!(p(&["--help"]).unwrap().0, Command::Help);
        assert_eq!(p(&["-h"]).unwrap().0, Command::Help);
        assert_eq!(p(&["scan", "--help"]).unwrap().0, Command::Help);
    }

    #[test]
    fn json_flag() {
        assert_eq!(
            p(&["scan", "--json"]).unwrap().0,
            Command::Scan {
                json: true,
                summary: false,
                since: None
            }
        );
        assert_eq!(
            p(&["sources", "--json"]).unwrap().0,
            Command::Sources { json: true }
        );
        assert!(err(&["status", "--json"]).contains("--json"));
        assert!(err(&["scan", "--json=1"]).contains("--json=1"));
    }

    #[test]
    fn since_flag() {
        let since = |a: &[&str]| match p(a).unwrap().0 {
            Command::Scan { since, .. } => since,
            _ => unreachable!(),
        };
        assert_eq!(since(&["scan"]), None);
        assert_eq!(
            since(&["scan", "--since", "b.json"]).as_deref(),
            Some("b.json")
        );
        assert_eq!(
            since(&["scan", "--since=-", "--summary"]).as_deref(),
            Some("-")
        );
        assert!(err(&["scan", "--since"]).contains("needs a value"));
        assert!(err(&["status", "--since", "b.json"]).contains("--since"));
    }
    #[test]
    fn summary_flag() {
        assert_eq!(
            p(&["scan", "--summary"]).unwrap().0,
            Command::Scan {
                json: false,
                summary: true,
                since: None
            }
        );
        assert!(err(&["status", "--summary"]).contains("--summary"));
        assert!(err(&["sources", "--summary"]).contains("--summary"));
    }

    #[test]
    fn status_formats() {
        for (s, f) in [
            ("emoji", Format::Emoji),
            ("text", Format::Text),
            ("nerd", Format::Nerd),
            ("json", Format::Json),
        ] {
            assert_eq!(
                p(&["status", "--format", s]).unwrap().0,
                Command::Status { format: f }
            );
            let eq = format!("--format={s}");
            assert_eq!(
                p(&["status", &eq]).unwrap().0,
                Command::Status { format: f }
            );
        }
        assert!(err(&["status", "--format", "level"]).contains("level"));
        assert!(err(&["scan", "--format", "text"]).contains("--format"));
    }

    #[test]
    fn alert_modes_and_aliases() {
        for (s, m) in [
            ("org", AlertMode::Org),
            ("org-unknown", AlertMode::OrgUnknown),
            ("everything", AlertMode::Everything),
            ("relaxed", AlertMode::Org),
            ("balanced", AlertMode::OrgUnknown),
            ("paranoid", AlertMode::Everything),
        ] {
            assert_eq!(p(&["scan", "--alert", s]).unwrap().1.alert, m, "{s}");
            let eq = format!("--alert={s}");
            assert_eq!(p(&["scan", &eq]).unwrap().1.alert, m, "{s}");
        }
        assert!(err(&["scan", "--alert", "loud"]).contains("loud"));
    }

    #[test]
    fn tool_accumulates() {
        let (_, c) = p(&[
            "scan",
            "--tool",
            "codex",
            "--tool=cursor",
            "--tool",
            "codex",
        ])
        .unwrap();
        assert_eq!(c.tools, [Tool::Codex, Tool::Cursor]);
        let (_, c) = p(&["scan", "--tool", "device"]).unwrap();
        assert_eq!(c.tools, [Tool::Device]);
        let (_, c) = p(&[
            "scan",
            "--tool",
            "claude",
            "--tool",
            "claude-code",
            "--tool",
            "openai",
        ])
        .unwrap();
        assert_eq!(
            c.tools,
            [
                Tool::ClaudeCode,
                Tool::ClaudeDesktop,
                Tool::Codex,
                Tool::Chatgpt
            ]
        );
        assert!(err(&["scan", "--tool", "vim"]).contains("vim"));
    }

    #[test]
    fn fixture_and_roots() {
        let (_, c) = p(&["scan", "--fixture", "fx/a"]).unwrap();
        assert_eq!(c.fixture, Some(PathBuf::from("fx/a")));
        let (_, c) = p(&["scan", "--fixture=fx/a", "--os", "linux"]).unwrap();
        assert_eq!(c.os, Some(Os::Linux));

        let (_, c) = p(&["sources", "--root", "/r", "--home=/r/home", "--os=macos"]).unwrap();
        assert_eq!(c.root, Some(PathBuf::from("/r")));
        assert_eq!(c.home, Some(PathBuf::from("/r/home")));
        assert_eq!(c.os, Some(Os::Macos));
        assert!(err(&["scan", "--os", "beos", "--root", "/r"]).contains("beos"));
    }

    #[test]
    fn os_needs_a_root() {
        assert!(err(&["scan", "--os", "linux"]).contains("--os"));
        assert!(err(&["status", "--os=macos"]).contains("--os"));
    }

    #[test]
    fn fixture_excludes_root() {
        assert!(err(&["scan", "--fixture", "a", "--root", "b"]).contains("together"));
        assert!(err(&["scan", "--root", "b", "--fixture", "a"]).contains("together"));
    }

    #[test]
    fn env_kind_and_no_color() {
        assert_eq!(
            p(&["scan", "--env-kind", "launchd"]).unwrap().1.env_kind,
            EnvKind::Launchd
        );
        assert_eq!(
            p(&["scan", "--env-kind=shell"]).unwrap().1.env_kind,
            EnvKind::Shell
        );
        assert!(err(&["scan", "--env-kind", "cron"]).contains("cron"));
        assert!(p(&["scan", "--no-color"]).unwrap().1.no_color);
        assert!(!p(&["scan"]).unwrap().1.no_color);
    }

    #[test]
    fn flags_combine_in_any_order() {
        let (c, common) = p(&[
            "status",
            "--no-color",
            "--format",
            "text",
            "--alert=org",
            "--tool",
            "chatgpt",
        ])
        .unwrap();
        assert_eq!(
            c,
            Command::Status {
                format: Format::Text
            }
        );
        assert!(common.no_color);
        assert_eq!(common.alert, AlertMode::Org);
        assert_eq!(common.tools, [Tool::Chatgpt]);
    }

    #[test]
    fn errors() {
        assert!(err(&[]).contains("missing command"));
        assert!(err(&["frobnicate"]).contains("frobnicate"));
        assert!(err(&["--json"]).contains("--json"));
        assert!(err(&["scan", "--bogus"]).contains("--bogus"));
        assert!(err(&["scan", "extra"]).contains("extra"));
        assert!(err(&["scan", "--tool"]).contains("needs a value"));
        assert!(err(&["scan", "--alert"]).contains("needs a value"));
        assert!(err(&["status", "--format"]).contains("needs a value"));
        assert!(err(&["scan", "--fixture"]).contains("needs a value"));
        assert!(err(&["scan", "--os"]).contains("needs a value"));
    }
}
