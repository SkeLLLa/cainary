//! `cainary` binary (architecture.md §8): wire args → Harness → scan → render.

mod args;
mod status;
mod text;

use args::{Command, Common};
use cainary_core::diff;
use cainary_core::harness::Harness;
use cainary_core::harness::fs::{self, ReadError};
use cainary_core::harness::platform::Os;
use cainary_core::{ScanOptions, scan};
use serde_json::json;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
usage:
  cainary scan    [--json | --summary] [--since <baseline.json|->] [COMMON]
  cainary status  [--format emoji|text|nerd|json] [COMMON]
  cainary sources [--json] [COMMON]
  cainary --version | --help

COMMON:
  --alert org|org-unknown|everything   (aliases relaxed|balanced|paranoid)
  --tool <slug>                        (repeatable; default all)
  --fixture <dir> | --root <dir> --home <dir> [--os macos|linux]
  --env-kind shell|launchd
  --no-color

scan --summary prints only the status and the one-line-per-entry tables.
scan --since compares with an earlier `scan --json` (a file, or - for stdin) and lists the changes.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match std::panic::catch_unwind(|| run(&args)) {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            eprintln!("cainary: internal error");
            ExitCode::from(3)
        }
    }
}

fn run(args: &[String]) -> u8 {
    let (command, common) = match args::parse(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("cainary: {}\n\n{USAGE}", e.message);
            return e.code;
        }
    };
    match command {
        Command::Version => {
            println!("cainary {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Command::Help => {
            print!("{USAGE}");
            0
        }
        command => {
            let harness = match harness(&common) {
                Ok(h) => h,
                Err(msg) => {
                    eprintln!("cainary: {msg}");
                    return 1;
                }
            };
            let opts = ScanOptions {
                alert: common.alert,
                tools: common.tools.clone(),
            };
            let mut report = scan(&harness, &opts);
            if let Command::Scan {
                since: Some(src), ..
            } = &command
            {
                let baseline = read_baseline(&harness, src);
                diff::apply_since(&mut report, baseline.as_deref().map_err(String::clone));
            }
            let out = match command {
                Command::Scan { json: true, .. } => nl(serde_json::to_string_pretty(&report)),
                Command::Scan {
                    json: false,
                    summary,
                    ..
                } => text::render(&report, color(&common), summary, columns()),
                Command::Status { format } => format!("{}\n", status::render(&report, format)),
                Command::Sources { json: true } => nl(serde_json::to_string_pretty(
                    &json!({ "schema": cainary_core::model::SCHEMA, "sources": report.sources }),
                )),
                Command::Sources { json: false } => text::sources_tsv(&report),
                Command::Version | Command::Help => unreachable!(),
            };
            // A closed pipe (`| head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(out.as_bytes());
            0
        }
    }
}

fn nl(json: serde_json::Result<String>) -> String {
    let mut s = json.expect("report serializes");
    s.push('\n');
    s
}

fn color(common: &Common) -> bool {
    !common.no_color
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        && std::io::stdout().is_terminal()
}

fn harness(common: &Common) -> Result<Harness, String> {
    if let Some(dir) = &common.fixture {
        return Harness::from_fixture(dir);
    }
    if let Some(root) = &common.root {
        let home = common.home.as_deref().ok_or("--root needs --home")?;
        for dir in [root.as_path(), home] {
            if !Path::new(dir).is_dir() {
                return Err(format!("not a directory: {}", dir.display()));
            }
        }
        let os = common.os.unwrap_or_else(Os::host);
        return Ok(Harness::with_roots(root.clone(), home.to_path_buf(), os));
    }
    Ok(Harness::live(common.env_kind))
}

/// Terminal width for the summary column: `COLUMNS` if set to a number, else 100.
fn columns() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(100)
}

/// The baseline for `--since`: a file (read like any scanned file) or `-` for stdin, 1 MiB max.
fn read_baseline(harness: &Harness, src: &str) -> Result<Vec<u8>, String> {
    const CAP: u64 = fs::MAX_FILE_BYTES;
    if src == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(CAP + 1)
            .read_to_end(&mut buf)
            .map_err(|_| "baseline couldn't be read from stdin".to_string())?;
        if buf.len() as u64 > CAP {
            return Err("baseline is larger than 1 MiB".to_string());
        }
        return Ok(buf);
    }
    fs::read(harness.policy(), Path::new(src), CAP).map_err(|e| {
        match e {
            ReadError::Missing => "baseline file not found",
            ReadError::TooLarge => "baseline is larger than 1 MiB",
            ReadError::Denied => "baseline path is not allowed to be read",
            _ => "baseline couldn't be read",
        }
        .to_string()
    })
}
