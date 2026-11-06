//! `cainary-otel-debug` (design §8): a local OTLP/JSON receiver for checking what an AI tool's
//! telemetry export carries. Reads the environment and owns the process exit; the rest lives
//! in the library.

use cainary_net::args::{self, Action, Options};
use cainary_net::redflag::{self, file, presets};
use cainary_net::server::{self, Config};
use cainary_net::{config, logfile, output, setup};
use std::io::{self, BufRead, Read};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

const USAGE: &str = "\
usage:
  cainary-otel-debug [--port <n>] [--listen <ip>]... [--json] [--show-values] [--once]
                     [--log-file <path> [--log-max-mib <n>] [--log-keep <n>]]
                     [--red-flag <name>=<text>]... [--red-flag-re <name>=<regex>]... [--match-case <name>]...
                     [--red-flags <file>] [--preset <name>]... [--no-default-red-flags] [--list-presets]
                     [--exit-on-stdin-eof] [--config-stdin]
  cainary-otel-debug --version | --help

A local OTLP/HTTP receiver, loopback only (127.0.0.1 and ::1), OTLP/JSON only (no protobuf, no
gzip). It never opens an outbound connection. Attribute values are masked unless --show-values.
Red flags (secrets, emails, your own words) raise `alert` lines; --list-presets shows the built-ins.
--red-flag values land in your shell history; GUIs use --config-stdin instead.

";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match std::panic::catch_unwind(|| run(&args)) {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            eprintln!("cainary-otel-debug: internal error");
            ExitCode::from(3)
        }
    }
}

fn run(args: &[String]) -> u8 {
    match args::parse(args) {
        Err(e) => {
            eprintln!("cainary-otel-debug: {}\n\n{USAGE}", e.message);
            e.code
        }
        Ok(Action::Version) => {
            println!("cainary-otel-debug {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Action::Help) => {
            print!(
                "{USAGE}{}",
                setup::text(&setup::setup(&format!(
                    "http://127.0.0.1:{}",
                    args::DEFAULT_PORT
                )))
            );
            0
        }
        Ok(Action::ListPresets) => {
            for p in presets::PRESETS {
                let on = if p.default_on { "on " } else { "off" };
                println!("{:<16} {on}  {}", p.name, p.regex);
            }
            0
        }
        Ok(Action::Run(o)) => serve(*o),
    }
}

/// Reads the config line (if asked), then keeps reading stdin as the lifeline: EOF means the
/// parent is gone, so exit. A separate thread, so nothing in the output path can delay it.
fn stdin_thread(config_line: bool) -> (mpsc::Receiver<Result<String, String>>, mpsc::Sender<()>) {
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut r = io::BufReader::new(io::stdin());
        if config_line {
            let mut buf = Vec::new();
            let limit = (config::MAX_CONFIG_BYTES + 1) as u64;
            let got = (&mut r).take(limit).read_until(b'\n', &mut buf);
            let line = match got {
                Ok(0) => Err("no config on stdin".to_string()),
                Ok(_) if buf.len() > config::MAX_CONFIG_BYTES => {
                    Err("config on stdin is over 1 MiB".to_string())
                }
                Ok(_) => {
                    String::from_utf8(buf).map_err(|_| "config on stdin isn't UTF-8".to_string())
                }
                Err(e) => Err(format!("can't read the config from stdin: {e}")),
            };
            let bad = line.is_err();
            let _ = tx.send(line);
            if bad {
                return;
            }
            // The lifeline starts once the config has been taken, so a parent that writes the
            // config and closes stdin still gets its config checked (and an exit code).
            if go_rx.recv().is_err() {
                return;
            }
        }
        let mut sink = [0u8; 4096];
        loop {
            match r.read(&mut sink) {
                Ok(0) | Err(_) => std::process::exit(0),
                Ok(_) => {}
            }
        }
    });
    (rx, go_tx)
}

fn fail(msg: impl std::fmt::Display, code: u8) -> u8 {
    eprintln!("cainary-otel-debug: {msg}");
    code
}

fn serve(o: Options) -> u8 {
    if o.show_values {
        let mut w = String::from(
            "warning: --show-values prints attribute values unmasked (emails, commands and any secrets in them)",
        );
        if let Some(p) = &o.log_file {
            w.push_str(&format!("; they are also written to {}", p.display()));
        }
        eprintln!("{w}");
    }

    let stdin = (o.exit_on_stdin_eof || o.config_stdin).then(|| stdin_thread(o.config_stdin));
    let mut configs = Vec::new();
    if let Some(path) = &o.red_flags_file {
        match file::load(path) {
            Ok(c) => configs.push(c),
            Err(e) => return fail(e.message(), e.code()),
        }
    }
    if o.config_stdin {
        let (rx, _) = stdin.as_ref().expect("the thread was started");
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(line)) => match config::parse(&line) {
                Ok(c) => configs.push(c),
                Err(m) => return fail(m, 2),
            },
            Ok(Err(m)) => return fail(m, 2),
            Err(_) => return fail("timed out waiting for the config on stdin", 2),
        }
    }
    let sel = redflag::Selection {
        no_default: o.no_default_red_flags,
        cli_presets: &o.presets,
        cli_patterns: &o.patterns,
        match_case: &o.file_match_case,
    };
    let matcher = match redflag::resolve(&sel, &configs) {
        Ok(m) => Arc::new(m),
        Err(e) => return fail(e.message, e.code),
    };

    if let Some((_, go)) = &stdin {
        let _ = go.send(());
    }
    let log = match &o.log_file {
        Some(p) => match logfile::LogFile::open(p, o.log_max_mib << 20, o.log_keep) {
            Ok(l) => Some(l),
            Err(m) => return fail(m, 1),
        },
        None => None,
    };

    let mut cfg = Config::new(Box::new(io::stdout()));
    cfg.listen = o.listen.clone();
    cfg.port = o.port;
    cfg.matcher = matcher;
    cfg.show_values = o.show_values;
    cfg.json = o.json;
    cfg.once = o.once;
    cfg.log = log;
    cfg.status = Box::new(io::stderr());
    let server = match server::run(cfg) {
        Ok(s) => s,
        Err(e) => return fail(e.message, e.code),
    };
    match server.wait() {
        output::End::Once | output::End::Closed => 0,
        // The reader went away (an orphaned child writing to a dead pipe): not an error.
        output::End::SinkFailed(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        output::End::SinkFailed(e) => fail(format!("can't write output: {e}"), 1),
    }
}
