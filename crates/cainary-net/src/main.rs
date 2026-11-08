//! `cainary-otel-debug`: a local OTLP/HTTP receiver for checking what an AI tool's
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
  cainary-otel-debug [--port <n>] [--listen <ip>]... [--listen-fd <n>]... [--json] [--show-values] [--once] [--allow-root]
                     [--log-file <path> [--log-max-mib <n>] [--log-keep <n>]]
                     [--red-flag <name>=<text>]... [--red-flag-re <name>=<regex>]... [--match-case <name>]...
                     [--red-flags <file>] [--preset <name>]... [--no-default-red-flags] [--list-presets]
                     [--exit-on-stdin-eof] [--config-stdin]
                     [--tls --tls-host <name>... [--tls-public-port <n>]]
  cainary-otel-debug --trust claude-code [--dry-run] [--undo] [--json]
  cainary-otel-debug --trust codex [--undo] [--json]
  cainary-otel-debug --trust-status [--json]
  cainary-otel-debug --delete-ca
  cainary-otel-debug --version | --help

A local OTLP/HTTP receiver, loopback only (127.0.0.1 and ::1), JSON or protobuf, gzip or
uncompressed (no gRPC). It never opens an outbound connection. Attribute values are masked unless --show-values.
Red flags (secrets, emails, your own words) raise `alert` lines; --list-presets shows the built-ins.
--red-flag values land in your shell history; GUIs use --config-stdin instead.

--tls --tls-host <name> is the endpoint takeover, for a telemetry host your organization pins to
HTTPS (managed settings that a shell variable can't override). You point that name at loopback,
and this serves it with a certificate from a throwaway CA limited to the names you give. It
FORWARDS NOTHING: while it runs, your organization's collector receives nothing from this
machine, and every other request to those names fails. It listens on 8443 by default and prints
the 443 redirect, the /etc/hosts lines and how to trust the certificate; it never runs sudo,
or nft, and it needs a build with the `tls` cargo feature. `--delete-ca` removes the
certificate file it writes.

--trust claude-code sets one key, env.NODE_EXTRA_CA_CERTS, in ~/.claude/settings.json (after a
backup; --dry-run shows the change, --undo reverses it) so Claude Code trusts that certificate;
--trust codex writes a combined certificate bundle and prints the command that uses it. Neither
edits shell profiles or any system trust store, and --trust-status shows where things stand.

";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match std::panic::catch_unwind(|| run(&args)) {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            if wants_json(&args) {
                print!(
                    "{}",
                    output::error_line("startup", "internal", "internal error", None)
                );
            }
            eprintln!("cainary-otel-debug: internal error");
            ExitCode::from(3)
        }
    }
}

/// `--json` in the raw arguments, found before they are parsed: a usage error has to come out as
/// a JSON `error` line too, and parsing is what failed.
fn wants_json(args: &[String]) -> bool {
    args.iter().any(|a| a == "--json")
}

/// Everything but a receiver run never binds, so it gives up the bind capability at once.
fn drop_now(json: bool) -> Option<u8> {
    let dropped = cainary_net::privdrop::drop_capabilities();
    dropped.err().map(|e| {
        let msg = format!("can't drop capabilities: {e}");
        fatal(json, "startup", "privilege-drop", msg, 1)
    })
}

fn run(args: &[String]) -> u8 {
    let parsed = args::parse(args);
    if !matches!(parsed, Ok(Action::Run(_)))
        && let Some(code) = drop_now(wants_json(args))
    {
        return code;
    }
    match parsed {
        Err(e) => {
            if wants_json(args) {
                print!(
                    "{}",
                    output::error_line("startup", e.kind, &e.message, None)
                );
            }
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
        Ok(Action::DeleteCa) => delete_ca(),
        Ok(Action::Trust {
            target,
            dry_run,
            undo,
            json,
        }) => trust_cmd(target, dry_run, undo, json),
        Ok(Action::TrustStatus { json }) => trust_status_cmd(json),
        Ok(Action::ListPresets) => {
            for p in presets::PRESETS {
                let on = if p.default_on { "on " } else { "off" };
                println!("{:<16} {on}  {}", p.name, p.regex);
            }
            0
        }
        Ok(Action::Run(o)) => serve(*o, args),
    }
}

type Ack = mpsc::Receiver<Result<(), String>>;

/// Reads the config line (if asked), then keeps reading stdin as the lifeline: EOF means the
/// parent is gone, so exit. A separate thread, so nothing in the output path can delay it.
fn stdin_thread(
    config_line: bool,
) -> (
    mpsc::Receiver<Result<String, String>>,
    mpsc::Sender<()>,
    Ack,
) {
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (ack_tx, ack_rx) = mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        // This thread was started before the bind, so it inherited any bind capability: it has
        // no use for it. It drops its copy, verified, and says so; the main
        // thread won't bind or accept until it has heard. The bind thread drops its own right
        // after binding.
        let dropped = cainary_net::privdrop::drop_capabilities()
            .map_err(|e| format!("can't drop capabilities in the stdin thread: {e}"));
        let failed = dropped.is_err();
        let _ = ack_tx.send(dropped);
        if failed {
            return;
        }
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
    (rx, go_tx, ack_rx)
}

/// A refused bind to a privileged port: the error as a line (JSON on stdout under `--json`, text
/// on stderr otherwise), then the note on stderr with the ways to get the port (the
/// program prints these commands and never runs them).
fn refused_port(message: &str, port: u16, json: bool, args: &[String]) -> u8 {
    if json {
        print!(
            "{}",
            output::error_line("listen", "port-privileged", message, Some(port))
        );
    } else {
        eprintln!("cainary-otel-debug: {message}");
    }
    let exe = std::env::current_exe().ok();
    let shown = exe.as_ref().map(|e| e.display().to_string());
    let note = setup::privileged_port_note(&setup::PortNote {
        port,
        exe: shown.as_deref(),
        args,
        linux: cfg!(target_os = "linux"),
    });
    for line in note {
        eprintln!("{line}");
    }
    1
}

fn fail(msg: impl std::fmt::Display, code: u8) -> u8 {
    eprintln!("cainary-otel-debug: {msg}");
    code
}

/// A fatal startup failure of the receiver: the text on stderr as ever and, under `--json`,
/// exactly one `error` line with a stable `code` on stdout.
fn fatal(json: bool, source: &str, kind: &str, msg: impl std::fmt::Display, exit: u8) -> u8 {
    fatal_port(json, source, kind, msg, exit, None)
}

fn fatal_port(
    json: bool,
    source: &str,
    kind: &str,
    msg: impl std::fmt::Display,
    exit: u8,
    port: Option<u16>,
) -> u8 {
    let msg = msg.to_string();
    if json {
        print!("{}", output::error_line(source, kind, &msg, port));
    }
    fail(msg, exit)
}

#[cfg(not(feature = "tls"))]
const NO_TLS: &str = "this build has no TLS support (cargo feature `tls`)";

/// Where the takeover CA's public certificate lives: the state directory, so a
/// stable path survives restarts.
#[cfg(feature = "tls")]
fn ca_dir() -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;
    // A set but relative value is an error, not something to quietly skip: the directory is
    // the one the exporter is told to read, so it must be unambiguous.
    let absolute = |name: &str| -> Result<Option<PathBuf>, String> {
        match std::env::var_os(name) {
            None => Ok(None),
            Some(v) if PathBuf::from(&v).is_absolute() => Ok(Some(PathBuf::from(v))),
            Some(_) => Err(format!("{name} is not an absolute path")),
        }
    };
    let home = || absolute("HOME")?.ok_or_else(|| "HOME is not set".to_string());
    #[cfg(target_os = "macos")]
    {
        Ok(home()?.join("Library/Application Support/cAInary"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = match absolute("XDG_STATE_HOME")? {
            Some(p) => p,
            None => home()?.join(".local/state"),
        };
        Ok(base.join("cainary"))
    }
}

#[cfg(feature = "tls")]
fn delete_ca() -> u8 {
    use cainary_net::tls::ca_file;
    use cainary_net::trust;
    let dir = match ca_dir() {
        Ok(d) => d,
        Err(m) => return fail(m, 1),
    };
    // The trust that points at this CA is undone first, under the run lock; if that is refused
    // the CA stays (deleting it would leave a bundle or setting dangling).
    let (harness, trust_dir) = match trust_env() {
        Ok(e) => e,
        Err(m) => return fail(m, 1),
    };
    let env = trust::Env {
        harness: &harness,
        ca_dir: trust_dir,
    };
    let mut refused = false;
    let mut lines = Vec::new();
    let result = ca_file::delete_holding(&dir, |_| {
        let c = trust::undo_mode_everywhere_held(&env, trust::TAKEOVER);
        lines = c.lines;
        refused = !c.ok;
        // `Some` even with nothing to hold: the CA may go, and what is held stays until it has.
        c.ok.then_some(c.held)
    });
    for l in &lines {
        print!("{}", l.text());
    }
    if refused {
        eprintln!(
            "cainary-otel-debug: the certificate was kept: trust could not be undone (see above)"
        );
        return 1;
    }
    match result {
        Ok(true) => {
            println!("removed {}", dir.join(ca_file::CA_FILE).display());
            0
        }
        Ok(false) => {
            println!(
                "no certificate file at {}",
                dir.join(ca_file::CA_FILE).display()
            );
            0
        }
        Err(e) => fail(e, 1),
    }
}

#[cfg(not(feature = "tls"))]
fn delete_ca() -> u8 {
    fail(NO_TLS, 2)
}

#[cfg(feature = "tls")]
fn trust_env() -> Result<(cainary_core::harness::Harness, std::path::PathBuf), String> {
    use cainary_core::harness::Harness;
    use cainary_core::harness::platform::EnvKind;
    Ok((Harness::live(EnvKind::Shell), ca_dir()?))
}

#[cfg(feature = "tls")]
fn trust_cmd(target: args::TrustTarget, dry_run: bool, undo: bool, json: bool) -> u8 {
    use cainary_net::trust::{self, Mode, Target};
    let (harness, ca_dir) = match trust_env() {
        Ok(e) => e,
        Err(m) => return fail(m, 1),
    };
    let env = trust::Env {
        harness: &harness,
        ca_dir,
    };
    let line = match target {
        args::TrustTarget::ClaudeCode => {
            let mode = if undo {
                Mode::Undo { dry_run }
            } else {
                Mode::Apply { dry_run }
            };
            trust::claude_code(&env, mode)
        }
        args::TrustTarget::Codex => trust::codex(&env, undo),
    };
    debug_assert!(matches!(line.target, Target::ClaudeCode | Target::Codex));
    if json {
        print!(
            "{}",
            line.json(&cainary_core::value::rfc3339(harness.now()))
        );
    } else {
        print!("{}", line.text());
    }
    line.code()
}

#[cfg(feature = "tls")]
fn trust_status_cmd(json: bool) -> u8 {
    use cainary_net::trust;
    let (harness, ca_dir) = match trust_env() {
        Ok(e) => e,
        Err(m) => return fail(m, 1),
    };
    let env = trust::Env {
        harness: &harness,
        ca_dir,
    };
    if json {
        print!(
            "{}",
            trust::status_json(&env, &cainary_core::value::rfc3339(harness.now()))
        );
    } else {
        print!("{}", trust::status_text(&env));
    }
    0
}

#[cfg(not(feature = "tls"))]
fn trust_cmd(_: args::TrustTarget, _: bool, _: bool, _: bool) -> u8 {
    fail(NO_TLS, 2)
}

#[cfg(not(feature = "tls"))]
fn trust_status_cmd(_: bool) -> u8 {
    fail(NO_TLS, 2)
}

fn serve(o: Options, args: &[String]) -> u8 {
    #[cfg(not(feature = "tls"))]
    if o.tls {
        return fatal(o.json, "startup", "tls-unsupported", NO_TLS, 2);
    }
    // Before anything is read or parsed: refuse root, bind (the one step that may need the
    // capability) and drop it. Config, patterns, the log file and the TLS state all follow.
    if let Err(m) = cainary_net::privdrop::refuse_root(cainary_net::privdrop::euid(), o.allow_root)
    {
        return fatal(o.json, "startup", "privilege-drop", m, 1);
    }
    // Inherited descriptors are taken here, once each (args made the numbers distinct), before
    // any thread is started; from now on only the owned values exist.
    let mut inherited = Vec::new();
    for &n in &o.listen_fds {
        // SAFETY: `--listen-fd` names descriptors the parent placed for us; nothing else in
        // this process has used them, and no thread exists yet.
        match unsafe { cainary_net::listenfd::take_inherited(n) } {
            Ok(fd) => inherited.push(fd),
            Err(m) => return fatal(o.json, "startup", "listen-fd", m, 2),
        }
    }
    let ready =
        match server::bind(&o.listen, inherited, o.port).and_then(server::Bound::drop_privileges) {
            Ok(r) => r,
            Err(e) => {
                if let (Some(port), "port-privileged") = (e.port, e.kind) {
                    return refused_port(&e.message, port, o.json, args);
                }
                let source = if e.kind == "port-in-use" {
                    "listen"
                } else {
                    "startup"
                };
                return fatal_port(o.json, source, e.kind, e.message, e.code, e.port);
            }
        };
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
    // Started after the drop, so it inherits a clean state; capabilities are per thread, though,
    // so it drops (and verifies) its own too before it reads anything, and nothing else goes on
    // until it has heard.
    if let Some((_, _, ack)) = &stdin {
        match ack.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(m)) => return fatal(o.json, "startup", "privilege-drop", m, 1),
            Err(_) => {
                return fatal(
                    o.json,
                    "startup",
                    "privilege-drop",
                    "the stdin thread did not report its capability drop",
                    1,
                );
            }
        }
    }
    let mut configs = Vec::new();
    if let Some(path) = &o.red_flags_file {
        match file::load(path) {
            Ok(c) => configs.push(c),
            Err(e) => return fatal(o.json, "startup", "config", e.message(), e.code()),
        }
    }
    if o.config_stdin {
        let (rx, _, _) = stdin.as_ref().expect("the thread was started");
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(line)) => match config::parse(&line) {
                Ok(c) => configs.push(c),
                Err(m) => return fatal(o.json, "startup", "config", m, 2),
            },
            Ok(Err(m)) => return fatal(o.json, "startup", "config", m, 2),
            Err(_) => {
                return fatal(
                    o.json,
                    "startup",
                    "config",
                    "timed out waiting for the config on stdin",
                    2,
                );
            }
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
        Err(e) => return fatal(o.json, "startup", "config", e.message, e.code),
    };

    if let Some((_, go, _)) = &stdin {
        let _ = go.send(());
    }
    let log = match &o.log_file {
        Some(p) => match logfile::LogFile::open(p, o.log_max_mib << 20, o.log_keep) {
            Ok(l) => Some(l),
            Err(m) => return fatal(o.json, "startup", "log-file", m, 1),
        },
        None => None,
    };

    #[cfg(feature = "tls")]
    let tls_run = if o.tls {
        let dir = match ca_dir() {
            Ok(d) => d,
            Err(m) => return fatal(o.json, "startup", "tls-failed", m, 1),
        };
        match cainary_net::tls::Tls::start(&o.tls_hosts, &dir) {
            Ok(tls) => {
                // A new CA was just published: refresh the trust bundles built from the last one.
                if let Ok((harness, ca_dir)) = trust_env() {
                    let env = cainary_net::trust::Env {
                        harness: &harness,
                        ca_dir,
                    };
                    for w in cainary_net::trust::refresh(&env) {
                        eprintln!("cainary-otel-debug: {w}");
                    }
                }
                Some(server::TlsRun {
                    tls,
                    public_port: o.tls_public_port.unwrap_or(443),
                })
            }
            Err(cainary_net::tls::StartError::Busy(m)) => {
                return fatal(o.json, "startup", "tls-busy", m, 1);
            }
            Err(cainary_net::tls::StartError::Failed(m)) => {
                return fatal(o.json, "startup", "tls-failed", m, 1);
            }
        }
    } else {
        None
    };

    let mut cfg = Config::new(Box::new(io::stdout()));
    #[cfg(feature = "tls")]
    {
        cfg.tls = tls_run;
    }
    cfg.listen = o.listen.clone();
    cfg.port = o.port;
    cfg.matcher = matcher;
    cfg.show_values = o.show_values;
    cfg.json = o.json;
    cfg.once = o.once;
    cfg.log = log;
    cfg.status = Box::new(io::stderr());
    let server = match server::start(cfg, ready) {
        Ok(s) => s,
        Err(e) => return fatal(o.json, "startup", e.kind, e.message, e.code),
    };
    match server.wait() {
        output::End::Once | output::End::Closed => 0,
        // The reader went away (an orphaned child writing to a dead pipe): not an error.
        output::End::SinkFailed(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        output::End::SinkFailed(e) => fail(format!("can't write output: {e}"), 1),
    }
}
