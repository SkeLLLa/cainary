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
                     [--tls --tls-host <name>... [--tls-public-port <n>]]
  cainary-otel-debug --delete-ca
  cainary-otel-debug --version | --help

A local OTLP/HTTP receiver, loopback only (127.0.0.1 and ::1), OTLP/JSON only (no protobuf, no
gzip). It never opens an outbound connection. Attribute values are masked unless --show-values.
Red flags (secrets, emails, your own words) raise `alert` lines; --list-presets shows the built-ins.
--red-flag values land in your shell history; GUIs use --config-stdin instead.

--tls --tls-host <name> is the endpoint takeover, for a telemetry host your organization pins to
HTTPS (managed settings that a shell variable can't override). You point that name at loopback,
and this serves it with a certificate from a throwaway CA limited to the names you give. It
FORWARDS NOTHING: while it runs, your organization's collector receives nothing from this
machine, and every other request to those names fails. It listens on 8443 by default and prints
the 443 redirect, the /etc/hosts lines and how to trust the certificate; it never runs sudo,
setcap or nft, and it needs a build with the `tls` cargo feature. `--delete-ca` removes the
certificate file it writes.

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
        Ok(Action::DeleteCa) => delete_ca(),
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
        // no use for it (design §16.7.5). It drops its copy, verified, and says so; the main
        // thread won't bind or accept until it has heard. The bind thread drops its own right
        // after binding.
        #[cfg(feature = "tls")]
        let dropped = cainary_net::tls::privdrop::drop_capabilities()
            .map_err(|e| format!("can't drop capabilities in the stdin thread: {e}"));
        #[cfg(not(feature = "tls"))]
        let dropped: Result<(), String> = Ok(());
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
/// on stderr otherwise), then the note on stderr with the ways to get the port (design: the
/// program prints these commands and never runs them).
fn refused_port(message: &str, port: u16, json: bool, args: &[String]) -> u8 {
    use std::os::unix::fs::MetadataExt;
    if json {
        print!("{}", output::error_line("listen", message));
    } else {
        eprintln!("cainary-otel-debug: {message}");
    }
    let exe = std::env::current_exe().ok();
    // Root-owned file in a root-owned directory, writable by nobody else: a capability on it
    // can't be exploited by swapping the file or the directory entry.
    let safe = |p: &std::path::Path| {
        p.metadata()
            .is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
    };
    let root_owned = exe
        .as_deref()
        .is_some_and(|e| safe(e) && e.parent().is_some_and(safe));
    let shown = exe.as_ref().map(|e| e.display().to_string());
    let note = setup::privileged_port_note(&setup::PortNote {
        port,
        exe: shown.as_deref(),
        exe_root_owned: root_owned,
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

#[cfg(not(feature = "tls"))]
const NO_TLS: &str = "this build has no TLS support (cargo feature `tls`)";

/// Where the takeover CA's public certificate lives (design §16.2): the state directory, so a
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
    let dir = match ca_dir() {
        Ok(d) => d,
        Err(m) => return fail(m, 1),
    };
    match ca_file::delete(&dir) {
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

fn serve(o: Options, args: &[String]) -> u8 {
    #[cfg(not(feature = "tls"))]
    if o.tls {
        return fail(NO_TLS, 2);
    }
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
    // The thread must have dropped (and verified) its capabilities before anything binds.
    if let Some((_, _, ack)) = &stdin {
        match ack.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(m)) => return fail(m, 1),
            Err(_) => return fail("the stdin thread did not report its capability drop", 1),
        }
    }
    let mut configs = Vec::new();
    if let Some(path) = &o.red_flags_file {
        match file::load(path) {
            Ok(c) => configs.push(c),
            Err(e) => return fail(e.message(), e.code()),
        }
    }
    if o.config_stdin {
        let (rx, _, _) = stdin.as_ref().expect("the thread was started");
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

    if let Some((_, go, _)) = &stdin {
        let _ = go.send(());
    }
    let log = match &o.log_file {
        Some(p) => match logfile::LogFile::open(p, o.log_max_mib << 20, o.log_keep) {
            Ok(l) => Some(l),
            Err(m) => return fail(m, 1),
        },
        None => None,
    };

    #[cfg(feature = "tls")]
    let tls_run = if o.tls {
        let dir = match ca_dir() {
            Ok(d) => d,
            Err(m) => return fail(m, 1),
        };
        match cainary_net::tls::Tls::start(&o.tls_hosts, &dir) {
            Ok(tls) => Some(server::TlsRun {
                tls,
                public_port: o.tls_public_port.unwrap_or(443),
            }),
            Err(
                cainary_net::tls::StartError::Busy(m) | cainary_net::tls::StartError::Failed(m),
            ) => {
                return fail(m, 1);
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
    let server = match server::run(cfg) {
        Ok(s) => s,
        Err(e) => {
            if let Some(port) = e.denied_port {
                return refused_port(&e.message, port, o.json, args);
            }
            return fail(e.message, e.code);
        }
    };
    match server.wait() {
        output::End::Once | output::End::Closed => 0,
        // The reader went away (an orphaned child writing to a dead pipe): not an error.
        output::End::SinkFailed(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        output::End::SinkFailed(e) => fail(format!("can't write output: {e}"), 1),
    }
}
