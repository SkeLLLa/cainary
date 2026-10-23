//! Runs the CLI with hard bounds (plan §4) and decodes what it prints. This is the only place
//! the tray starts a process.
//!
//! The child gets its own process group, so a deadline kills everything it started. Pipes are
//! read with `poll` on the calling thread (the store runs this on a worker), and once the child
//! has exited the runner drains what is buffered instead of waiting for EOF: a descendant that
//! keeps the pipes open can't hold a scan up.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::report::{DecodeError, Report, SCHEMA};

/// How long and how much the CLI may run and print.
#[derive(Clone, Debug)]
pub struct Limits {
    pub deadline: Duration,
    /// More stdout than this fails the scan.
    pub stdout: usize,
    /// Only the last this-many bytes of stderr are kept.
    pub stderr: usize,
    /// Time between SIGTERM and SIGKILL once the deadline passes.
    pub term_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(20),
            stdout: 8 << 20,
            stderr: 64 << 10,
            term_grace: Duration::from_secs(2),
        }
    }
}

/// What a finished run printed.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    /// The tail of stderr, at most `Limits::stderr` bytes.
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum RunError {
    Spawn(io::Error),
    TimedOut,
    Oversize,
    /// [`Client::cancel`] ended the run.
    Cancelled,
}

/// How often the loop looks at the child while its pipes are quiet.
const TICK: Duration = Duration::from_millis(20);

/// Runs `program` with `args`, feeding it `stdin` (or `/dev/null` when there is none).
pub fn run(
    program: &std::path::Path,
    args: &[OsString],
    stdin: Option<&[u8]>,
    limits: &Limits,
) -> Result<Output, RunError> {
    run_cancellable(
        program,
        args,
        stdin,
        limits,
        &Mutex::new(None),
        &AtomicBool::new(false),
    )
}

/// [`run`], recording the child's pid (= its process group) in `running` while it lives, and
/// ending it the way a deadline does once `cancelled` is set.
pub fn run_cancellable(
    program: &std::path::Path,
    args: &[OsString],
    stdin: Option<&[u8]>,
    limits: &Limits,
    running: &Mutex<Option<libc::pid_t>>,
    cancelled: &AtomicBool,
) -> Result<Output, RunError> {
    let parent = std::process::id() as libc::pid_t;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // The tray may hold a short-lived activation token; the scanner must not inherit it.
        .env_remove("XDG_ACTIVATION_TOKEN")
        .process_group(0);
    // PDEATHSIG fires when the *spawning thread* exits, and each scan or copy thread waits for
    // its child, so the two lifetimes match: a crash of the tray can't orphan a scan.
    // SAFETY: async-signal-safe calls only.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::raise(libc::SIGTERM);
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    *running.lock().unwrap_or_else(|e| e.into_inner()) = Some(child.id() as libc::pid_t);
    let result = supervise(&mut child, stdin, limits, cancelled);
    *running.lock().unwrap_or_else(|e| e.into_inner()) = None;
    result
}

fn supervise(
    child: &mut Child,
    stdin: Option<&[u8]>,
    limits: &Limits,
    cancelled: &AtomicBool,
) -> Result<Output, RunError> {
    let mut pipes = Pipes {
        stdin: child.stdin.take(),
        stdin_bytes: stdin.unwrap_or_default(),
        stdout: child.stdout.take(),
        stderr: child.stderr.take(),
        out: Vec::new(),
        err: Vec::new(),
    };
    pipes.set_nonblocking();
    let deadline = Instant::now() + limits.deadline;
    loop {
        let now = Instant::now();
        if cancelled.load(Ordering::SeqCst) {
            terminate(child, limits.term_grace);
            return Err(RunError::Cancelled);
        }
        if now >= deadline {
            terminate(child, limits.term_grace);
            return Err(RunError::TimedOut);
        }
        pipes.poll((deadline - now).min(TICK));
        if pipes.pump(limits).is_err() {
            kill_group(child, libc::SIGKILL);
            let _ = child.wait();
            return Err(RunError::Oversize);
        }
        if exited(child) {
            // Whatever the child wrote is in the pipe buffers now; descendants that still hold
            // the pipes are not waited for.
            // Keep going until a pass moves nothing, so a large report is not cut short.
            let mut over = false;
            loop {
                match pipes.pump(limits) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => {
                        over = true;
                        break;
                    }
                }
            }
            kill_group(child, libc::SIGKILL);
            let status = child.wait().map_err(RunError::Spawn)?;
            if over {
                return Err(RunError::Oversize);
            }
            return Ok(Output {
                status,
                stdout: pipes.out,
                stderr: pipes.err,
            });
        }
    }
}

/// Our ends of the child's pipes, each dropped (closed) once finished with.
struct Pipes<'a> {
    stdin: Option<ChildStdin>,
    stdin_bytes: &'a [u8],
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    out: Vec<u8>,
    err: Vec<u8>,
}

struct Oversize;

impl Pipes<'_> {
    fn set_nonblocking(&mut self) {
        if self.stdin_bytes.is_empty() {
            // Nothing to send: EOF right away.
            self.stdin = None;
        }
        let fds = [
            self.stdin.as_ref().map(AsRawFd::as_raw_fd),
            self.stdout.as_ref().map(AsRawFd::as_raw_fd),
            self.stderr.as_ref().map(AsRawFd::as_raw_fd),
        ];
        for fd in fds.into_iter().flatten() {
            set_nonblocking(fd);
        }
    }

    /// Waits up to `timeout` for any pipe to be ready. With every pipe closed it just sleeps, so
    /// the caller still notices the child exiting.
    fn poll(&self, timeout: Duration) {
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(3);
        let mut add = |fd: Option<RawFd>, events| {
            if let Some(fd) = fd {
                fds.push(libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                });
            }
        };
        add(self.stdin.as_ref().map(AsRawFd::as_raw_fd), libc::POLLOUT);
        add(self.stdout.as_ref().map(AsRawFd::as_raw_fd), libc::POLLIN);
        add(self.stderr.as_ref().map(AsRawFd::as_raw_fd), libc::POLLIN);
        if fds.is_empty() {
            std::thread::sleep(timeout);
            return;
        }
        let ms = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: `fds` is a valid, initialised array of `fds.len()` pollfd structs.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    }

    /// Moves whatever the pipes allow right now, without blocking.
    fn pump(&mut self, limits: &Limits) -> Result<bool, Oversize> {
        if let Some(stdin) = self.stdin.as_mut() {
            match stdin.write(self.stdin_bytes) {
                Ok(n) => self.stdin_bytes = &self.stdin_bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // EPIPE: the child exited or closed stdin without reading it all, which is its
                // business (`--since -` is optional input for it).
                Err(_) => self.stdin_bytes = &[],
            }
            if self.stdin_bytes.is_empty() {
                self.stdin = None;
            }
        }
        let out = drain(&mut self.stdout, &mut self.out);
        if out && self.out.len() > limits.stdout {
            return Err(Oversize);
        }
        let err = drain(&mut self.stderr, &mut self.err);
        if err && self.err.len() > limits.stderr {
            let cut = self.err.len() - limits.stderr;
            self.err.drain(..cut);
        }
        Ok(out || err)
    }
}

/// Reads everything available from `pipe` into `buf`, closing it at EOF or on an error.
/// True when bytes were read.
fn drain<R: Read>(pipe: &mut Option<R>, buf: &mut Vec<u8>) -> bool {
    let Some(reader) = pipe.as_mut() else {
        return false;
    };
    let mut chunk = [0u8; 64 << 10];
    let mut any = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                *pipe = None;
                return any;
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                any = true;
                // Let the caller check the caps between chunks.
                if buf.len() > (1 << 20) && n == chunk.len() {
                    return true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return any,
            Err(_) => {
                *pipe = None;
                return any;
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fcntl on a descriptor we own; failures leave it blocking, which only slows a
    // misbehaving child down to the deadline.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// Whether the child has exited, without reaping it: until it is reaped its pid can't be reused,
/// so signalling its process group afterwards is safe.
fn exited(child: &Child) -> bool {
    // SAFETY: waitid with WNOWAIT only inspects our own child; `info` is plain data.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        rc == 0 && info.si_pid() != 0
    }
}

fn kill_group(child: &Child, signal: libc::c_int) {
    // SAFETY: the child is its own group leader (`process_group(0)`) and not yet reaped.
    unsafe { libc::killpg(child.id() as libc::pid_t, signal) };
}

/// SIGTERM to the group, SIGKILL after `grace`, then reap.
fn terminate(child: &mut Child, grace: Duration) {
    kill_group(child, libc::SIGTERM);
    let until = Instant::now() + grace;
    while Instant::now() < until && !exited(child) {
        std::thread::sleep(TICK);
    }
    // Also stops descendants that outlived (or ignored) the SIGTERM.
    kill_group(child, libc::SIGKILL);
    let _ = child.wait();
}

/// A decoded report and the bytes it came from (the next scan's baseline).
#[derive(Clone, Debug)]
pub struct Scan {
    pub report: Report,
    pub raw: Vec<u8>,
}

/// Why a scan produced no report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// No CLI at any of the places it is looked for.
    Missing,
    Spawn(String),
    /// Non-zero exit (`code` is `None` when a signal ended it).
    Failed {
        code: Option<i32>,
        stderr_tail: String,
    },
    TimedOut,
    Oversize,
    BadJson(String),
    UnsupportedSchema(u64),
    /// Stopped on purpose (shutdown).
    Cancelled,
}

impl ScanError {
    /// A short, stable slug for the views (`AppController.errorKind`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Spawn(_) => "spawn",
            Self::Failed { .. } => "failed",
            Self::TimedOut => "timeout",
            Self::Oversize => "oversize",
            Self::BadJson(_) => "bad-json",
            Self::UnsupportedSchema(_) => "schema",
            Self::Cancelled => "cancelled",
        }
    }

    /// One lowercase line for the tooltip and the popup, shown after "Couldn't scan" (the
    /// wording of the macOS app's `CoreError.reason`).
    pub fn reason(&self) -> String {
        match self {
            Self::Missing => "the scanner is missing (reinstall cAInary)".into(),
            Self::Spawn(e) => format!("couldn't start the scanner ({e})"),
            Self::Failed { code, stderr_tail } => {
                match stderr_tail.lines().map(str::trim).find(|l| !l.is_empty()) {
                    Some(line) => format!("the scanner failed: {line}"),
                    None => match code {
                        Some(c) => format!("the scanner exited with code {c}"),
                        None => "the scanner was stopped by a signal".into(),
                    },
                }
            }
            Self::TimedOut => "the scanner took too long".into(),
            Self::Oversize => "the scanner printed too much".into(),
            Self::BadJson(why) => format!("the scan result was unreadable ({why})"),
            Self::UnsupportedSchema(n) => {
                format!("the scanner speaks schema {n}, this app expects {SCHEMA}")
            }
            Self::Cancelled => "the scan was stopped".into(),
        }
    }

    /// Extra text for the details view: the stderr tail or the decode error.
    pub fn detail(&self) -> String {
        match self {
            Self::Failed { stderr_tail, .. } => stderr_tail.clone(),
            Self::BadJson(e) | Self::Spawn(e) => e.clone(),
            _ => String::new(),
        }
    }
}

/// How to run `cainary scan`.
#[derive(Clone, Debug)]
pub struct Client {
    /// `None` when [`crate::locate::cli`] found nothing.
    pub cli: Option<PathBuf>,
    /// Appended after the scan arguments (`CAINARY_SCAN_ARGS` in debug builds; stub inputs in
    /// tests).
    pub extra_args: Vec<OsString>,
    pub limits: Limits,
    command_lock: Arc<Mutex<()>>,
    /// The pid (= process group) of the child that is running, if any.
    running: Arc<Mutex<Option<libc::pid_t>>>,
    cancelled: Arc<AtomicBool>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            cli: None,
            extra_args: Vec::new(),
            limits: Limits::default(),
            command_lock: Arc::new(Mutex::new(())),
            running: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Client {
    pub fn new(cli: Option<PathBuf>) -> Self {
        Self {
            cli,
            ..Self::default()
        }
    }

    /// `cainary scan --json --env-kind launchd`, plus `--since -` with the baseline on stdin.
    /// `launchd` is what a desktop session is: the shell's variables aren't visible, as on macOS.
    pub fn scan(&self, baseline: Option<&[u8]>) -> Result<Scan, ScanError> {
        let out = self.run_cli(&["scan", "--json", "--env-kind", "launchd"], baseline)?;
        match Report::decode(&out.stdout) {
            Ok(report) => Ok(Scan {
                report,
                raw: out.stdout,
            }),
            Err(DecodeError::BadJson(e)) => Err(ScanError::BadJson(e)),
            Err(DecodeError::UnsupportedSchema(n)) => Err(ScanError::UnsupportedSchema(n)),
        }
    }

    /// Runs `cainary scan --no-color --env-kind launchd` and returns the human-readable report.
    /// The same lock as `scan` keeps this command from competing with a background scan.
    pub fn report_text(&self, since: Option<&[u8]>) -> Result<String, ScanError> {
        let out = self.run_cli(&["scan", "--no-color", "--env-kind", "launchd"], since)?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Ends the run in progress (and makes later ones fail at once): the run loop notices within
    /// a tick and terminates the child's process group. Meant for shutdown.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// The pid of the running child, for tests.
    pub fn running_pid(&self) -> Option<libc::pid_t> {
        *self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn run_cli(&self, base: &[&str], stdin: Option<&[u8]>) -> Result<Output, ScanError> {
        let _guard = self.command_lock.lock().unwrap_or_else(|e| e.into_inner());
        let cli = self.cli.as_deref().ok_or(ScanError::Missing)?;
        let mut args: Vec<OsString> = base.iter().map(OsString::from).collect();
        if stdin.is_some() {
            args.extend(["--since", "-"].map(OsString::from));
        }
        args.extend(self.extra_args.iter().cloned());
        let out = match run_cancellable(
            cli,
            &args,
            stdin,
            &self.limits,
            &self.running,
            &self.cancelled,
        ) {
            Ok(out) => out,
            Err(RunError::Spawn(e)) if e.kind() == io::ErrorKind::NotFound => {
                return Err(ScanError::Missing);
            }
            Err(RunError::Spawn(e)) => return Err(ScanError::Spawn(e.to_string())),
            Err(RunError::TimedOut) => return Err(ScanError::TimedOut),
            Err(RunError::Oversize) => return Err(ScanError::Oversize),
            Err(RunError::Cancelled) => return Err(ScanError::Cancelled),
        };
        if !out.status.success() {
            return Err(ScanError::Failed {
                code: out.status.code(),
                stderr_tail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        Ok(out)
    }

    /// `cainary --version`'s output, for the details footer. Empty when it can't be run.
    pub fn version(&self) -> String {
        let Some(cli) = self.cli.as_deref() else {
            return String::new();
        };
        let limits = Limits {
            deadline: Duration::from_secs(5),
            ..self.limits.clone()
        };
        match run(cli, &[OsString::from("--version")], None, &limits) {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_owned()
            }
            _ => String::new(),
        }
    }
}
