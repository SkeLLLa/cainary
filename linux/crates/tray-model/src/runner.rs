//! Runs the CLI with hard bounds (plan §4) and decodes what it prints. This is the only place
//! the tray starts a process.
//!
//! The child gets its own process group, so a deadline kills everything it started. Pipes are
//! read with `poll` on the calling thread (the store runs this on a worker), and once the child
//! has exited the runner drains what is buffered instead of waiting for EOF: a descendant that
//! keeps the pipes open can't hold a scan up.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::privport::{self, HelperError, Reply, ReplyError, VerifiedHelper};
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

/// A line read from a long-lived child, or its final status and bounded stderr tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamMsg {
    Line(String),
    Fault(String),
    Exited {
        code: Option<i32>,
        stderr_tail: String,
    },
}

enum StreamCommand {
    Write(Vec<u8>),
    CloseStdin,
    Stop(Duration),
}

/// A process and its single-purpose supervisor thread. The child is spawned and reaped by that
/// thread, which is also the lifetime to which PR_SET_PDEATHSIG is attached.
pub struct StreamHandle {
    pid: libc::pid_t,
    commands: SyncSender<StreamCommand>,
    receiver: Option<Receiver<StreamMsg>>,
    finished: Receiver<()>,
    worker: Option<JoinHandle<()>>,
    stopped: bool,
}

impl StreamHandle {
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Queues bytes for the child's stdin. The caller sends the config line and then leaves the
    /// pipe open as the child's lifeline.
    pub fn write_stdin(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > (1 << 20) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stdin message is too large",
            ));
        }
        self.commands
            .send(StreamCommand::Write(bytes.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "child supervisor stopped"))
    }

    pub fn close_stdin(&self) -> io::Result<()> {
        self.commands
            .send(StreamCommand::CloseStdin)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "child supervisor stopped"))
    }

    /// Transfers the only event receiver to a reader thread.
    pub fn take_receiver(&mut self) -> Option<Receiver<StreamMsg>> {
        self.receiver.take()
    }

    /// Closes stdin, sends SIGTERM, waits for `grace`, then kills the process group and reaps.
    pub fn stop(&mut self, grace: Duration) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let _ = self.commands.send(StreamCommand::Stop(grace));
        let deadline = Instant::now() + grace + Duration::from_secs(1);
        loop {
            if let Some(receiver) = &self.receiver {
                while receiver.try_recv().is_ok() {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match self.finished.recv_timeout(remaining.min(TICK)) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.stop(Duration::from_secs(2));
    }
}

/// How often the loop looks at the child while its pipes are quiet.
const TICK: Duration = Duration::from_millis(20);

/// Starts a long-running line-oriented child. Its line reader and stderr tail are bounded, and
/// all process creation stays in this file (guard L3).
pub fn spawn_stream(
    program: &std::path::Path,
    args: &[OsString],
    max_line: usize,
) -> Result<StreamHandle, RunError> {
    spawn_stream_with_fds(program, args, max_line, &[])
}

/// The most descriptors [`spawn_stream_with_fds`] hands down (fds 3 to 10).
pub const MAX_INHERITED_FDS: usize = 8;
/// The temporaries are parked at or above this, clear of the targets 3, 4, ….
const INHERIT_PARKING: libc::c_int = 100;

/// `--listen-fd 3 [--listen-fd 4]` for the collector, one pair per inherited descriptor.
pub fn listen_fd_args(count: usize) -> Vec<OsString> {
    (0..count)
        .flat_map(|i| {
            [
                OsString::from("--listen-fd"),
                OsString::from((3 + i).to_string()),
            ]
        })
        .collect()
}

/// `fcntl(F_DUPFD_CLOEXEC)` of `fd` to the first free descriptor at or above `min`.
fn dup_cloexec_from(fd: RawFd, min: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC on a descriptor number; the result is a new descriptor we own.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if new < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fcntl returned a fresh descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(new) })
    }
}

/// Keeps descriptors 3, 4, … occupied while a child is spawned, so the pipe `std` uses to report
/// an exec failure can't land on a number the child's `dup2` is about to overwrite. Best effort:
/// another thread opening descriptors at the same moment can still take one.
fn occupy_low_fds(count: usize) -> Vec<OwnedFd> {
    let mut held = Vec::new();
    // SAFETY: open of a constant path.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if null < 0 {
        return held;
    }
    // SAFETY: open returned a descriptor we own.
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    for target in 3..3 + count as libc::c_int {
        // SAFETY: F_GETFD only reads the flags.
        if unsafe { libc::fcntl(target, libc::F_GETFD) } == -1
            && let Ok(fd) = dup_cloexec_from(null.as_raw_fd(), target)
        {
            held.push(fd);
        }
    }
    held
}

/// [`spawn_stream`], with `inherit` placed on descriptors 3, 4, … in the child (and nowhere
/// else: every descriptor the tray holds is close-on-exec). The caller keeps its own copies.
pub fn spawn_stream_with_fds(
    program: &std::path::Path,
    args: &[OsString],
    max_line: usize,
    inherit: &[RawFd],
) -> Result<StreamHandle, RunError> {
    if inherit.len() > MAX_INHERITED_FDS {
        return Err(RunError::Spawn(io::Error::from(
            io::ErrorKind::InvalidInput,
        )));
    }
    // Duplicate before the fork so the child's dup2 targets (3, 4) can't be the sources.
    let mut parked = Vec::with_capacity(inherit.len());
    for fd in inherit {
        parked.push(dup_cloexec_from(*fd, INHERIT_PARKING).map_err(RunError::Spawn)?);
    }
    let parked_raw: Vec<RawFd> = parked.iter().map(AsRawFd::as_raw_fd).collect();
    let parent = std::process::id() as libc::pid_t;
    let program = program.to_path_buf();
    let args = args.to_vec();
    let max_line = max_line.clamp(1, MAX_STREAM_LINE);
    let (ready_tx, ready_rx) = sync_channel(1);
    let (commands, command_rx) = sync_channel(16);
    let (events_tx, receiver) = sync_channel(1);
    let (finished_tx, finished) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("cainary-otel-debug".into())
        .spawn(move || {
            let mut command = Command::new(&program);
            command
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_remove("XDG_ACTIVATION_TOKEN")
                .process_group(0);
            // SAFETY: async-signal-safe calls only (prctl, getppid, raise, dup2: no allocation,
            // no locks). PDEATHSIG is tied to this dedicated thread, which stays alive until the
            // child has been waited for.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        libc::raise(libc::SIGTERM);
                    }
                    for (offset, source) in parked_raw.iter().enumerate() {
                        if libc::dup2(*source, 3 + offset as libc::c_int) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            let placeholders = occupy_low_fds(parked.len());
            let spawned = command.spawn();
            // The parent's temporaries and placeholders go as soon as the child exists.
            drop(command);
            drop(placeholders);
            drop(parked);
            match spawned {
                Ok(child) => {
                    let pid = child.id() as libc::pid_t;
                    let _ = ready_tx.send(Ok(pid));
                    supervise_stream(child, command_rx, events_tx, max_line);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            }
            let _ = finished_tx.send(());
        })
        .map_err(RunError::Spawn)?;
    let pid = match ready_rx.recv() {
        Ok(Ok(pid)) => pid,
        Ok(Err(error)) => {
            let _ = worker.join();
            return Err(RunError::Spawn(error));
        }
        Err(_) => {
            let _ = worker.join();
            return Err(RunError::Spawn(io::Error::other(
                "stream supervisor stopped",
            )));
        }
    };
    Ok(StreamHandle {
        pid,
        commands,
        receiver: Some(receiver),
        finished,
        worker: Some(worker),
        stopped: false,
    })
}

const MAX_STREAM_LINE: usize = 4 << 20;
const STREAM_STDERR_LIMIT: usize = 8 << 10;

fn supervise_stream(
    mut child: Child,
    commands: Receiver<StreamCommand>,
    events: SyncSender<StreamMsg>,
    max_line: usize,
) {
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    for fd in [
        stdin.as_ref().map(AsRawFd::as_raw_fd),
        stdout.as_ref().map(AsRawFd::as_raw_fd),
        stderr.as_ref().map(AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        set_nonblocking(fd);
    }

    let mut input = Vec::new();
    let mut input_offset = 0;
    let mut close_after_write = false;
    let mut output_line = Vec::new();
    let mut stderr_tail = Vec::new();
    let mut stopping: Option<(Instant, Duration)> = None;
    let mut fault = None;

    loop {
        loop {
            match commands.try_recv() {
                Ok(StreamCommand::Write(bytes)) if stopping.is_none() && stdin.is_some() => {
                    if input
                        .len()
                        .saturating_sub(input_offset)
                        .saturating_add(bytes.len())
                        > (1 << 20)
                    {
                        fault = Some("stdin config is too large".to_owned());
                        stopping = Some((Instant::now(), Duration::ZERO));
                        stdin.take();
                        kill_group(&child, libc::SIGTERM);
                    } else {
                        if input_offset > 0 {
                            input.drain(..input_offset);
                            input_offset = 0;
                        }
                        input.extend_from_slice(&bytes);
                    }
                }
                Ok(StreamCommand::CloseStdin) => {
                    close_after_write = true;
                }
                Ok(StreamCommand::Stop(grace)) => {
                    stdin.take();
                    if stopping.is_none() {
                        kill_group(&child, libc::SIGTERM);
                        stopping = Some((Instant::now(), grace));
                    }
                }
                Ok(StreamCommand::Write(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }

        if stopping.is_none()
            && let Some(pipe) = stdin.as_mut()
            && input_offset < input.len()
        {
            match Write::write(pipe, &input[input_offset..]) {
                Ok(n) => input_offset += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    stdin.take();
                    input.clear();
                    input_offset = 0;
                }
            }
        }
        if close_after_write && input_offset == input.len() {
            stdin.take();
        }

        match read_stream_stdout(&mut stdout, &mut output_line, max_line, &events) {
            Ok(()) => {}
            Err(StreamReadError::TooLarge) => {
                fault = Some("output too large".to_owned());
                stdin.take();
                kill_group(&child, libc::SIGKILL);
                let _ = child.wait();
                break;
            }
            Err(StreamReadError::InvalidUtf8) => {
                fault = Some("collector wrote invalid UTF-8".to_owned());
                kill_group(&child, libc::SIGKILL);
                let _ = child.wait();
                break;
            }
        }
        read_stream_stderr(&mut stderr, &mut stderr_tail);

        if let Some((started, grace)) = stopping
            && started.elapsed() >= grace
        {
            kill_group(&child, libc::SIGKILL);
            let _ = child.wait();
            read_stream_stdout(&mut stdout, &mut output_line, max_line, &events).ok();
            read_stream_stderr(&mut stderr, &mut stderr_tail);
            break;
        }

        match child.try_wait() {
            Ok(Some(_)) => {
                // Drain bytes already written, but don't wait for a descendant that inherited a
                // pipe. The process group is killed before the direct child is reaped.
                loop {
                    let before = output_line.len();
                    read_stream_stdout(&mut stdout, &mut output_line, max_line, &events).ok();
                    read_stream_stderr(&mut stderr, &mut stderr_tail);
                    if stdout.is_none() || output_line.len() == before {
                        break;
                    }
                }
                kill_group(&child, libc::SIGKILL);
                let _ = child.wait();
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }

        if let Some((_, grace)) = stopping
            && grace.is_zero()
        {
            kill_group(&child, libc::SIGKILL);
            let _ = child.wait();
            break;
        }
        poll_stream(stdin.as_ref(), stdout.as_ref(), stderr.as_ref(), TICK);
    }

    if !output_line.is_empty() && fault.is_none() {
        if let Ok(line) = String::from_utf8(std::mem::take(&mut output_line)) {
            let _ = events.send(StreamMsg::Line(line));
        } else {
            fault = Some("collector wrote invalid UTF-8".into());
        }
    }
    if let Some(fault) = fault {
        let _ = events.send(StreamMsg::Fault(fault));
    }
    let status = child.try_wait().ok().flatten();
    let _ = events.send(StreamMsg::Exited {
        code: status.and_then(|status| status.code()),
        stderr_tail: String::from_utf8_lossy(&stderr_tail).into_owned(),
    });
}

enum StreamReadError {
    TooLarge,
    InvalidUtf8,
}

fn read_stream_stdout(
    stdout: &mut Option<ChildStdout>,
    pending: &mut Vec<u8>,
    max_line: usize,
    events: &SyncSender<StreamMsg>,
) -> Result<(), StreamReadError> {
    let Some(pipe) = stdout.as_mut() else {
        return Ok(());
    };
    let mut chunk = [0_u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => {
                stdout.take();
                break;
            }
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                stdout.take();
                break;
            }
        }
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            if newline > max_line {
                return Err(StreamReadError::TooLarge);
            }
            let mut bytes = pending.drain(..=newline).collect::<Vec<_>>();
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            let line = String::from_utf8(bytes).map_err(|_| StreamReadError::InvalidUtf8)?;
            let _ = events.send(StreamMsg::Line(line));
        }
        if pending.len() > max_line {
            return Err(StreamReadError::TooLarge);
        }
    }
    Ok(())
}

fn read_stream_stderr(stderr: &mut Option<ChildStderr>, tail: &mut Vec<u8>) {
    let Some(pipe) = stderr.as_mut() else { return };
    let mut chunk = [0_u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => {
                stderr.take();
                break;
            }
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > STREAM_STDERR_LIMIT {
                    let excess = tail.len() - STREAM_STDERR_LIMIT;
                    tail.drain(..excess);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                stderr.take();
                break;
            }
        }
    }
}

fn poll_stream(
    stdin: Option<&ChildStdin>,
    stdout: Option<&ChildStdout>,
    stderr: Option<&ChildStderr>,
    timeout: Duration,
) {
    let mut fds = Vec::with_capacity(3);
    if let Some(pipe) = stdin {
        fds.push(libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        });
    }
    for fd in [
        stdout.map(AsRawFd::as_raw_fd),
        stderr.map(AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        fds.push(libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
    }
    let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    // SAFETY: `fds` contains valid pollfd entries for the live child pipes.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
}

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

/// Runs one bounded trust/status command from the collector helper. Call this on a worker thread:
/// its child is tied to that spawning thread by PDEATHSIG and is always reaped before return.
pub fn run_one_shot(program: &std::path::Path, args: &[OsString]) -> Result<Output, RunError> {
    run(
        program,
        args,
        None,
        &Limits {
            deadline: Duration::from_secs(10),
            stdout: 64 << 10,
            stderr: 16 << 10,
            term_grace: Duration::from_secs(1),
        },
    )
}

/// Runs `<program> --version` unprivileged, with a short deadline and a few bytes of stdout, and
/// returns what it printed. Call this on a worker thread (see [`run_one_shot`]).
pub fn probe_version(program: &std::path::Path) -> Result<String, String> {
    let output = run(
        program,
        &[OsString::from("--version")],
        None,
        &Limits {
            deadline: Duration::from_secs(2),
            stdout: 4 << 10,
            stderr: 1 << 10,
            term_grace: Duration::from_millis(300),
        },
    )
    .map_err(|error| match error {
        RunError::Spawn(e) => format!("couldn't start it ({e})"),
        RunError::TimedOut => "it didn't answer in time".into(),
        RunError::Oversize => "it printed too much".into(),
        RunError::Cancelled => "cancelled".into(),
    })?;
    if !output.status.success() {
        return Err("it exited with an error".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "its answer wasn't text".into())
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

// ---- privileged port reservation -------------------------------------------------------------

/// The only program that may run the root helper.
pub const PKEXEC: &str = "/usr/bin/pkexec";
/// How long the user has to authenticate before the reservation is abandoned.
pub const BIND_DEADLINE: Duration = Duration::from_secs(300);

/// Loopback listeners the helper reserved, already checked against the port that was asked for.
#[derive(Debug)]
pub struct Reserved {
    pub v4: OwnedFd,
    pub v6: Option<OwnedFd>,
    /// Set when only IPv4 was reserved, for the settings page.
    pub warning: Option<String>,
}

impl Reserved {
    /// The descriptors in `--listen-fd` order (IPv4 first).
    pub fn raw_fds(&self) -> Vec<RawFd> {
        let mut fds = vec![self.v4.as_raw_fd()];
        fds.extend(self.v6.as_ref().map(AsRawFd::as_raw_fd));
        fds
    }
}

#[derive(Debug)]
pub enum BindError {
    /// pkexec couldn't be started.
    Spawn(io::Error),
    /// The authentication dialog was dismissed (pkexec exit 126).
    Dismissed,
    /// Not authorised, or no agent to ask (pkexec exit 127).
    NotAuthorized,
    /// Nobody authenticated in time, or the helper hung.
    TimedOut,
    /// The helper refused.
    Helper(HelperError),
    /// The helper speaks another protocol: it needs updating.
    ProtocolMismatch(String),
    /// What came back wasn't what was asked for; everything received was closed.
    Rejected(String),
    /// pkexec or the helper failed some other way.
    Failed {
        code: Option<i32>,
        stderr_tail: String,
    },
}

impl BindError {
    /// One lowercase line for the settings page.
    pub fn reason(&self) -> String {
        match self {
            Self::Spawn(e) => format!("couldn't start pkexec ({e})"),
            Self::Dismissed => "the authentication dialog was dismissed".into(),
            Self::NotAuthorized => "not authorized to reserve the port".into(),
            Self::TimedOut => "timed out waiting for authentication".into(),
            Self::Helper(HelperError::PortInUse) => "the port is already in use".into(),
            Self::Helper(error) => format!("the port helper refused ({error:?})"),
            Self::ProtocolMismatch(p) => {
                format!("the port helper speaks protocol {p}; update the helper")
            }
            Self::Rejected(why) => format!("the port helper's answer was refused ({why})"),
            Self::Failed { code, stderr_tail } => {
                match stderr_tail.lines().map(str::trim).find(|l| !l.is_empty()) {
                    Some(line) => format!("the port helper failed: {line}"),
                    None => match code {
                        Some(c) => format!("the port helper exited with code {c}"),
                        None => "the port helper was stopped by a signal".into(),
                    },
                }
            }
        }
    }
}

/// The whole pkexec command line after the program name, built in one place.
fn pkexec_args(helper: &std::path::Path, port: u16) -> [OsString; 4] {
    [
        OsString::from("--disable-internal-agent"),
        helper.as_os_str().to_owned(),
        OsString::from("--port"),
        OsString::from(port.to_string()),
    ]
}

fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` has room for the two descriptors socketpair writes.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors we own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Asks the root helper, through `pkexec`, to bind `127.0.0.1:port` and `[::1]:port` and hand the
/// listening sockets back. Blocks for up to `deadline` (the user is typing a password), so call it
/// on a worker thread. The helper's stdout is one end of a `SOCK_SEQPACKET` pair; its single reply
/// carries the sockets as `SCM_RIGHTS`. Nothing is trusted: the reply is decoded strictly, every
/// socket is checked here against the port that was asked for, and success needs both a valid
/// reply and a clean exit. Whatever is rejected is closed.
pub fn bind_privileged(
    helper: &VerifiedHelper,
    port: u16,
    deadline: Duration,
) -> Result<Reserved, BindError> {
    // The files may have changed since they were verified; look again right before running them.
    helper
        .recheck()
        .map_err(|why| BindError::Rejected(format!("the helper is no longer trusted: {why}")))?;
    bind_with(
        std::path::Path::new(PKEXEC),
        helper.helper_path(),
        port,
        deadline,
    )
}

/// [`bind_privileged`] with any pkexec and helper, so tests can substitute the fake. It exists
/// only in test builds; a guard keeps production code from naming it.
#[cfg(any(test, feature = "test-fakes"))]
pub fn bind_privileged_with(
    pkexec: &std::path::Path,
    helper: &std::path::Path,
    port: u16,
    deadline: Duration,
) -> Result<Reserved, BindError> {
    bind_with(pkexec, helper, port, deadline)
}

fn bind_with(
    pkexec: &std::path::Path,
    helper: &std::path::Path,
    port: u16,
    deadline: Duration,
) -> Result<Reserved, BindError> {
    if port == 0 {
        return Err(BindError::Rejected("port 0".into()));
    }
    let (ours, theirs) = seqpacket_pair().map_err(BindError::Spawn)?;
    let parent = std::process::id() as libc::pid_t;
    let mut command = Command::new(pkexec);
    command
        .args(pkexec_args(helper, port))
        .stdin(Stdio::null())
        // std dup2s the helper end onto fd 1 in the child, which clears close-on-exec there only.
        .stdout(Stdio::from(theirs))
        .stderr(Stdio::piped())
        .process_group(0);
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
    let spawned = command.spawn();
    // Drops the parent's copy of the helper end: a dead child now shows up as a closed socket.
    drop(command);
    let mut child = spawned.map_err(BindError::Spawn)?;
    exchange(&mut child, ours, port, deadline)
}

enum Received {
    Nothing,
    Closed,
    Message(Result<Reserved, BindError>),
}

fn exchange(
    child: &mut Child,
    socket: OwnedFd,
    port: u16,
    deadline: Duration,
) -> Result<Reserved, BindError> {
    let mut socket = Some(socket);
    let mut stderr = child.stderr.take();
    if let Some(pipe) = &stderr {
        set_nonblocking(pipe.as_raw_fd());
    }
    let mut tail = Vec::new();
    let mut received: Option<Result<Reserved, BindError>> = None;
    let until = Instant::now() + deadline;
    loop {
        let now = Instant::now();
        if now >= until {
            terminate(child, Duration::from_millis(500));
            return Err(BindError::TimedOut);
        }
        let mut fds = Vec::with_capacity(2);
        if let Some(sock) = &socket {
            fds.push(libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(pipe) = &stderr {
            fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let wait = (until - now).min(TICK);
        if fds.is_empty() {
            thread::sleep(wait);
        } else {
            let ms = wait.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: `fds` holds valid pollfd entries for descriptors we own.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        }
        read_stream_stderr(&mut stderr, &mut tail);
        if let Some(sock) = &socket {
            match receive_reply(sock.as_raw_fd(), port) {
                Received::Nothing => {}
                Received::Closed => socket = None,
                Received::Message(result) => {
                    // One reply is all there is; closing now also drops anything queued behind it.
                    socket = None;
                    if matches!(
                        result,
                        Err(BindError::Rejected(_) | BindError::ProtocolMismatch(_))
                    ) {
                        kill_group(child, libc::SIGKILL);
                        let _ = child.wait();
                        return result;
                    }
                    received = Some(result);
                }
            }
        }
        if exited(child) {
            if received.is_none()
                && let Some(sock) = &socket
                && let Received::Message(result) = receive_reply(sock.as_raw_fd(), port)
            {
                received = Some(result);
            }
            read_stream_stderr(&mut stderr, &mut tail);
            kill_group(child, libc::SIGKILL);
            let status = child.wait().map_err(BindError::Spawn)?;
            let code = status.code();
            return match (code, received) {
                (Some(126), _) => Err(BindError::Dismissed),
                (Some(127), _) => Err(BindError::NotAuthorized),
                (_, Some(Err(error))) => Err(error),
                (Some(0), Some(Ok(reserved))) => Ok(reserved),
                (Some(0), None) => Err(BindError::Rejected(
                    "the helper exited without a reply".into(),
                )),
                (_, _) => Err(BindError::Failed {
                    code,
                    stderr_tail: String::from_utf8_lossy(&tail).trim().to_owned(),
                }),
            };
        }
    }
}

/// Reads at most one datagram without blocking and judges it. Every descriptor that arrives is
/// owned (and so closed on any rejection) before anything else is looked at.
fn receive_reply(socket: RawFd, port: u16) -> Received {
    let mut buffer = [0_u8; 256];
    // Room for far more descriptors than the 2 allowed, so extras show up as extras (the kernel
    // closes whatever doesn't fit and flags MSG_CTRUNC).
    let mut control = [0_u64; 16];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: msghdr is plain data; the pointers set below outlive the call.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: `message` describes live buffers.
    let n = unsafe {
        libc::recvmsg(
            socket,
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN | libc::EINTR) => Received::Nothing,
            _ => Received::Closed,
        };
    }
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut unexpected = false;
    // SAFETY: the cmsg macros walk the control buffer the kernel just filled in.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&message);
        while !cmsg.is_null() {
            let header = &*cmsg;
            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                let bytes = (header.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for i in 0..bytes / std::mem::size_of::<libc::c_int>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(i).read_unaligned()));
                }
            } else {
                unexpected = true;
            }
            cmsg = libc::CMSG_NXTHDR(&message, cmsg);
        }
    }
    // Descriptors can ride on an empty message too: they are ours (and closed on any rejection)
    // before the payload is looked at.
    if n == 0 {
        return if fds.is_empty() && !unexpected {
            Received::Closed
        } else {
            Received::Message(Err(BindError::Rejected(
                "an empty message with attachments".into(),
            )))
        };
    }
    let rejected = |why: &str| Received::Message(Err(BindError::Rejected(why.into())));
    if message.msg_flags & libc::MSG_TRUNC != 0 {
        return rejected("the reply was truncated");
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return rejected("too many descriptors");
    }
    if unexpected {
        return rejected("unexpected control message");
    }
    let reply = match privport::parse_reply(&buffer[..n as usize]) {
        Ok(reply) => reply,
        Err(ReplyError::Protocol(p)) => {
            return Received::Message(Err(BindError::ProtocolMismatch(p)));
        }
        Err(ReplyError::Malformed) => return rejected("malformed reply"),
    };
    match reply {
        Reply::Error(error) => {
            if fds.is_empty() {
                Received::Message(Err(BindError::Helper(error)))
            } else {
                rejected("descriptors with an error reply")
            }
        }
        Reply::Ok {
            port: reply_port,
            count,
            ipv6_unavailable,
            ..
        } => {
            if reply_port != port {
                return rejected("the reply names another port");
            }
            if fds.len() != count {
                return rejected("the descriptor count doesn't match the reply");
            }
            Received::Message(check_sockets(fds, port, ipv6_unavailable))
        }
    }
}

/// The descriptors must be one listening TCP socket per family, bound to exactly loopback on the
/// port the caller asked for (not the one the reply claims).
fn check_sockets(
    fds: Vec<OwnedFd>,
    port: u16,
    ipv6_unavailable: bool,
) -> Result<Reserved, BindError> {
    let mut v4 = None;
    let mut v6 = None;
    for fd in fds {
        let raw = fd.as_raw_fd();
        let int_option = |level, name| socket_option(raw, level, name);
        let kind = int_option(libc::SOL_SOCKET, libc::SO_TYPE);
        let listening = int_option(libc::SOL_SOCKET, libc::SO_ACCEPTCONN);
        let protocol = int_option(libc::SOL_SOCKET, libc::SO_PROTOCOL);
        if !is_listening_tcp(kind, listening, protocol) {
            return Err(BindError::Rejected("not a listening TCP socket".into()));
        }
        match local_address(raw) {
            Some(Local::V4 { address, port: p }) if address == [127, 0, 0, 1] && p == port => {
                if v4.replace(fd).is_some() {
                    return Err(BindError::Rejected("two IPv4 sockets".into()));
                }
            }
            Some(Local::V6 { address, port: p }) if address == LOOPBACK_V6 && p == port => {
                if int_option(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY) != Some(1) {
                    return Err(BindError::Rejected("the IPv6 socket isn't v6-only".into()));
                }
                if v6.replace(fd).is_some() {
                    return Err(BindError::Rejected("two IPv6 sockets".into()));
                }
            }
            _ => {
                return Err(BindError::Rejected(
                    "a socket isn't on loopback at the requested port".into(),
                ));
            }
        }
    }
    let Some(v4) = v4 else {
        return Err(BindError::Rejected("no IPv4 socket".into()));
    };
    if v6.is_none() != ipv6_unavailable {
        return Err(BindError::Rejected(
            "IPv6 sockets don't match the reply".into(),
        ));
    }
    let warning = ipv6_unavailable
        .then(|| "IPv6 loopback is unavailable; only 127.0.0.1 is reserved".to_owned());
    Ok(Reserved { v4, v6, warning })
}

/// Stream, listening, TCP: all three must be known and right, so a failed query rejects.
fn is_listening_tcp(
    kind: Option<libc::c_int>,
    listening: Option<libc::c_int>,
    protocol: Option<libc::c_int>,
) -> bool {
    kind == Some(libc::SOCK_STREAM) && listening == Some(1) && protocol == Some(libc::IPPROTO_TCP)
}

const LOOPBACK_V6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

enum Local {
    V4 { address: [u8; 4], port: u16 },
    V6 { address: [u8; 16], port: u16 },
}

fn socket_option(fd: RawFd, level: libc::c_int, name: libc::c_int) -> Option<libc::c_int> {
    let mut value: libc::c_int = -1;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `length` are valid for an int-sized option.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    (rc == 0).then_some(value)
}

fn local_address(fd: RawFd) -> Option<Local> {
    // SAFETY: sockaddr_storage is plain data; getsockname fills at most `length` bytes of it.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if rc != 0 {
        return None;
    }
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says this is a sockaddr_in and the length covers it.
            let a = unsafe {
                &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            Some(Local::V4 {
                address: a.sin_addr.s_addr.to_ne_bytes(),
                port: u16::from_be(a.sin_port),
            })
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for sockaddr_in6.
            let a = unsafe {
                &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            Some(Local::V6 {
                address: a.sin6_addr.s6_addr,
                port: u16::from_be(a.sin6_port),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::is_listening_tcp;

    #[test]
    fn only_a_listening_tcp_stream_passes() {
        let (stream, tcp, sctp) = (libc::SOCK_STREAM, libc::IPPROTO_TCP, libc::IPPROTO_SCTP);
        assert!(is_listening_tcp(Some(stream), Some(1), Some(tcp)));
        assert!(!is_listening_tcp(Some(stream), Some(1), Some(sctp)));
        assert!(!is_listening_tcp(
            Some(libc::SOCK_DGRAM),
            Some(1),
            Some(tcp)
        ));
        assert!(!is_listening_tcp(Some(stream), Some(0), Some(tcp)));
        // A failed getsockopt never passes.
        assert!(!is_listening_tcp(None, Some(1), Some(tcp)));
        assert!(!is_listening_tcp(Some(stream), None, Some(tcp)));
        assert!(!is_listening_tcp(Some(stream), Some(1), None));
    }
}
