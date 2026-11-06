//! The bounded runner and the scan client against the macOS stub CLIs (as ClientTests.swift).

mod common;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cainary_tray_model::runner::{self, Client, Limits, RunError, ScanError, StreamMsg};
use common::{golden, stub, temp_dir};

fn client(name: &str, extra: &[PathBuf]) -> Client {
    let mut client = Client::new(Some(stub(name)));
    client.extra_args = extra.iter().map(OsString::from).collect();
    client
}

fn quick() -> Limits {
    Limits {
        deadline: Duration::from_secs(1),
        ..Limits::default()
    }
}

/// Whether `pid` is gone (reaped, not just a zombie).
fn gone(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == -1 }
}

fn read_pid(path: &PathBuf) -> i32 {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn stream_reads_bounded_lines_and_stops_with_stdin_eof() {
    let args = [
        OsString::from("-c"),
        OsString::from("printf 'first\\nsecond\\n'; cat >/dev/null"),
    ];
    let mut stream = runner::spawn_stream(std::path::Path::new("/bin/sh"), &args, 1024).unwrap();
    stream.write_stdin(b"{\"v\":1}\n").unwrap();
    let receiver = stream.take_receiver().unwrap();
    let mut lines = Vec::new();
    while lines.len() < 2 {
        match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
            StreamMsg::Line(line) => lines.push(line),
            other => panic!("unexpected stream message: {other:?}"),
        }
    }
    assert_eq!(lines, ["first", "second"]);
    stream.stop(Duration::from_secs(1));
    assert!(
        receiver
            .try_iter()
            .any(|message| matches!(message, StreamMsg::Exited { .. }))
    );
}

#[test]
fn stream_stops_on_an_oversize_line() {
    let args = [
        OsString::from("-c"),
        OsString::from("printf '12345678901234567890\\n'; sleep 30"),
    ];
    let mut stream = runner::spawn_stream(std::path::Path::new("/bin/sh"), &args, 16).unwrap();
    let receiver = stream.take_receiver().unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        StreamMsg::Fault("output too large".into())
    );
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        StreamMsg::Exited { .. }
    ));
    stream.stop(Duration::from_secs(1));
}

#[test]
fn collector_child_dies_when_its_parent_is_sigkilled() {
    const PID_FILE: &str = "CAINARY_STREAM_TEST_PID_FILE";
    if let Some(path) = std::env::var_os(PID_FILE) {
        let _stream = runner::spawn_stream(
            std::path::Path::new("/bin/sleep"),
            &[OsString::from("30")],
            1024,
        )
        .unwrap();
        std::fs::write(path, _stream.pid().to_string()).unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // Adopt and reap the helper's child, so a zombie cannot make kill(pid, 0) look alive.
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer flag and has no pointer arguments.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let pid_file = temp_dir("stream-parent-death").join("pid");
    let mut helper = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "collector_child_dies_when_its_parent_is_sigkilled",
            "--nocapture",
        ])
        .env(PID_FILE, &pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !pid_file.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_file.exists(), "helper didn't start the stream child");
    let child_pid = read_pid(&pid_file);
    // SAFETY: `helper.id()` is the child process this test just spawned.
    assert_eq!(
        unsafe { libc::kill(helper.id() as libc::pid_t, libc::SIGKILL) },
        0
    );
    let _ = helper.wait();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status = 0;
        // SAFETY: wait only for the adopted collector child and do not block.
        let reaped = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) } == child_pid;
        // SAFETY: signal 0 checks whether this pid still exists.
        let exists = unsafe { libc::kill(child_pid, 0) } == 0;
        if reaped || !exists {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "collector child {child_pid} survived parent death"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_report_decodes_and_keeps_its_bytes() {
    let path = golden("claude-code-linux.json");
    let scan = client("report.sh", std::slice::from_ref(&path))
        .scan(None)
        .unwrap();
    assert_eq!(scan.report.schema, 3);
    assert_eq!(scan.report.apps[0].id, "claude");
    assert_eq!(scan.raw, std::fs::read(&path).unwrap());
}

#[test]
fn a_missing_cli_is_missing() {
    assert_eq!(
        Client::new(None).scan(None).unwrap_err(),
        ScanError::Missing
    );
    let nowhere = Client::new(Some("/nonexistent/cainary".into()));
    assert_eq!(nowhere.scan(None).unwrap_err(), ScanError::Missing);
}

#[test]
fn a_failure_keeps_the_stderr_tail() {
    let err = client("fail.sh", &[]).scan(None).unwrap_err();
    let ScanError::Failed { code, stderr_tail } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(*code, Some(1));
    assert!(stderr_tail.contains("boom: the scanner broke"));
    assert_eq!(err.reason(), "the scanner failed: boom: the scanner broke");
    assert_eq!(err.kind(), "failed");
}

#[test]
fn a_newer_schema_asks_for_an_update() {
    let err = client("schema4.sh", &[]).scan(None).unwrap_err();
    assert_eq!(err, ScanError::UnsupportedSchema(4));
    assert_eq!(
        err.reason(),
        "the scanner speaks schema 4, this app expects 3"
    );
}

#[test]
fn too_much_stdout_is_oversize() {
    assert_eq!(
        client("bigout.sh", &[]).scan(None).unwrap_err(),
        ScanError::Oversize
    );
}

#[test]
fn too_much_stderr_keeps_the_tail() {
    let limits = Limits::default();
    let out = runner::run(&stub("bigerr.sh"), &[], None, &limits).unwrap();
    assert!(out.status.success());
    assert_eq!(out.stderr.len(), limits.stderr);
    assert!(out.stderr.iter().all(|b| *b == b'e'));
}

#[test]
fn not_json_is_bad_json() {
    // stdin-count prints a bare number with an empty stdin.
    let err = client("stdin-count.sh", &[]).scan(None).unwrap_err();
    assert!(matches!(err, ScanError::BadJson(_)), "{err:?}");
}

#[test]
fn stderr_before_or_after_the_report_does_not_deadlock() {
    let path = golden("claude-code-linux.json");
    for name in ["err-before.sh", "err-after.sh"] {
        let scan = client(name, std::slice::from_ref(&path)).scan(None);
        assert!(scan.is_ok(), "{name}: {scan:?}");
    }
}

#[test]
fn a_child_that_never_reads_stdin_still_succeeds() {
    let path = golden("claude-code-linux.json");
    let baseline = vec![b' '; 200 << 10];
    let scan = client("exit-noread.sh", &[path]).scan(Some(&baseline));
    assert!(scan.is_ok(), "{scan:?}");
}

#[test]
fn the_whole_baseline_reaches_stdin() {
    let baseline = vec![b'x'; 300_000];
    let out = runner::run(
        &stub("stdin-count.sh"),
        &[],
        Some(&baseline),
        &Limits::default(),
    );
    assert_eq!(out.unwrap().stdout, b"300000");
}

#[test]
fn the_deadline_kills_a_child_that_ignores_sigterm() {
    let pid_file = temp_dir("trap-term").join("pid");
    let started = Instant::now();
    let result = runner::run(
        &stub("trap-term.sh"),
        &[pid_file.clone().into()],
        None,
        &quick(),
    );
    assert!(matches!(result, Err(RunError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(gone(read_pid(&pid_file)));
}

#[test]
fn the_deadline_kills_descendants_holding_the_pipes() {
    let pid_file = temp_dir("descendant").join("pid");
    let started = Instant::now();
    let result = runner::run(
        &stub("descendant.sh"),
        &[pid_file.clone().into()],
        None,
        &quick(),
    );
    assert!(matches!(result, Err(RunError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(gone(read_pid(&pid_file)));
}

#[test]
fn an_exit_with_the_pipes_still_open_does_not_wait_for_eof() {
    let pid_file = temp_dir("exit-open").join("pid");
    let started = Instant::now();
    let out = runner::run(
        &stub("exit-open.sh"),
        &[pid_file.clone().into()],
        None,
        &quick(),
    );
    assert!(out.unwrap().status.success());
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(gone(read_pid(&pid_file)));
}

#[test]
fn scan_arguments_ask_for_launchd_json_and_since_with_a_baseline() {
    // report.sh prints the file named by its last argument, so the scan's own arguments
    // come first and the baseline flag sits before the extra ones.
    let dir = temp_dir("args");
    let script = dir.join("args.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nexit 3\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let c = Client::new(Some(script));
    // A freshly written script can hit ETXTBSY while sibling tests fork; retry the spawn.
    let mut error = c.scan(Some(b"{}")).unwrap_err();
    for _ in 0..20 {
        if matches!(error, ScanError::Failed { .. }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        error = c.scan(Some(b"{}")).unwrap_err();
    }
    let ScanError::Failed { stderr_tail, .. } = error else {
        panic!("{error:?}")
    };
    assert_eq!(stderr_tail, "scan\n--json\n--env-kind\nlaunchd\n--since\n-");
}

#[test]
fn report_text_uses_launchd_plain_text_arguments_and_returns_stdout() {
    let dir = temp_dir("report-text-args");
    let script = dir.join("args.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let client = Client::new(Some(script));
    let text = client.report_text(Some(b"{}")).unwrap();
    assert_eq!(
        text.trim_end(),
        "scan\n--no-color\n--env-kind\nlaunchd\n--since\n-"
    );
}

#[test]
fn output_larger_than_a_pipe_buffer_is_read_to_the_end() {
    let size = 3 << 20;
    let args: Vec<OsString> = vec![
        "-c".into(),
        format!("head -c {size} /dev/zero | tr '\\\\0' 'x'").into(),
    ];
    let out = runner::run(
        std::path::Path::new("/bin/sh"),
        &args,
        None,
        &Limits::default(),
    )
    .unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout.len(), size);
}

#[test]
fn reasons_use_the_macos_wording() {
    let failed = |code, tail: &str| ScanError::Failed {
        code,
        stderr_tail: tail.into(),
    };
    let table = [
        (
            ScanError::Missing,
            "missing",
            "the scanner is missing (reinstall cAInary)",
        ),
        (
            ScanError::Spawn("no fork".into()),
            "spawn",
            "couldn't start the scanner (no fork)",
        ),
        (
            failed(Some(2), ""),
            "failed",
            "the scanner exited with code 2",
        ),
        (
            failed(None, "  \n"),
            "failed",
            "the scanner was stopped by a signal",
        ),
        (
            failed(Some(1), "\n  boom \nlater"),
            "failed",
            "the scanner failed: boom",
        ),
        (ScanError::TimedOut, "timeout", "the scanner took too long"),
        (
            ScanError::Oversize,
            "oversize",
            "the scanner printed too much",
        ),
        (
            ScanError::BadJson("eof".into()),
            "bad-json",
            "the scan result was unreadable (eof)",
        ),
        (
            ScanError::UnsupportedSchema(9),
            "schema",
            "the scanner speaks schema 9, this app expects 3",
        ),
        (ScanError::Cancelled, "cancelled", "the scan was stopped"),
    ];
    for (error, kind, reason) in table {
        assert_eq!(error.reason(), reason, "{error:?}");
        assert_eq!(error.kind(), kind, "{error:?}");
    }
    assert_eq!(ScanError::Cancelled.detail(), "");
}

#[test]
fn cancel_ends_a_running_scan_and_its_child() {
    let (script, pid_file) = common::sleeper(&temp_dir("cancel"));
    let mut c = Client::new(Some(script));
    c.limits.deadline = Duration::from_secs(30);
    let worker = {
        let c = c.clone();
        std::thread::spawn(move || c.scan(None))
    };
    while c.running_pid().is_none() || !pid_file.exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    c.cancel();
    assert_eq!(worker.join().unwrap().unwrap_err(), ScanError::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(gone(read_pid(&pid_file)));
    assert_eq!(c.running_pid(), None);
}
