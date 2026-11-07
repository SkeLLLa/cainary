//! `runner::edit_hosts_with` against the fake pkexec (feature `test-fakes`, enabled for this
//! package's own tests), one test per hosts mode, mapped to the outcome table. The fake never
//! touches a file and the real pkexec is never run.

mod common;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cainary_tray_model::hostsedit::{self, HostsError, HostsOp};
use cainary_tray_model::runner::{
    self, HostsEditOutcome as Out, HostsNotRun, HostsUncertain as Uncertain,
};

use common::hosts_tree;

const HELPER: &str = "/usr/libexec/cainary/cainary-hosts-helper";

/// The fake, reached through a symlink named after the mode it should act out. Each call gets
/// its own directory: tests sharing a mode run in parallel and must not replace each other's link.
fn fake(mode: &str) -> PathBuf {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fake-pkexec-hosts-{}", std::process::id()))
        .join(CALLS.fetch_add(1, Ordering::Relaxed).to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(mode);
    symlink(env!("CARGO_BIN_EXE_fake-pkexec"), &link).unwrap();
    link
}

fn set_op() -> HostsOp {
    HostsOp::set(&["otel.example.com".into(), "api.example.com".into()]).unwrap()
}

fn run_op(mode: &str, op: &HostsOp, deadline: Duration) -> Out {
    runner::edit_hosts_with(&fake(mode), Path::new(HELPER), op, deadline)
}

fn run(mode: &str) -> Out {
    run_op(mode, &set_op(), Duration::from_secs(20))
}

fn uncertain(mode: &str) -> Uncertain {
    match run(mode) {
        Out::Uncertain(why) => why,
        other => panic!("{mode}: expected Uncertain, got {other:?}"),
    }
}

#[test]
fn ok_changed() {
    assert_eq!(
        run("ok-changed"),
        Out::Applied {
            changed: true,
            synced: true
        }
    );
}

#[test]
fn ok_unchanged() {
    assert_eq!(
        run("ok-unchanged"),
        Out::Applied {
            changed: false,
            synced: true
        }
    );
}

#[test]
fn ok_unsynced() {
    assert_eq!(
        run("ok-unsynced"),
        Out::Applied {
            changed: true,
            synced: false
        }
    );
}

#[test]
fn clear_is_asked_and_answered_as_clear() {
    // The fake echoes the command word it was given: a clear is answered `ok clear …`.
    assert_eq!(
        run_op("ok-changed", &HostsOp::Clear, Duration::from_secs(20)),
        Out::Applied {
            changed: true,
            synced: true
        }
    );
}

#[test]
fn refusals_are_typed() {
    assert_eq!(run("error-symlink"), Out::Refused(HostsError::Symlink));
    assert_eq!(run("error-damaged"), Out::Refused(HostsError::DamagedBlock));
}

#[test]
fn garbage_is_uncertain() {
    assert_eq!(uncertain("garbage"), Uncertain::Garbled);
}

#[test]
fn no_reply_is_uncertain() {
    assert_eq!(uncertain("no-reply"), Uncertain::NoReply);
}

#[test]
fn protocol_mismatch_after_running_is_uncertain() {
    assert_eq!(
        uncertain("protocol-2"),
        Uncertain::ProtocolMismatch("2".into())
    );
}

#[test]
fn dismissed_126() {
    assert_eq!(run("exit-126"), Out::NotRun(HostsNotRun::Dismissed));
}

#[test]
fn not_authorized_127() {
    let started = Instant::now();
    assert_eq!(run("exit-127"), Out::NotRun(HostsNotRun::NotAuthorized));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn hang_hits_the_deadline() {
    let started = Instant::now();
    let out = run_op("hang", &set_op(), Duration::from_millis(300));
    assert_eq!(out, Out::Uncertain(Uncertain::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn flood_is_bounded() {
    let started = Instant::now();
    assert_eq!(uncertain("flood"), Uncertain::OutputTooLarge);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn ok_with_a_bad_exit_is_uncertain() {
    assert_eq!(uncertain("ok-but-exit-1"), Uncertain::OkWithExit(1));
}

#[test]
fn killed_is_uncertain() {
    assert_eq!(uncertain("killed"), Uncertain::Signal(libc::SIGKILL));
}

#[test]
fn unknown_mode_is_not_an_answer() {
    // The fake itself refuses (exit 2, nothing on stdout): no reply, so uncertain.
    assert_eq!(uncertain("surprise"), Uncertain::NoReply);
}

#[test]
fn missing_pkexec_is_a_spawn_error() {
    let out = runner::edit_hosts_with(
        Path::new("/nonexistent/pkexec"),
        Path::new(HELPER),
        &set_op(),
        Duration::from_secs(1),
    );
    assert!(matches!(out, Out::NotRun(HostsNotRun::Spawn(_))), "{out:?}");
}

#[test]
fn a_helper_that_is_no_longer_trusted_is_not_run() {
    use std::os::unix::fs::PermissionsExt;
    let tree = hosts_tree::tree("recheck");
    let verified = tree.verified();
    verified.recheck().expect("still trusted");
    // Make the helper writable by others: the recheck right before pkexec must catch it, and the
    // real pkexec must not be started (it would prompt on the developer's desktop).
    std::fs::set_permissions(
        tree.path(hostsedit::HELPER_PACKAGED),
        std::fs::Permissions::from_mode(0o757),
    )
    .unwrap();
    let out = runner::edit_hosts(&verified, &set_op(), Duration::from_secs(1));
    assert!(
        matches!(out, Out::NotRun(HostsNotRun::NotTrusted(_))),
        "{out:?}"
    );
}
