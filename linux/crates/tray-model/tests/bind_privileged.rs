//! `runner::bind_privileged` against the fake pkexec (feature `test-fakes`, enabled for this
//! package's own tests): every way the helper's answer can be wrong, and the pkexec exit codes.

mod common;

use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cainary_tray_model::privport::HelperError;
use cainary_tray_model::runner::{self, BindError, Reserved};
use common::sockets::{free_port, is_cloexec, port_of};

const HELPER: &str = "/usr/libexec/cainary/cainary-bind-helper";

/// The fake, reached through a symlink named after the mode it should act out.
fn fake(mode: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fake-pkexec-{}", std::process::id()));
    let dir = dir.join(mode);
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(mode);
    let _ = std::fs::remove_file(&link);
    symlink(env!("CARGO_BIN_EXE_fake-pkexec"), &link).unwrap();
    link
}

fn bind(mode: &str, port: u16) -> Result<Reserved, BindError> {
    bind_within(mode, port, Duration::from_secs(20))
}

fn bind_within(mode: &str, port: u16, deadline: Duration) -> Result<Reserved, BindError> {
    runner::bind_privileged_with(&fake(mode), Path::new(HELPER), port, deadline)
}

fn rejected(mode: &str) -> String {
    match bind(mode, free_port()) {
        Err(BindError::Rejected(why)) => why,
        other => panic!("{mode}: expected a rejection, got {other:?}"),
    }
}

#[test]
fn bind_ok_two_listeners() {
    let port = free_port();
    let reserved = bind("ok", port).expect("reserved");
    assert_eq!(port_of(reserved.v4.as_raw_fd()), port);
    assert!(reserved.v6.is_some());
    assert_eq!(reserved.warning, None);
    assert_eq!(reserved.raw_fds().len(), 2);
    for fd in reserved.raw_fds() {
        assert!(is_cloexec(fd), "received descriptors are close-on-exec");
    }
}

#[test]
fn rejects_extra_fd() {
    assert!(rejected("extra-socket").contains("count"));
    assert!(rejected("three-extra-sockets").contains("count"));
    assert!(rejected("many-sockets").contains("too many"));
}

#[test]
fn rejects_wildcard() {
    assert!(rejected("wildcard").contains("loopback"));
}

#[test]
fn rejects_udp() {
    assert!(rejected("udp").contains("listening TCP"));
}

#[test]
fn rejects_not_listening() {
    assert!(rejected("not-listening").contains("listening TCP"));
}

#[test]
fn rejects_wrong_port() {
    assert!(rejected("wrong-port").contains("requested port"));
}

#[test]
fn rejects_garbage_reply() {
    assert!(rejected("garbage-reply").contains("malformed"));
}

#[test]
fn rejects_duplicate_family_and_missing_ipv6() {
    assert!(rejected("duplicate-family").contains("two IPv4"));
    assert!(rejected("ipv6-claimed-but-missing").contains("count"));
}

#[test]
fn protocol_mismatch_blocks() {
    match bind("protocol-2", free_port()) {
        Err(BindError::ProtocolMismatch(p)) => assert_eq!(p, "2"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn helper_error_is_typed() {
    match bind("port-in-use", free_port()) {
        Err(BindError::Helper(HelperError::PortInUse)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn success_needs_a_clean_exit() {
    assert!(matches!(
        bind("ok-then-exit-1", free_port()),
        Err(BindError::Failed { code: Some(1), .. })
    ));
    assert!(rejected_exit0("no-reply-exit-0").contains("without a reply"));
}

fn rejected_exit0(mode: &str) -> String {
    rejected(mode)
}

#[test]
fn dismissed_126() {
    assert!(matches!(
        bind("exit-126", free_port()),
        Err(BindError::Dismissed)
    ));
}

#[test]
fn not_authorized_127() {
    let started = Instant::now();
    assert!(matches!(
        bind("exit-127-no-reply", free_port()),
        Err(BindError::NotAuthorized)
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "peer disconnect must not hang"
    );
}

#[test]
fn times_out() {
    let started = Instant::now();
    let result = bind_within("never-replies", free_port(), Duration::from_millis(300));
    assert!(matches!(result, Err(BindError::TimedOut)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn ipv6_unavailable_warns() {
    let port = free_port();
    let reserved = bind("ipv6-unavailable", port).expect("reserved");
    assert!(reserved.v6.is_none());
    assert!(reserved.warning.as_deref().unwrap().contains("IPv6"));
    assert_eq!(port_of(reserved.v4.as_raw_fd()), port);
}

#[test]
fn missing_pkexec_is_a_spawn_error() {
    let result = runner::bind_privileged_with(
        Path::new("/nonexistent/pkexec"),
        Path::new(HELPER),
        4000,
        Duration::from_secs(1),
    );
    assert!(matches!(result, Err(BindError::Spawn(_))), "{result:?}");
}

#[test]
fn rejects_sctp() {
    match bind("sctp", free_port()) {
        Err(BindError::Rejected(why)) => assert!(why.contains("listening TCP"), "{why}"),
        Err(BindError::Failed { code: Some(77), .. }) => {
            eprintln!("skipping: the kernel has no SCTP");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rejects_empty_message_with_descriptors() {
    assert!(rejected("empty-with-fds").contains("empty message"));
}
