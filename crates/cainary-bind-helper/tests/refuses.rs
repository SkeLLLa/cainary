//! Run unprivileged, the helper refuses before it binds anything.
#![cfg(target_os = "linux")]

use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

const HELPER: &str = env!("CARGO_BIN_EXE_cainary-bind-helper");

fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for two descriptors.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: socketpair returned two fresh descriptors.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn recv_line(fd: &OwnedFd) -> Option<String> {
    use std::os::fd::AsRawFd;
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for the call.
    let n = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

#[test]
fn unprivileged_run_refuses_and_sends_nothing() {
    // SAFETY: geteuid(2) cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return; // As root the precondition passes; this test is for ordinary users.
    }
    // stdout is a pipe, not a seqpacket socket: nothing is sent, exit 2.
    let out = Command::new(HELPER)
        .args(["--port", "443"])
        .env_remove("PKEXEC_UID")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());

    // stdout is a valid channel: exactly one refusal, no descriptors, exit 2.
    let (helper_end, tray_end) = seqpacket_pair();
    let status = Command::new(HELPER)
        .args(["--port", "443"])
        .env_remove("PKEXEC_UID")
        .stdin(Stdio::null())
        .stdout(Stdio::from(helper_end))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    assert_eq!(
        recv_line(&tray_end).as_deref(),
        Some("cainary-bind-helper/1 error not-pkexec")
    );
    assert_eq!(recv_line(&tray_end), None);
}

#[test]
fn version_works_unprivileged() {
    let out = Command::new(HELPER).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        text,
        format!(
            "cainary-bind-helper {} protocol 1\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}
