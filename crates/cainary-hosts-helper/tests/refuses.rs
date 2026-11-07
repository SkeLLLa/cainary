//! Run unprivileged, the helper refuses before it opens anything.
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};

const HELPER: &str = env!("CARGO_BIN_EXE_cainary-hosts-helper");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(HELPER)
        .args(args)
        .env_remove("PKEXEC_UID")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn unprivileged_run_refuses_and_touches_nothing() {
    // SAFETY: geteuid(2) cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return; // As root the precondition passes; this test is for ordinary users.
    }
    let before = std::fs::metadata("/etc/hosts").unwrap();
    for args in [&["set", "otel.example.com"][..], &["clear"][..]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "cainary-hosts-helper/1 error not-pkexec\n"
        );
        assert!(out.stderr.is_empty());
    }
    let after = std::fs::metadata("/etc/hosts").unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
}

#[test]
fn bad_arguments_are_refused_before_anything_else() {
    for args in [
        &[][..],
        &["set"][..],
        &["clear", "a.example.com"][..],
        &["bogus"][..],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "cainary-hosts-helper/1 error bad-args\n",
            "{args:?}"
        );
    }
}

#[test]
fn version_works_unprivileged() {
    let out = Command::new(HELPER).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!(
            "cainary-hosts-helper {} protocol 1\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}
