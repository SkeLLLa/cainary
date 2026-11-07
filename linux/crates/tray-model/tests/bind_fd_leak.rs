//! Alone in its own test binary so the descriptor counts aren't disturbed by other tests: every
//! rejected or failed reservation must close everything it received.

mod common;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cainary_tray_model::runner;
use common::sockets::{free_port, open_fd_count};

#[test]
fn rejections_close_every_received_descriptor() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fake-leak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let modes = [
        "extra-socket",
        "three-extra-sockets",
        "many-sockets",
        "wildcard",
        "udp",
        "not-listening",
        "wrong-port",
        "garbage-reply",
        "duplicate-family",
        "ipv6-claimed-but-missing",
        "protocol-2",
        "ok-then-exit-1",
        "exit-126",
        "exit-127-no-reply",
        "no-reply-exit-0",
        "port-in-use",
    ];
    let run = |mode: &str| {
        let link = dir.join(mode);
        let _ = std::fs::remove_file(&link);
        symlink(env!("CARGO_BIN_EXE_fake-pkexec"), &link).unwrap();
        let result = runner::bind_privileged(
            &link,
            Path::new("/usr/libexec/cainary/cainary-bind-helper"),
            free_port(),
            Duration::from_secs(20),
        );
        assert!(result.is_err(), "{mode} must fail");
    };
    // Once to warm up lazily opened descriptors, then measure.
    run("garbage-reply");
    let before = open_fd_count();
    for mode in modes {
        run(mode);
        assert_eq!(open_fd_count(), before, "{mode} leaked a descriptor");
    }
}
