//! `spawn_stream_with_fds`: the child gets the listeners on 3 and 4 and nothing else of ours.

mod common;

use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use cainary_tray_model::runner::{self, StreamMsg};
use common::sockets::{listen_v4, open_fd_count};

/// What `/bin/sh` reports about its descriptors: what 3 and 4 are, and every number it holds.
fn probe(inherit: &[i32]) -> (Vec<String>, Vec<(i32, String)>) {
    let script = "readlink /proc/$$/fd/3; readlink /proc/$$/fd/4; echo FDS; \
        for f in /proc/$$/fd/*; do echo \"${f##*/} $(readlink $f)\"; done";
    let args = [OsString::from("-c"), OsString::from(script)];
    let mut stream =
        runner::spawn_stream_with_fds(Path::new("/bin/sh"), &args, 1024, inherit).unwrap();
    let receiver = stream.take_receiver().unwrap();
    let mut lines = Vec::new();
    loop {
        match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
            StreamMsg::Line(line) => lines.push(line),
            StreamMsg::Exited { .. } => break,
            StreamMsg::Fault(f) => panic!("{f}"),
        }
    }
    stream.stop(Duration::from_secs(1));
    let split = lines.iter().position(|l| l == "FDS").unwrap();
    let held = lines[split + 1..]
        .iter()
        .map(|l| {
            let (fd, target) = l.split_once(' ').unwrap();
            (fd.parse().unwrap(), target.to_owned())
        })
        .collect();
    (lines[..split].to_vec(), held)
}

fn ambient_inheritable() -> Vec<i32> {
    // SAFETY: F_GETFD only reads the flags.
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0)
        .collect()
}

fn socket_name(fd: i32) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn inherit_places_fds_at_3_and_4() {
    let first = listen_v4(0);
    let second = listen_v4(0);
    let inherit = [first.as_raw_fd(), second.as_raw_fd()];
    let ambient = ambient_inheritable();
    let before = open_fd_count();

    let (links, held) = probe(&inherit);
    assert_eq!(links, [socket_name(inherit[0]), socket_name(inherit[1])]);
    for (fd, target) in &held {
        let ours = (3..=4).contains(fd) || ambient.contains(fd) || *fd <= 2;
        // The shell may keep a private pipe or two, but never a socket of ours or a parked copy.
        assert!(
            ours || (!target.starts_with("socket:") && *fd < 100),
            "descriptor {fd} -> {target} leaked into the child (held: {held:?})"
        );
    }
    assert_eq!(
        open_fd_count(),
        before,
        "the parent's temporaries must be closed"
    );

    // One descriptor lands on 3 alone.
    let (links, held) = probe(&inherit[..1]);
    assert_eq!(links[0], socket_name(inherit[0]));
    assert!(
        held.iter()
            .all(|(fd, t)| *fd != 4 || ambient.contains(fd) || !t.starts_with("socket:")),
        "{held:?}"
    );

    // None: nothing of ours is passed down.
    let (_, held) = probe(&[]);
    assert!(
        held.iter()
            .all(|(fd, t)| *fd <= 2 || ambient.contains(fd) || !t.starts_with("socket:")),
        "{held:?}"
    );
}

#[test]
fn listen_fd_args_name_the_targets() {
    let args = runner::listen_fd_args(2);
    assert_eq!(
        args,
        ["--listen-fd", "3", "--listen-fd", "4"].map(OsString::from)
    );
    assert!(runner::listen_fd_args(0).is_empty());
}
