//! Raw loopback sockets for the descriptor-passing tests (libc only; the tray crates use no
//! `std::net`).

#![allow(dead_code)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A listening 127.0.0.1 socket on `port` (0 for any).
pub fn listen_v4(port: u16) -> OwnedFd {
    // SAFETY: plain socket calls on a descriptor we own; the sockaddr is zeroed plain data.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0, "socket");
        let fd = OwnedFd::from_raw_fd(fd);
        let mut a: libc::sockaddr_in = std::mem::zeroed();
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_port = port.to_be();
        a.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let rc = libc::bind(
            fd.as_raw_fd(),
            (&a as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
        assert_eq!(libc::listen(fd.as_raw_fd(), 4), 0, "listen");
        fd
    }
}

/// The port a bound IPv4 socket has.
pub fn port_of(fd: RawFd) -> u16 {
    // SAFETY: getsockname fills a zeroed sockaddr_in of the stated length.
    unsafe {
        let mut a: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockname(fd, (&mut a as *mut libc::sockaddr_in).cast(), &mut len);
        assert_eq!(rc, 0, "getsockname");
        u16::from_be(a.sin_port)
    }
}

/// A port nothing listens on right now.
pub fn free_port() -> u16 {
    let fd = listen_v4(0);
    port_of(fd.as_raw_fd())
}

/// How many descriptors this process has open.
pub fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// Whether `fd` is close-on-exec.
pub fn is_cloexec(fd: RawFd) -> bool {
    // SAFETY: F_GETFD only reads the flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC != 0
}
