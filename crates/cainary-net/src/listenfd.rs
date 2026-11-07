//! Already-bound listening sockets handed down by the parent (`--listen-fd`, design §12.1).
//!
//! The tray gets loopback sockets for a privileged port from a root helper and passes them on
//! as inherited file descriptors. Nothing the parent says is trusted: every descriptor is
//! checked here to be a listening TCP socket on exactly 127.0.0.1 or ::1 (IPv6 with
//! `IPV6_V6ONLY`) at OUR `--port`, with at most one per family. Any failure is an error and the
//! caller never binds by itself instead. This file and `privdrop.rs` are the only users of
//! `libc` here besides the file helpers. The caller turns the descriptors into listeners (this
//! file names no `std::net` type).

use std::os::fd::OwnedFd;

/// What failed, as the message of the `listen-fd` error.
pub type Reject = String;

#[cfg(target_os = "linux")]
pub fn adopt(fds: &[i32], port: u16) -> Result<Vec<OwnedFd>, Reject> {
    use std::os::fd::{FromRawFd, RawFd};

    if fds.is_empty() {
        return Err("no --listen-fd given".into());
    }
    if fds.len() > 2 {
        return Err("at most two --listen-fd descriptors".into());
    }
    let mut seen: Vec<(RawFd, bool)> = Vec::new();
    for &fd in fds {
        if fd < 3 {
            return Err(format!(
                "--listen-fd {fd}: descriptors 0-2 are not accepted"
            ));
        }
        if seen.iter().any(|(f, _)| *f == fd) {
            return Err(format!("--listen-fd {fd} is given twice"));
        }
        let addr = check(fd, port)?;
        let v6 = addr.v6;
        if seen.iter().any(|(_, other)| *other == v6) {
            return Err(format!(
                "--listen-fd {fd}: a second {} socket (one per family)",
                if v6 { "IPv6" } else { "IPv4" }
            ));
        }
        seen.push((fd, v6));
    }
    let mut out = Vec::new();
    for (fd, _) in seen {
        // SAFETY: the descriptor was just validated as an open socket of ours and appears once
        // in the list, so the OwnedFd is its only owner.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        out.push(owned);
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
pub fn adopt(_fds: &[i32], _port: u16) -> Result<Vec<OwnedFd>, Reject> {
    Err("--listen-fd is not supported on this platform".into())
}

#[cfg(target_os = "linux")]
fn getopt_int(fd: i32, level: i32, name: i32) -> Result<i32, std::io::Error> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are live and correctly sized for the whole call.
    let r = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            &mut v as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if r == 0 {
        Ok(v)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A local address: the family and, for the checks only, the raw bytes.
#[cfg(target_os = "linux")]
struct Local {
    v6: bool,
    ip: [u8; 16],
    port: u16,
}

/// The socket-level facts that make a descriptor a listening TCP socket: `SOCK_STREAM` alone
/// also admits SCTP and others, so the protocol is checked too.
fn tcp_listening(ty: i32, proto: i32, listening: i32) -> Result<(), &'static str> {
    if ty != libc::SOCK_STREAM {
        return Err("not a stream socket");
    }
    if proto != libc::IPPROTO_TCP {
        return Err("not a TCP socket");
    }
    if listening != 1 {
        return Err("not a listening socket");
    }
    Ok(())
}

/// Validates one descriptor and marks it close-on-exec; returns its local address.
#[cfg(target_os = "linux")]
fn check(fd: i32, port: u16) -> Result<Local, Reject> {
    let bad = |what: &str| format!("--listen-fd {fd}: {what}");
    let os = |what: &str, e: std::io::Error| format!("--listen-fd {fd}: {what}: {e}");

    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is live for the call.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(os(
            "not an open descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(bad("not a socket"));
    }
    // Every query must succeed: a failure is a rejection, never a skipped check.
    let ty = getopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE).map_err(|e| os("SO_TYPE", e))?;
    let proto =
        getopt_int(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL).map_err(|e| os("SO_PROTOCOL", e))?;
    let listening = getopt_int(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN)
        .map_err(|e| os("SO_ACCEPTCONN", e))?;
    tcp_listening(ty, proto, listening).map_err(bad)?;

    // SAFETY: an all-zero `sockaddr_storage` is a valid out-parameter.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `ss` and `len` are live and `len` is its size.
    let r = unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) };
    if r != 0 {
        return Err(os("getsockname", std::io::Error::last_os_error()));
    }
    // The family comes from the address itself (what SO_DOMAIN reports, on every unix).
    let local = match ss.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says `sockaddr_in` and `len` covers it.
            let a = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in) };
            let mut ip = [0u8; 16];
            // `s_addr` is in network order: its memory bytes are the address.
            ip[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
            Local {
                v6: false,
                ip,
                port: u16::from_be(a.sin_port),
            }
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family says `sockaddr_in6` and `len` covers it.
            let a = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in6) };
            Local {
                v6: true,
                ip: a.sin6_addr.s6_addr,
                port: u16::from_be(a.sin6_port),
            }
        }
        _ => return Err(bad("not an IPv4 or IPv6 socket")),
    };
    if local.v6 {
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        if local.ip != loopback {
            return Err(bad("bound to an address other than exactly ::1"));
        }
        let only = getopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)
            .map_err(|e| os("IPV6_V6ONLY", e))?;
        if only != 1 {
            return Err(bad("an IPv6 socket without IPV6_V6ONLY"));
        }
    } else if local.ip[..4] != [127, 0, 0, 1] {
        return Err(bad("bound to an address other than exactly 127.0.0.1"));
    }
    if local.port != port {
        return Err(bad(&format!(
            "bound to port {}, not the requested --port {port}",
            local.port
        )));
    }

    // SAFETY: plain fcntl on a descriptor just validated.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(os("F_GETFD", std::io::Error::last_os_error()));
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(os("F_SETFD", std::io::Error::last_os_error()));
    }
    Ok(local)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_a_listening_tcp_stream_passes() {
        let (s, t, l) = (libc::SOCK_STREAM, libc::IPPROTO_TCP, 1);
        assert!(tcp_listening(s, t, l).is_ok());
        assert!(tcp_listening(libc::SOCK_DGRAM, libc::IPPROTO_UDP, l).is_err());
        assert!(tcp_listening(libc::SOCK_DGRAM, t, l).is_err());
        assert!(
            tcp_listening(s, libc::IPPROTO_SCTP, l).is_err(),
            "SCTP is a stream too"
        );
        assert!(tcp_listening(s, 0, l).is_err());
        assert!(tcp_listening(s, t, 0).is_err());
        assert!(tcp_listening(s, t, 2).is_err());
    }

    #[test]
    fn a_closed_descriptor_is_rejected() {
        assert!(adopt(&[999_999], 1).is_err());
    }
}
