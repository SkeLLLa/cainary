//! Protocol 1. The tray starts `pkexec <helper> --port N` with a SOCK_SEQPACKET socketpair end as
//! the helper's stdout. The helper binds, then sends one datagram on it, with the listening
//! sockets as SCM_RIGHTS: `cainary-bind-helper/1 ok <port> <count> <version>[ ipv6-unavailable]`,
//! or `cainary-bind-helper/1 error <token>`. Exit 0 on success, 2 on a refused precondition
//! (bad arguments, not run by pkexec, bad channel), 1 on a failed bind or send. It reads no file
//! and no stdin, writes none, runs nothing and reads only `PKEXEC_UID` from the environment.

use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL: &str = "cainary-bind-helper/1";
const CHANNEL: RawFd = 1;

#[derive(Debug, PartialEq)]
pub enum Fail {
    BadArgs,
    NotPkexec,
    BadChannel,
    PortInUse,
    BindFailed,
    SendFailed,
}

impl Fail {
    fn token(&self) -> &'static str {
        match self {
            Fail::BadArgs => "bad-args",
            Fail::NotPkexec => "not-pkexec",
            Fail::BadChannel => "bad-channel",
            Fail::PortInUse => "port-in-use",
            Fail::BindFailed => "bind-failed",
            Fail::SendFailed => "send-failed",
        }
    }

    fn exit_code(&self) -> i32 {
        match self {
            Fail::BadArgs | Fail::NotPkexec | Fail::BadChannel => 2,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fam {
    V4,
    V6,
}

/// Opens a listening loopback socket for one family; the error is the `errno`.
pub type BindFn = fn(Fam, u16) -> Result<OwnedFd, i32>;

/// `N` in `--port N`: canonical decimal, 1 to 1023, and nothing else on the command line.
pub fn parse_args(args: &[String]) -> Result<u16, Fail> {
    let [flag, n] = args else {
        return Err(Fail::BadArgs);
    };
    let canonical = !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && (n.len() == 1 || !n.starts_with('0'));
    match n.parse::<u16>() {
        Ok(p) if flag == "--port" && canonical && (1..=1023).contains(&p) => Ok(p),
        _ => Err(Fail::BadArgs),
    }
}

/// `PKEXEC_UID`: canonical decimal that fits a uid (`(uid_t)-1` is not one).
pub fn parse_uid(s: Option<&str>) -> Option<u32> {
    let s = s?;
    let canonical = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    s.parse::<u32>()
        .ok()
        .filter(|&u| canonical && u != u32::MAX)
}

/// Whether fd 1 may receive a reply at all: a Unix SOCK_SEQPACKET socket.
pub fn is_seqpacket(sock_type: Option<i32>, domain: Option<i32>) -> bool {
    sock_type == Some(libc::SOCK_SEQPACKET) && domain == Some(libc::AF_UNIX)
}

/// The channel is a seqpacket socket whose peer (the tray, which made the socketpair) is the user
/// pkexec says it was started for.
pub fn channel_checks(
    sock_type: Option<i32>,
    domain: Option<i32>,
    peer_uid: Option<u32>,
    pkexec_uid: u32,
) -> Result<(), Fail> {
    if is_seqpacket(sock_type, domain) && peer_uid == Some(pkexec_uid) {
        Ok(())
    } else {
        Err(Fail::BadChannel)
    }
}

pub fn reply_ok(port: u16, count: usize, ipv6_unavailable: bool) -> String {
    let warn = if ipv6_unavailable {
        " ipv6-unavailable"
    } else {
        ""
    };
    format!("{PROTOCOL} ok {port} {count} {VERSION}{warn}")
}

fn reply_error(fail: &Fail) -> String {
    format!("{PROTOCOL} error {}", fail.token())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn sockopt_int(fd: RawFd, level: i32, opt: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for the call and sized for an int option.
    let rc = unsafe { libc::getsockopt(fd, level, opt, (&mut v as *mut i32).cast(), &mut len) };
    (rc == 0).then_some(v)
}

fn set_int(fd: RawFd, level: i32, opt: i32, v: i32) -> Result<(), i32> {
    // SAFETY: `v` is valid for the call and sized as passed.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&v as *const i32).cast(),
            mem::size_of::<i32>() as _,
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn peer_uid(fd: RawFd) -> Option<u32> {
    // SAFETY: an all-zero ucred is valid; the length matches the buffer.
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let p = (&mut cred as *mut libc::ucred).cast();
    // SAFETY: `p` points at `cred`, `len` is its size.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, p, &mut len) };
    (rc == 0).then_some(cred.uid)
}

/// SOCK_STREAM, CLOEXEC, SO_REUSEADDR only (never SO_REUSEPORT), IPV6_V6ONLY on `::1`, listening.
pub fn bind_loopback(fam: Fam, port: u16) -> Result<OwnedFd, i32> {
    let domain = if fam == Fam::V4 {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: plain socket(2); the result is owned right below.
    let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(errno());
    }
    // SAFETY: `raw` is a fresh descriptor nobody else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let raw = fd.as_raw_fd();
    set_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    // SAFETY: all-zero sockaddrs are valid; fields are set below.
    let (mut a4, mut a6): (libc::sockaddr_in, libc::sockaddr_in6) = unsafe { mem::zeroed() };
    let (addr, len) = if fam == Fam::V4 {
        a4.sin_family = libc::AF_INET as _;
        a4.sin_port = port.to_be();
        a4.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        (
            &a4 as *const _ as *const libc::sockaddr,
            mem::size_of_val(&a4),
        )
    } else {
        set_int(raw, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
        a6.sin6_family = libc::AF_INET6 as _;
        a6.sin6_port = port.to_be();
        a6.sin6_addr.s6_addr[15] = 1;
        (
            &a6 as *const _ as *const libc::sockaddr,
            mem::size_of_val(&a6),
        )
    };
    // SAFETY: `addr` points at a live sockaddr of `len` bytes.
    if unsafe { libc::bind(raw, addr, len as _) } != 0 {
        return Err(errno());
    }
    // SAFETY: listen(2) on a bound socket.
    if unsafe { libc::listen(raw, 128) } != 0 {
        return Err(errno());
    }
    Ok(fd)
}

/// The socket is listening on exactly the loopback address of its family, at `port`.
fn self_check(fd: &OwnedFd, fam: Fam, port: u16) -> bool {
    // SAFETY: an all-zero sockaddr_storage is valid.
    let mut ss: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&ss) as libc::socklen_t;
    let p = (&mut ss as *mut libc::sockaddr_storage).cast();
    // SAFETY: `p` points at `ss`, `len` is its size.
    if unsafe { libc::getsockname(fd.as_raw_fd(), p, &mut len) } != 0 {
        return false;
    }
    let listening = sockopt_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ACCEPTCONN) == Some(1);
    // SAFETY: the kernel wrote a sockaddr of the family it reports; each cast is to that family.
    let addr_ok = unsafe {
        match fam {
            Fam::V4 if ss.ss_family == libc::AF_INET as _ => {
                let a = &*(&ss as *const _ as *const libc::sockaddr_in);
                a.sin_port == port.to_be()
                    && a.sin_addr.s_addr == u32::from_ne_bytes([127, 0, 0, 1])
            }
            Fam::V6 if ss.ss_family == libc::AF_INET6 as _ => {
                let a = &*(&ss as *const _ as *const libc::sockaddr_in6);
                a.sin6_port == port.to_be()
                    && a.sin6_addr.s6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            }
            _ => false,
        }
    };
    listening && addr_ok
}

/// One datagram on `chan` carrying `fds` as SCM_RIGHTS. Never blocks, never raises SIGPIPE.
fn send(chan: RawFd, line: &str, fds: &[RawFd]) -> Result<(), Fail> {
    let mut iov = libc::iovec {
        iov_base: line.as_ptr() as *mut _,
        iov_len: line.len(),
    };
    let mut ctl = [0u64; 8];
    let data_len = mem::size_of_val(fds);
    // SAFETY: an all-zero msghdr is valid; the control buffer (64 bytes, aligned) outlives the
    // call and holds one header with up to two fds, and `iov` points at `line`.
    let rc = unsafe {
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            msg.msg_control = ctl.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(data_len as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(data_len as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), fds.len());
        }
        libc::sendmsg(chan, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
    };
    if rc == line.len() as isize {
        Ok(())
    } else {
        Err(Fail::SendFailed)
    }
}

/// Binds, self-checks and sends. IPv6 may be narrowly unavailable (`EAFNOSUPPORT`, or
/// `EADDRNOTAVAIL` for `::1`): then the reply carries one socket and a warning. Any other failure,
/// `EADDRINUSE` on IPv6 included, closes everything. The caller reports a failure on the channel.
pub fn bind_and_send(port: u16, chan: RawFd, bind: BindFn) -> Result<(), Fail> {
    let fail = |e: i32| {
        if e == libc::EADDRINUSE {
            Fail::PortInUse
        } else {
            Fail::BindFailed
        }
    };
    let v4 = bind(Fam::V4, port).map_err(fail)?;
    let v6 = match bind(Fam::V6, port) {
        Ok(fd) => Some(fd),
        Err(e) if e == libc::EAFNOSUPPORT || e == libc::EADDRNOTAVAIL => None,
        Err(e) => return Err(fail(e)),
    };
    let mut socks = vec![(v4, Fam::V4)];
    socks.extend(v6.map(|fd| (fd, Fam::V6)));
    if !socks.iter().all(|(fd, fam)| self_check(fd, *fam, port)) {
        return Err(Fail::BindFailed);
    }
    let fds: Vec<RawFd> = socks.iter().map(|(fd, _)| fd.as_raw_fd()).collect();
    send(chan, &reply_ok(port, fds.len(), fds.len() == 1), &fds)
}

fn run_checked(args: &[String]) -> Result<(), Fail> {
    let port = parse_args(args)?;
    // SAFETY: geteuid(2) cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let uid = parse_uid(std::env::var("PKEXEC_UID").ok().as_deref()).filter(|_| root);
    let uid = uid.ok_or(Fail::NotPkexec)?;
    let sock_type = sockopt_int(CHANNEL, libc::SOL_SOCKET, libc::SO_TYPE);
    let domain = sockopt_int(CHANNEL, libc::SOL_SOCKET, libc::SO_DOMAIN);
    channel_checks(sock_type, domain, peer_uid(CHANNEL), uid)?;
    bind_and_send(port, CHANNEL, bind_loopback)
}

pub fn run() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().unwrap_or_default())
        .collect();
    if args == ["--version"] {
        println!("cainary-bind-helper {VERSION} protocol 1");
        exit(0);
    }
    let Err(fail) = run_checked(&args) else {
        exit(0)
    };
    let sock_type = sockopt_int(CHANNEL, libc::SOL_SOCKET, libc::SO_TYPE);
    if is_seqpacket(
        sock_type,
        sockopt_int(CHANNEL, libc::SOL_SOCKET, libc::SO_DOMAIN),
    ) && fail != Fail::SendFailed
    {
        let _ = send(CHANNEL, &reply_error(&fail), &[]);
    }
    exit(fail.exit_code());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, TcpListener, TcpStream};

    fn s(a: &[&str]) -> Vec<String> {
        a.iter().map(|x| x.to_string()).collect()
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn pair() -> (OwnedFd, OwnedFd) {
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

    /// The datagram and its SCM_RIGHTS descriptors, with truncation treated as a failure.
    fn recv(fd: &OwnedFd) -> (String, Vec<OwnedFd>) {
        let mut buf = [0u8; 256];
        let mut ctl = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: buffers outlive the call; headers are read only after a successful recvmsg.
        unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctl.as_mut_ptr().cast();
            msg.msg_controllen = mem::size_of_val(&ctl) as _;
            let n = libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
            assert!(n > 0);
            assert_eq!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
            let mut out = Vec::new();
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                assert_eq!((*c).cmsg_type, libc::SCM_RIGHTS);
                let n_fds = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / 4;
                for i in 0..n_fds {
                    out.push(OwnedFd::from_raw_fd(
                        *libc::CMSG_DATA(c).cast::<RawFd>().add(i),
                    ));
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            (String::from_utf8(buf[..n as usize].to_vec()).unwrap(), out)
        }
    }

    #[test]
    fn parse_args_canonical_ports() {
        for p in [1u16, 22, 80, 443, 1023] {
            assert_eq!(parse_args(&s(&["--port", &p.to_string()])), Ok(p));
        }
    }

    #[test]
    fn parse_args_rejects() {
        for bad in [
            &["--port", "0"][..],
            &["--port", "1024"],
            &["--port", "01"],
            &["--port", "+1"],
            &["--port", "-1"],
            &["--port", ""],
            &["--port", "65536"],
            &["--port", "80", "x"],
            &["--port"],
            &["--prt", "80"],
            &["80"],
            &[],
            &["--version", "--port", "80"],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(Fail::BadArgs), "{bad:?}");
        }
    }

    #[test]
    fn parse_uid_overflow() {
        assert_eq!(parse_uid(Some("0")), Some(0));
        assert_eq!(parse_uid(Some("1000")), Some(1000));
        assert_eq!(parse_uid(Some("4294967294")), Some(4294967294));
        for bad in [
            None,
            Some(""),
            Some("4294967295"),
            Some("4294967296"),
            Some("99999999999999999999"),
            Some("+1"),
            Some("-1"),
            Some("01"),
            Some("1 "),
            Some("0x10"),
        ] {
            assert_eq!(parse_uid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn channel_checks_reject_wrong_type_and_peer() {
        let (t, d) = (Some(libc::SOCK_SEQPACKET), Some(libc::AF_UNIX));
        assert_eq!(channel_checks(t, d, Some(1000), 1000), Ok(()));
        assert_eq!(
            channel_checks(Some(libc::SOCK_STREAM), d, Some(1000), 1000),
            Err(Fail::BadChannel)
        );
        assert_eq!(
            channel_checks(t, Some(libc::AF_INET), Some(1000), 1000),
            Err(Fail::BadChannel)
        );
        assert_eq!(
            channel_checks(None, d, Some(1000), 1000),
            Err(Fail::BadChannel)
        );
        assert_eq!(
            channel_checks(t, d, Some(1001), 1000),
            Err(Fail::BadChannel)
        );
        assert_eq!(channel_checks(t, d, None, 1000), Err(Fail::BadChannel));
        assert!(!is_seqpacket(Some(libc::SOCK_DGRAM), d));
    }

    #[test]
    fn reply_format() {
        assert_eq!(
            reply_ok(443, 2, false),
            format!("cainary-bind-helper/1 ok 443 2 {VERSION}")
        );
        assert_eq!(
            reply_ok(80, 1, true),
            format!("cainary-bind-helper/1 ok 80 1 {VERSION} ipv6-unavailable")
        );
        assert_eq!(
            reply_error(&Fail::PortInUse),
            "cainary-bind-helper/1 error port-in-use"
        );
    }

    #[test]
    fn bind_and_send_passes_two_loopback_listeners() {
        let port = free_port();
        let (helper_end, tray_end) = pair();
        bind_and_send(port, helper_end.as_raw_fd(), bind_loopback).unwrap();
        let (line, fds) = recv(&tray_end);
        assert!(
            line.starts_with(&format!("cainary-bind-helper/1 ok {port} {} ", fds.len())),
            "{line}"
        );
        assert_eq!(line.ends_with("ipv6-unavailable"), fds.len() == 1);
        assert!(!fds.is_empty());
        for (fd, fam) in fds.iter().zip([Fam::V4, Fam::V6]) {
            assert!(self_check(fd, fam, port));
            let flags = sockopt_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT);
            assert_eq!(flags, Some(0));
            // SAFETY: the listening socket is moved into the TcpListener.
            let l = unsafe { TcpListener::from_raw_fd(libc::dup(fd.as_raw_fd())) };
            let addr = l.local_addr().unwrap();
            assert!(addr.ip().is_loopback() && addr.port() == port);
            let _client = TcpStream::connect(addr).unwrap();
            l.accept().unwrap();
        }
    }

    #[test]
    fn ipv6_in_use_fails_closed() {
        let Ok(held) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return;
        };
        let port = held.local_addr().unwrap().port();
        let (helper_end, tray_end) = pair();
        assert_eq!(
            bind_and_send(port, helper_end.as_raw_fd(), bind_loopback),
            Err(Fail::PortInUse)
        );
        // Nothing was sent: the channel is empty.
        let mut b = [0u8; 8];
        // SAFETY: `b` is valid for the call.
        let n = unsafe {
            libc::recv(
                tray_end.as_raw_fd(),
                b.as_mut_ptr().cast(),
                8,
                libc::MSG_DONTWAIT,
            )
        };
        assert_eq!(n, -1);
        // IPv4 was released again, so the same port can be bound there.
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
    }

    #[test]
    fn ipv6_unavailable_continues_with_ipv4_only() {
        fn no_v6(fam: Fam, port: u16) -> Result<OwnedFd, i32> {
            if fam == Fam::V6 {
                Err(libc::EAFNOSUPPORT)
            } else {
                bind_loopback(fam, port)
            }
        }
        let port = free_port();
        let (helper_end, tray_end) = pair();
        bind_and_send(port, helper_end.as_raw_fd(), no_v6).unwrap();
        let (line, fds) = recv(&tray_end);
        assert_eq!(fds.len(), 1);
        assert!(line.ends_with("ipv6-unavailable"));
    }
}
