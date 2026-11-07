//! A stand-in for `pkexec <helper>` in tests (feature `test-fakes`). It ignores the polkit flag
//! and the helper path, checks the rest of the command line, and then behaves as the mode named
//! by the last component of its own path (tests symlink it under each mode's name): it binds
//! loopback sockets on the port it is given and sends them down fd 1 the way the real helper does,
//! or misbehaves in one specific way.

use std::process::exit;

const PROTOCOL: &str = "cainary-bind-helper/1";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args[0].rsplit('/').next().unwrap_or("").to_owned();
    let port = match args[1..] {
        [ref flag, ref _helper, ref port_flag, ref port]
            if flag == "--disable-internal-agent" && port_flag == "--port" =>
        {
            port.parse::<u16>().unwrap_or(0)
        }
        _ => {
            eprintln!("fake-pkexec: unexpected arguments {:?}", &args[1..]);
            exit(2);
        }
    };
    let version = env!("CARGO_PKG_VERSION");
    let ok = |count: usize| format!("{PROTOCOL} ok {port} {count} {version}");
    match mode.as_str() {
        "ok" => reply(&ok(2), &[listen_v4(port), listen_v6(port)]),
        "extra-socket" => reply(&ok(2), &[listen_v4(port), listen_v6(port), listen_v4(0)]),
        "three-extra-sockets" => reply(
            &ok(2),
            &[listen_v4(port), listen_v6(port), listen_v4(0), listen_v4(0)],
        ),
        "wildcard" => reply(
            &ok(2),
            &[
                listen_on(libc::AF_INET, [0; 16], port, true),
                listen_v6(port),
            ],
        ),
        "udp" => reply(
            &ok(2),
            &[bind_v4(libc::SOCK_DGRAM, port, false), listen_v6(port)],
        ),
        "not-listening" => reply(
            &ok(2),
            &[bind_v4(libc::SOCK_STREAM, port, false), listen_v6(port)],
        ),
        "wrong-port" => reply(&ok(2), &[listen_v4(0), listen_v6(0)]),
        "garbage-reply" => reply("hello there", &[listen_v4(port), listen_v6(port)]),
        "protocol-2" => reply(
            &ok(2).replace("/1", "/2"),
            &[listen_v4(port), listen_v6(port)],
        ),
        "duplicate-family" => {
            let both = listen_v4(port);
            reply(&ok(2), &[both, both]);
        }
        "empty-with-fds" => {
            let one = listen_v4(port);
            reply("", &[one, one]);
        }
        "sctp" => reply(&ok(2), &[listen_sctp(port), listen_v6(port)]),
        "many-sockets" => {
            let one = listen_v4(port);
            reply(&ok(2), &[one; 40]);
        }
        "ipv6-unavailable" => reply(&format!("{} ipv6-unavailable", ok(1)), &[listen_v4(port)]),
        "ipv6-claimed-but-missing" => reply(&ok(2), &[listen_v4(port)]),
        "port-in-use" => {
            reply(&format!("{PROTOCOL} error port-in-use"), &[]);
            exit(1);
        }
        "ok-then-exit-1" => {
            reply(&ok(2), &[listen_v4(port), listen_v6(port)]);
            exit(1);
        }
        "exit-126" => exit(126),
        "exit-127-no-reply" => exit(127),
        "no-reply-exit-0" => exit(0),
        "never-replies" => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
        other => {
            eprintln!("fake-pkexec: unknown mode {other:?}");
            exit(2);
        }
    }
}

fn listen_v4(port: u16) -> libc::c_int {
    bind_v4(libc::SOCK_STREAM, port, true)
}

fn bind_v4(kind: libc::c_int, port: u16, listen: bool) -> libc::c_int {
    let mut address = [0; 16];
    address[..4].copy_from_slice(&[127, 0, 0, 1]);
    let fd = socket(libc::AF_INET, kind);
    bind_to(fd, libc::AF_INET, address, port);
    if listen {
        start_listening(fd);
    }
    fd
}

fn listen_v6(port: u16) -> libc::c_int {
    let mut address = [0; 16];
    address[15] = 1;
    listen_on(libc::AF_INET6, address, port, true)
}

fn listen_on(family: libc::c_int, address: [u8; 16], port: u16, listen: bool) -> libc::c_int {
    let fd = socket(family, libc::SOCK_STREAM);
    if family == libc::AF_INET6 {
        let one: libc::c_int = 1;
        // SAFETY: an int option on a socket we own.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    bind_to(fd, family, address, port);
    if listen {
        start_listening(fd);
    }
    fd
}

/// A listening SCTP stream socket on 127.0.0.1. Exits 77 when the kernel has no SCTP.
fn listen_sctp(port: u16) -> libc::c_int {
    let mut address = [0; 16];
    address[..4].copy_from_slice(&[127, 0, 0, 1]);
    let fd = socket_with(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_SCTP);
    bind_to(fd, libc::AF_INET, address, port);
    start_listening(fd);
    fd
}

fn socket(family: libc::c_int, kind: libc::c_int) -> libc::c_int {
    socket_with(family, kind, 0)
}

fn socket_with(family: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> libc::c_int {
    // SAFETY: plain socket creation.
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 && protocol != 0 {
        eprintln!("fake-pkexec: protocol {protocol} unavailable");
        exit(77);
    }
    if fd < 0 {
        eprintln!("fake-pkexec: socket: {}", std::io::Error::last_os_error());
        exit(3);
    }
    fd
}

fn bind_to(fd: libc::c_int, family: libc::c_int, address: [u8; 16], port: u16) {
    // SAFETY: the sockaddr structs are plain data, zeroed and then filled, and the length passed
    // matches the struct.
    let rc = unsafe {
        if family == libc::AF_INET {
            let mut a: libc::sockaddr_in = std::mem::zeroed();
            a.sin_family = libc::AF_INET as libc::sa_family_t;
            a.sin_port = port.to_be();
            a.sin_addr.s_addr =
                u32::from_ne_bytes([address[0], address[1], address[2], address[3]]);
            libc::bind(
                fd,
                (&a as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } else {
            let mut a: libc::sockaddr_in6 = std::mem::zeroed();
            a.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            a.sin6_port = port.to_be();
            a.sin6_addr.s6_addr = address;
            libc::bind(
                fd,
                (&a as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    if rc != 0 {
        eprintln!("fake-pkexec: bind: {}", std::io::Error::last_os_error());
        exit(4);
    }
}

fn start_listening(fd: libc::c_int) {
    // SAFETY: listen on a socket we own.
    if unsafe { libc::listen(fd, 16) } != 0 {
        eprintln!("fake-pkexec: listen: {}", std::io::Error::last_os_error());
        exit(5);
    }
}

/// One datagram on fd 1, with `fds` attached as SCM_RIGHTS.
fn reply(text: &str, fds: &[libc::c_int]) {
    let mut iov = libc::iovec {
        iov_base: text.as_ptr() as *mut libc::c_void,
        iov_len: text.len(),
    };
    let mut control = [0_u64; 64];
    // SAFETY: msghdr is plain data; every pointer set below outlives the sendmsg call, and the
    // control buffer is large enough for the few descriptors a test sends.
    let rc = unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !fds.is_empty() {
            let bytes = std::mem::size_of_val(fds);
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(bytes as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&message);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(bytes as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());
        }
        libc::sendmsg(1, &message, libc::MSG_NOSIGNAL)
    };
    if rc < 0 {
        eprintln!("fake-pkexec: sendmsg: {}", std::io::Error::last_os_error());
        exit(6);
    }
}
