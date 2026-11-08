//! Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/self/status` and `/proc/sys/kernel/overflowuid`
//! for the own-user check. The only files here are those four fixed kernel paths,
//! read-only; parsing is `peer.rs`, which touches no file, so guard N2's `std::fs` exemption
//! covers just this module.

use crate::peer::{self, Endpoint, Lookup, Server};
use std::io::{self, BufRead, BufReader, Read};

/// Tables are streamed through a buffer this size, a line at a time: constant memory however
/// many sockets there are.
const TABLE_BUFFER: usize = 64 << 10;
const MAX_SMALL_FILE: u64 = 64 << 10;
/// What the kernel maps an unmappable uid to unless `/proc/sys/kernel/overflowuid` says otherwise.
const DEFAULT_OVERFLOW_UID: u32 = 65534;

fn table(path: &str) -> io::Result<BufReader<std::fs::File>> {
    Ok(BufReader::with_capacity(
        TABLE_BUFFER,
        std::fs::File::open(path)?,
    ))
}

/// Find `client`'s socket in `/proc/net/tcp` and `tcp6`. A missing `tcp6` (a kernel without
/// IPv6) is an empty table.
pub fn lookup(client: Endpoint, server: Server) -> io::Result<Lookup> {
    let tcp = table("/proc/net/tcp")?;
    let tcp6: Box<dyn BufRead> = match table("/proc/net/tcp6") {
        Ok(t) => Box::new(t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Box::new(io::empty()),
        Err(e) => return Err(e),
    };
    peer::lookup_all(tcp, tcp6, client, server)
}

fn read_small(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_SMALL_FILE)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// This process's effective uid, as the kernel reports it.
pub fn euid() -> io::Result<u32> {
    peer::parse_euid(&read_small("/proc/self/status")?).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no Uid line in /proc/self/status",
        )
    })
}

/// The uid the kernel shows for a user it can't map (another user namespace, and orphaned
/// sockets in some kernels); a row with this uid says nothing about who owns the socket.
pub fn overflow_uid() -> u32 {
    read_small("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|b| peer::parse_uid(&b))
        .unwrap_or(DEFAULT_OVERFLOW_UID)
}
