//! Reads `/proc/net/tcp`, `/proc/net/tcp6` and `/proc/self/status` for the own-user check
//! (design D3). The only file here is the kernel's own, read-only and size-capped; parsing is
//! `peer.rs`, which touches no file, so guard N2's `std::fs` exemption covers just this module.

use crate::peer;
use std::io::{self, Read};

/// A table longer than this is treated as unreadable: nothing is guessed from a truncated one.
pub const MAX_TABLE_BYTES: u64 = 8 << 20;
const MAX_STATUS_BYTES: u64 = 64 << 10;

fn read_capped(path: &str, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(cap + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path} is over {cap} bytes"),
        ));
    }
    Ok(bytes)
}

/// The IPv4 and IPv6 tables. A missing `tcp6` (a kernel without IPv6) is an empty table.
pub fn read_tables() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let tcp = read_capped("/proc/net/tcp", MAX_TABLE_BYTES)?;
    let tcp6 = match read_capped("/proc/net/tcp6", MAX_TABLE_BYTES) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        other => other?,
    };
    Ok((tcp, tcp6))
}

/// This process's effective uid, as the kernel reports it.
pub fn euid() -> io::Result<u32> {
    let status = read_capped("/proc/self/status", MAX_STATUS_BYTES)?;
    peer::parse_euid(&status).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no Uid line in /proc/self/status",
        )
    })
}
