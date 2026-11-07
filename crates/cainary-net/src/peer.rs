//! Which local user owns a loopback client's socket (design D3). Pure parsers over the text of
//! `/proc/net/tcp` and `/proc/net/tcp6`; reading them is `peer_proc.rs`, so this
//! module touches no file, no socket and no `std::net` type (guards N1/N2).
//!
//! A row matches when its local address is the client's socket, its remote address is the very
//! socket the collector accepted on (same address, and the listening port or the public one a
//! redirect forwards from), and the connection is live (ESTABLISHED, FIN_WAIT1, FIN_WAIT2): never
//! TIME_WAIT, whose row keeps the uid of an old connection (or 0).
//!
//! Tables are read line by line: constant memory however many sockets the machine has.

use std::io::{self, BufRead};

/// Longest line considered; real rows are well under 200 bytes.
const MAX_LINE: usize = 512;
/// `sl local rem st queues timer retrnsmt uid timeout inode`; later columns vary by kernel.
const MIN_COLUMNS: usize = 10;

const ST_ESTABLISHED: u8 = 0x01;
const ST_FIN_WAIT1: u8 = 0x04;
const ST_FIN_WAIT2: u8 = 0x05;

/// An IP address and port, normalised to 16 bytes: IPv4 is stored v4-mapped, so a v4 client and
/// the same address seen in `tcp6` compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    ip: [u8; 16],
    port: u16,
}

impl Endpoint {
    pub fn v4(octets: [u8; 4], port: u16) -> Endpoint {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&octets);
        Endpoint { ip, port }
    }

    pub fn v6(octets: [u8; 16], port: u16) -> Endpoint {
        Endpoint { ip: octets, port }
    }
}

/// The collector's side of a connection: the address the connection was accepted on, and the
/// port a redirect forwards from when it isn't the listening one (takeover on a privileged
/// port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server {
    pub endpoint: Endpoint,
    pub public_port: Option<u16>,
}

impl Server {
    /// Whether `remote` is where a client of this collector connects.
    fn is_target(&self, remote: Endpoint) -> bool {
        remote.ip == self.endpoint.ip
            && (remote.port == self.endpoint.port || Some(remote.port) == self.public_port)
    }
}

/// The outcome of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Uid(u32),
    NotFound,
    Ambiguous,
}

/// Sockets matching so far: the uid of the first, and one key per distinct socket. The kernel
/// writes the tables in chunks, so a busy machine can show one row twice in a single read; a row
/// identical to an earlier one (same inode and socket pointer, only `sl` differs) is that socket
/// again, not a second one.
#[derive(Debug, Default, Clone)]
struct Found {
    uid: u32,
    keys: Vec<String>,
}

impl Found {
    /// `key` is the row without its `sl` column.
    fn add(&mut self, uid: u32, key: String) {
        if self.keys.is_empty() {
            self.uid = uid;
        }
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }

    fn lookup(&self, count: usize) -> Lookup {
        match count {
            0 => Lookup::NotFound,
            1 => Lookup::Uid(self.uid),
            _ => Lookup::Ambiguous,
        }
    }
}

/// Parse `HEX_IP:HEX_PORT`. The kernel prints each 32-bit word of the address in host byte order,
/// so words are decoded with native-endian byte semantics (`0100007F` is 127.0.0.1 on a
/// little-endian machine); the port is a plain big-endian number.
fn parse_endpoint(s: &str) -> Option<Endpoint> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16)
        .ok()
        .filter(|_| port.len() == 4)?;
    if !ip.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let word = |i: usize| u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).map(u32::to_ne_bytes);
    match ip.len() {
        8 => Some(Endpoint::v4(word(0).ok()?, port)),
        32 => {
            let mut octets = [0u8; 16];
            for i in 0..4 {
                octets[i * 4..i * 4 + 4].copy_from_slice(&word(i).ok()?);
            }
            Some(Endpoint::v6(octets, port))
        }
        _ => None,
    }
}

/// Fill `line` with the next line of `table` (without its `\n`), keeping at most `MAX_LINE + 1`
/// bytes of it: the rest of a longer line is consumed and dropped. `false` at the end.
fn next_line(table: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    let mut any = false;
    loop {
        let chunk = table.fill_buf()?;
        if chunk.is_empty() {
            return Ok(any);
        }
        any = true;
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i, true),
            None => (chunk.len(), false),
        };
        let room = (MAX_LINE + 1).saturating_sub(line.len());
        line.extend_from_slice(&chunk[..take.min(room)]);
        table.consume(take + usize::from(done));
        if done {
            return Ok(true);
        }
    }
}

/// Scan one table, counting the sockets that match.
fn scan(mut table: impl BufRead, client: Endpoint, server: Server) -> io::Result<Found> {
    let mut found = Found::default();
    let mut buf = Vec::new();
    let mut first = true;
    while next_line(&mut table, &mut buf)? {
        if std::mem::take(&mut first) || buf.len() > MAX_LINE {
            continue;
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            continue;
        };
        let mut cols = line.split_ascii_whitespace();
        let (Some(_sl), Some(local), Some(remote), Some(state)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        // `tx:rx`, timer, retransmits, then the uid; at least the inode must follow.
        let rest: Vec<&str> = cols.take(MIN_COLUMNS).collect();
        if rest.len() < MIN_COLUMNS - 4 {
            continue;
        }
        let Some(uid) = rest[3].parse::<u32>().ok() else {
            continue;
        };
        let Some(state) = u8::from_str_radix(state, 16).ok() else {
            continue;
        };
        if !matches!(state, ST_ESTABLISHED | ST_FIN_WAIT1 | ST_FIN_WAIT2) {
            continue;
        }
        // Timer 3 is the TIME_WAIT timer: an orphaned socket, whose uid reads as 0.
        if rest[1].split(':').next() == Some("03") {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_endpoint(local), parse_endpoint(remote)) else {
            continue;
        };
        if local == client && server.is_target(remote) {
            let key: Vec<&str> = line.split_ascii_whitespace().skip(1).collect();
            found.add(uid, key.join(" "));
        }
    }
    Ok(found)
}

/// Look `client` up in one table (`/proc/net/tcp` or `tcp6`).
pub fn lookup(table: impl BufRead, client: Endpoint, server: Server) -> io::Result<Lookup> {
    let found = scan(table, client, server)?;
    Ok(found.lookup(found.keys.len()))
}

/// Look `client` up in both tables; a match in each, or two in one, is `Ambiguous`.
pub fn lookup_all(
    tcp: impl BufRead,
    tcp6: impl BufRead,
    client: Endpoint,
    server: Server,
) -> io::Result<Lookup> {
    let a = scan(tcp, client, server)?;
    let b = scan(tcp6, client, server)?;
    // A socket is in one table, so a match in each is two sockets.
    let uid = if a.keys.is_empty() { b.uid } else { a.uid };
    Ok(Found {
        uid,
        keys: Vec::new(),
    }
    .lookup(a.keys.len() + b.keys.len()))
}

/// The effective uid from the text of `/proc/self/status` (`Uid:\treal\teffective\tsaved\tfs`).
/// Unlike the owner of `/proc/self`, which is root for a process that isn't dumpable (a binary
/// with a file capability), this is always the process's own.
pub fn parse_euid(status: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(status).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut ids = line.split_ascii_whitespace();
    let (_real, effective) = (ids.next()?, ids.next()?);
    effective.parse().ok()
}

/// A bare decimal uid, as `/proc/sys/kernel/overflowuid` holds it.
pub fn parse_uid(text: &[u8]) -> Option<u32> {
    std::str::from_utf8(text).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv() -> Server {
        Server {
            endpoint: Endpoint::v4(LO, PORT),
            public_port: None,
        }
    }

    fn srv_public(port: u16) -> Server {
        Server {
            public_port: Some(port),
            ..srv()
        }
    }

    fn lookup(t: &[u8], client: Endpoint, server: Server) -> Lookup {
        super::lookup(t, client, server).unwrap()
    }

    fn lookup_all(a: &[u8], b: &[u8], client: Endpoint, server: Server) -> Lookup {
        super::lookup_all(a, b, client, server).unwrap()
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    /// Encode as the kernel does: 32-bit words in host byte order, port as big-endian hex.
    fn hex_ip(octets: &[u8]) -> String {
        octets
            .chunks(4)
            .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
            .collect()
    }

    fn v4_str(o: [u8; 4], port: u16) -> String {
        format!("{}:{port:04X}", hex_ip(&o))
    }

    fn v6_str(o: [u8; 16], port: u16) -> String {
        format!("{}:{port:04X}", hex_ip(&o))
    }

    fn mapped(o: [u8; 4]) -> [u8; 16] {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&o);
        ip
    }

    const LO: [u8; 4] = [127, 0, 0, 1];
    const LO6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    fn row(sl: u32, local: &str, remote: &str, st: u8, uid: u32) -> String {
        row_inode(sl, local, remote, st, uid, 12345)
    }

    fn row_inode(sl: u32, local: &str, remote: &str, st: u8, uid: u32, inode: u64) -> String {
        format!(
            "{sl:4}: {local} {remote} {st:02X} 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 1 0000000000000000 20 4 30 10 -1\n"
        )
    }

    fn table(rows: &[String]) -> Vec<u8> {
        let mut t = HEADER.to_string();
        for r in rows {
            t.push_str(r);
        }
        t.into_bytes()
    }

    const PORT: u16 = 4318;

    #[test]
    fn hex_decoding_matches_the_kernel_format() {
        let ep = parse_endpoint(&v4_str(LO, 8080)).unwrap();
        assert_eq!(ep, Endpoint::v4(LO, 8080));
        let ep = parse_endpoint(&v6_str(LO6, 1)).unwrap();
        assert_eq!(ep, Endpoint::v6(LO6, 1));
        #[cfg(target_endian = "little")]
        {
            assert_eq!(
                parse_endpoint("0100007F:1F90"),
                Some(Endpoint::v4(LO, 8080))
            );
            assert_eq!(
                parse_endpoint("00000000000000000000000001000000:0050"),
                Some(Endpoint::v6(LO6, 80))
            );
        }
    }

    #[test]
    fn realistic_table_picks_the_live_client_row() {
        let client = Endpoint::v4(LO, 51234);
        let t = table(&[
            row(0, &v4_str([0; 4], PORT), &v4_str([0; 4], 0), 0x0A, 1000),
            // server side of the connection: local is the server port
            row(1, &v4_str(LO, PORT), &v4_str(LO, 51234), 0x01, 1000),
            // the client's own socket
            row(2, &v4_str(LO, 51234), &v4_str(LO, PORT), 0x01, 1234),
            // an old connection on the same 4-tuple
            row(3, &v4_str(LO, 51234), &v4_str(LO, PORT), 0x06, 0),
            // another user's connection
            row(4, &v4_str(LO, 51300), &v4_str(LO, PORT), 0x01, 4321),
        ]);
        assert_eq!(lookup(&t, client, srv_public(443)), Lookup::Uid(1234));
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 51300), srv()),
            Lookup::Uid(4321)
        );
        assert_eq!(lookup(&t, Endpoint::v4(LO, 51999), srv()), Lookup::NotFound);
    }

    #[test]
    fn time_wait_alone_is_not_found() {
        let t = table(&[row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 0x06, 0)]);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 5), srv()), Lookup::NotFound);
    }

    #[test]
    fn states_accepted() {
        for (st, want) in [
            (0x01, Lookup::Uid(7)),
            (0x04, Lookup::Uid(7)),
            (0x05, Lookup::Uid(7)),
            (0x02, Lookup::NotFound),
            (0x06, Lookup::NotFound),
            (0x08, Lookup::NotFound),
            (0x0A, Lookup::NotFound),
        ] {
            let t = table(&[row(0, &v4_str(LO, 5), &v4_str(LO, PORT), st, 7)]);
            assert_eq!(
                lookup(&t, Endpoint::v4(LO, 5), srv()),
                want,
                "state {st:02X}"
            );
        }
    }

    /// The remote must be the very socket the connection was accepted on: not another loopback
    /// address, not another port, unless the port is the public one.
    #[test]
    fn remote_must_be_this_collectors_socket() {
        let t = table(&[
            row(0, &v4_str(LO, 5), &v4_str([127, 0, 0, 2], PORT), 1, 7),
            row(1, &v4_str(LO, 6), &v4_str(LO, 9999), 1, 8),
            row(2, &v4_str(LO, 7), &v4_str([10, 0, 0, 1], PORT), 1, 9),
            row(3, &v4_str(LO, 8), &v4_str(LO, 443), 1, 10),
        ]);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 5), srv()), Lookup::NotFound);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 6), srv()), Lookup::NotFound);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 7), srv()), Lookup::NotFound);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 8), srv()), Lookup::NotFound);
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 8), srv_public(443)),
            Lookup::Uid(10)
        );
        // The public port is only for the same address.
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 5), srv_public(PORT)),
            Lookup::NotFound
        );
        // A collector on 127.0.0.2 doesn't take a client of 127.0.0.1.
        let other = Server {
            endpoint: Endpoint::v4([127, 0, 0, 2], PORT),
            public_port: None,
        };
        assert_eq!(lookup(&t, Endpoint::v4(LO, 5), other), Lookup::Uid(7));
        assert_eq!(lookup(&t, Endpoint::v4(LO, 8), other), Lookup::NotFound);
    }

    #[test]
    fn timer_3_rows_are_skipped() {
        let local = v4_str(LO, 5);
        let remote = v4_str(LO, PORT);
        let orphan = format!(
            "   0: {local} {remote} 05 00000000:00000000 03:0000176F 00000000     0        0 0 3 0000000000000000\n"
        );
        assert_eq!(
            lookup(&table(&[orphan]), Endpoint::v4(LO, 5), srv()),
            Lookup::NotFound
        );
    }

    /// A line longer than `MAX_LINE` is skipped to its end, wherever the reader's chunks fall,
    /// and the rows around it still count.
    #[test]
    fn long_lines_are_skipped_across_chunk_boundaries() {
        let good = row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 7);
        let mut t = String::from(HEADER);
        t.push_str(&"x".repeat(5000));
        t.push('\n');
        t.push_str(&good);
        t.push_str(&"y".repeat(MAX_LINE * 3));
        let bytes = t.into_bytes();
        for cap in [1, 2, 7, 64, 512, 8192] {
            let r = std::io::BufReader::with_capacity(cap, &bytes[..]);
            assert_eq!(
                super::lookup(r, Endpoint::v4(LO, 5), srv()).unwrap(),
                Lookup::Uid(7),
                "buffer {cap}"
            );
        }
    }

    #[test]
    fn a_read_error_is_an_error() {
        struct Broken;
        impl io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
        }
        let r = io::BufReader::new(Broken);
        assert!(super::lookup(r, Endpoint::v4(LO, 5), srv()).is_err());
    }

    #[test]
    fn ipv6_rows() {
        let t = table(&[row(0, &v6_str(LO6, 40000), &v6_str(LO6, PORT), 1, 55)]);
        let srv6 = Server {
            endpoint: Endpoint::v6(LO6, PORT),
            public_port: None,
        };
        assert_eq!(lookup(&t, Endpoint::v6(LO6, 40000), srv6), Lookup::Uid(55));
        assert_eq!(lookup(&t, Endpoint::v4(LO, 40000), srv6), Lookup::NotFound);
        // ::1 and 127.0.0.1 are different collectors.
        assert_eq!(
            lookup(&t, Endpoint::v6(LO6, 40000), srv()),
            Lookup::NotFound
        );
    }

    #[test]
    fn v4_client_matches_a_v4_mapped_row_in_tcp6() {
        let t6 = table(&[row(
            0,
            &v6_str(mapped(LO), 41000),
            &v6_str(mapped(LO), PORT),
            1,
            99,
        )]);
        let client = Endpoint::v4(LO, 41000);
        assert_eq!(lookup(&t6, client, srv()), Lookup::Uid(99));
        assert_eq!(lookup_all(&table(&[]), &t6, client, srv()), Lookup::Uid(99));
    }

    #[test]
    fn two_sockets_are_ambiguous() {
        let local = v4_str(LO, 5);
        let remote = v4_str(LO, PORT);
        let a = row_inode(0, &local, &remote, 1, 7, 100);
        let b = row_inode(1, &local, &remote, 1, 7, 101);
        let two = table(&[a.clone(), b]);
        let client = Endpoint::v4(LO, 5);
        assert_eq!(lookup(&two, client, srv()), Lookup::Ambiguous);
        let one = table(&[a]);
        assert_eq!(lookup_all(&one, &one, client, srv()), Lookup::Ambiguous);
        assert_eq!(lookup_all(&one, &table(&[]), client, srv()), Lookup::Uid(7));
        assert_eq!(
            lookup_all(&table(&[]), &table(&[]), client, srv()),
            Lookup::NotFound
        );
    }

    /// The kernel can print a row twice when the table changes under a chunked read: `sl` differs,
    /// the rest is the same socket.
    #[test]
    fn a_row_printed_twice_is_one_socket() {
        let local = v4_str(LO, 5);
        let remote = v4_str(LO, PORT);
        let first = row_inode(2476, &local, &remote, 1, 7, 100);
        let again = row_inode(2480, &local, &remote, 1, 7, 100);
        let client = Endpoint::v4(LO, 5);
        assert_eq!(
            lookup(&table(&[first.clone(), again.clone()]), client, srv()),
            Lookup::Uid(7)
        );
        // An orphan (inode 0) in a different state is a different row.
        let orphan = row_inode(2481, &local, &remote, 5, 0, 0);
        assert_eq!(
            lookup(&table(&[first, again, orphan]), client, srv()),
            Lookup::Ambiguous
        );
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let good = row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 7);
        let mut t = String::from(HEADER);
        for bad in [
            "garbage\n",
            "\n",
            "   0: 0100007F:0005 0100007F:10DE 01\n",
            "   0: ZZZZZZZZ:0005 0100007F:10DE 01 a b c d 7 f 12\n",
            "   0: 0100007F:00ZZ 0100007F:10DE 01 a b c d 7 f 12\n",
            "   0: 0100007F:5 0100007F:10DE 01 a b c d 7 f 12\n",
            "   0: 0100007F0:0005 0100007F:10DE 01 a b c d 7 f 12\n",
            "   0: 0100007F:0005 0100007F:10DE 01 a b c d -7 f 12\n",
            "   0: 0100007F:0005 0100007F:10DE 01 a b c d x f 12\n",
            "   0: 0100007F:0005 0100007F:10DE 99999 a b c d 7 f 12\n",
        ] {
            t.push_str(bad);
        }
        t.push_str(&"x".repeat(100_000));
        t.push('\n');
        t.push_str(&good);
        t.push_str(&format!("{}\n", good.trim().repeat(10)));
        let mut bytes = t.into_bytes();
        bytes.extend_from_slice(b"\xff\xfe invalid utf8 \n");
        assert_eq!(lookup(&bytes, Endpoint::v4(LO, 5), srv()), Lookup::Uid(7));
    }

    #[test]
    fn uid_is_decimal_and_full_range() {
        let t = table(&[row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 4_294_967_294)]);
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 5), srv()),
            Lookup::Uid(4_294_967_294)
        );
    }

    #[test]
    fn header_only_and_empty_inputs() {
        assert_eq!(lookup(b"", Endpoint::v4(LO, 5), srv()), Lookup::NotFound);
        assert_eq!(
            lookup(HEADER.as_bytes(), Endpoint::v4(LO, 5), srv()),
            Lookup::NotFound
        );
    }

    #[test]
    fn fuzz_never_panics() {
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) as u32
        };
        let alphabet: &[u8] = b"0123456789ABCDEFabcdef: \n\t-xZ";
        let client = Endpoint::v4(LO, 5);
        for i in 0..10_000 {
            let len = (next() % 600) as usize;
            let mut t: Vec<u8> = Vec::with_capacity(len + 64);
            if i % 2 == 0 {
                t.extend_from_slice(HEADER.as_bytes());
                // plausible rows with one mutated byte
                let r = row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 7).into_bytes();
                t.extend_from_slice(&r);
                let at = next() as usize % t.len();
                t[at] = (next() & 0xff) as u8;
            }
            for _ in 0..len {
                let b = if next() % 8 == 0 {
                    (next() & 0xff) as u8
                } else {
                    alphabet[next() as usize % alphabet.len()]
                };
                t.push(b);
            }
            let _ = lookup(&t, client, srv());
            let _ = lookup_all(&t, &t, client, srv());
        }
    }

    #[test]
    fn euid_is_the_second_uid_field() {
        let status =
            b"Name:\tcainary\nUmask:\t0022\nUid:\t1000\t1001\t1002\t1003\nGid:\t1\t2\t3\t4\n";
        assert_eq!(parse_euid(status), Some(1001));
    }

    #[test]
    fn a_bare_uid_is_decimal() {
        assert_eq!(parse_uid(b"65534\n"), Some(65534));
        assert_eq!(parse_uid(b""), None);
        assert_eq!(parse_uid(b"-1"), None);
        assert_eq!(parse_uid(b"x"), None);
    }

    #[test]
    fn euid_needs_a_well_formed_uid_line() {
        assert_eq!(parse_euid(b"Name:\tx\n"), None);
        assert_eq!(parse_euid(b"Uid:\t1000\n"), None);
        assert_eq!(parse_euid(b"Uid:\t1000\tfoo\t1\t1\n"), None);
        assert_eq!(parse_euid(b"Uid:\t1000\t-1\t1\t1\n"), None);
        assert_eq!(parse_euid(b"\xff\xfe"), None);
        assert_eq!(parse_euid(b""), None);
    }
}
