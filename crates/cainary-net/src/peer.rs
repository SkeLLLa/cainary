//! Which local user owns a loopback client's socket (design D3). Pure parsers over the text of
//! `/proc/net/tcp` and `/proc/net/tcp6`; reading those files is the caller's business, so this
//! module touches no file, no socket and no `std::net` type (guards N1/N2).
//!
//! A row matches when its local address is the client's socket, its remote address is a loopback
//! address on one of the collector's ports, and the connection is live (ESTABLISHED, FIN_WAIT1,
//! FIN_WAIT2) — never TIME_WAIT, whose row keeps the uid of an old connection (or 0).

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

    fn is_loopback(&self) -> bool {
        let mapped = self.ip[..10].iter().all(|b| *b == 0) && self.ip[10..12] == [0xff, 0xff];
        let v6_loop = self.ip[..15].iter().all(|b| *b == 0) && self.ip[15] == 1;
        (mapped && self.ip[12] == 127) || v6_loop
    }
}

/// The outcome of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Uid(u32),
    NotFound,
    Ambiguous,
}

/// Rows matching so far: how many, and the uid of the first.
#[derive(Debug, Default, Clone, Copy)]
struct Found {
    count: u32,
    uid: u32,
}

impl Found {
    fn add(&mut self, uid: u32) {
        if self.count == 0 {
            self.uid = uid;
        }
        self.count = self.count.saturating_add(1);
    }

    fn lookup(self) -> Lookup {
        match self.count {
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

/// Scan one table, counting the rows that match.
fn scan(table: &[u8], client: Endpoint, server_ports: &[u16]) -> Found {
    let mut found = Found::default();
    for line in table.split(|b| *b == b'\n').skip(1) {
        if line.len() > MAX_LINE {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
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
        let (Some(local), Some(remote)) = (parse_endpoint(local), parse_endpoint(remote)) else {
            continue;
        };
        if local == client && remote.is_loopback() && server_ports.contains(&remote.port) {
            found.add(uid);
        }
    }
    found
}

/// Look `client` up in one table (the full text of `/proc/net/tcp` or `tcp6`).
pub fn lookup(table: &[u8], client: Endpoint, server_ports: &[u16]) -> Lookup {
    scan(table, client, server_ports).lookup()
}

/// Look `client` up in both tables; a match in each, or two in one, is `Ambiguous`.
pub fn lookup_all(tcp: &[u8], tcp6: &[u8], client: Endpoint, server_ports: &[u16]) -> Lookup {
    let a = scan(tcp, client, server_ports);
    let b = scan(tcp6, client, server_ports);
    Found {
        count: a.count.saturating_add(b.count),
        uid: if a.count > 0 { a.uid } else { b.uid },
    }
    .lookup()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        format!(
            "{sl:4}: {local} {remote} {st:02X} 00000000:00000000 00:00000000 00000000 {uid:5}        0 12345 1 0000000000000000 20 4 30 10 -1\n"
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
        assert!(ep.is_loopback());
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
    fn loopback_shapes() {
        assert!(Endpoint::v4([127, 9, 9, 9], 1).is_loopback());
        assert!(!Endpoint::v4([10, 0, 0, 1], 1).is_loopback());
        assert!(!Endpoint::v4([128, 0, 0, 1], 1).is_loopback());
        assert!(Endpoint::v6(mapped([127, 1, 2, 3]), 1).is_loopback());
        assert!(!Endpoint::v6(mapped([192, 168, 0, 1]), 1).is_loopback());
        assert!(!Endpoint::v6([0; 16], 1).is_loopback());
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
        assert_eq!(lookup(&t, client, &[PORT, 443]), Lookup::Uid(1234));
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 51300), &[PORT]),
            Lookup::Uid(4321)
        );
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 51999), &[PORT]),
            Lookup::NotFound
        );
    }

    #[test]
    fn time_wait_alone_is_not_found() {
        let t = table(&[row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 0x06, 0)]);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 5), &[PORT]), Lookup::NotFound);
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
                lookup(&t, Endpoint::v4(LO, 5), &[PORT]),
                want,
                "state {st:02X}"
            );
        }
    }

    #[test]
    fn remote_must_be_loopback_on_a_server_port() {
        let t = table(&[
            row(0, &v4_str(LO, 5), &v4_str([10, 0, 0, 1], PORT), 1, 7),
            row(1, &v4_str(LO, 6), &v4_str(LO, 9999), 1, 8),
        ]);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 5), &[PORT]), Lookup::NotFound);
        assert_eq!(lookup(&t, Endpoint::v4(LO, 6), &[PORT]), Lookup::NotFound);
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 6), &[PORT, 9999]),
            Lookup::Uid(8)
        );
        assert_eq!(lookup(&t, Endpoint::v4(LO, 6), &[]), Lookup::NotFound);
    }

    #[test]
    fn ipv6_rows() {
        let t = table(&[row(0, &v6_str(LO6, 40000), &v6_str(LO6, PORT), 1, 55)]);
        assert_eq!(
            lookup(&t, Endpoint::v6(LO6, 40000), &[PORT]),
            Lookup::Uid(55)
        );
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 40000), &[PORT]),
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
        assert_eq!(lookup(&t6, client, &[PORT]), Lookup::Uid(99));
        assert_eq!(
            lookup_all(&table(&[]), &t6, client, &[PORT]),
            Lookup::Uid(99)
        );
    }

    #[test]
    fn duplicates_are_ambiguous() {
        let r = row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 7);
        let two = table(&[r.clone(), r.clone()]);
        let client = Endpoint::v4(LO, 5);
        assert_eq!(lookup(&two, client, &[PORT]), Lookup::Ambiguous);
        let one = table(&[r]);
        assert_eq!(lookup_all(&one, &one, client, &[PORT]), Lookup::Ambiguous);
        assert_eq!(
            lookup_all(&one, &table(&[]), client, &[PORT]),
            Lookup::Uid(7)
        );
        assert_eq!(
            lookup_all(&table(&[]), &table(&[]), client, &[PORT]),
            Lookup::NotFound
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
        assert_eq!(lookup(&bytes, Endpoint::v4(LO, 5), &[PORT]), Lookup::Uid(7));
    }

    #[test]
    fn uid_is_decimal_and_full_range() {
        let t = table(&[row(0, &v4_str(LO, 5), &v4_str(LO, PORT), 1, 4_294_967_294)]);
        assert_eq!(
            lookup(&t, Endpoint::v4(LO, 5), &[PORT]),
            Lookup::Uid(4_294_967_294)
        );
    }

    #[test]
    fn header_only_and_empty_inputs() {
        assert_eq!(lookup(b"", Endpoint::v4(LO, 5), &[PORT]), Lookup::NotFound);
        assert_eq!(
            lookup(HEADER.as_bytes(), Endpoint::v4(LO, 5), &[PORT]),
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
            let _ = lookup(&t, client, &[PORT]);
            let _ = lookup_all(&t, &t, client, &[PORT]);
        }
    }
}
