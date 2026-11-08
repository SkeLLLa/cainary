//! The pure core: what `set` and `clear` do to the bytes of `/etc/hosts`. No file access, no `libc`.

use crate::helper::Fail;

pub const BEGIN: &str = "# >>> cAInary takeover: managed by cAInary, lines in here are replaced; remove with the app >>>";
pub const END: &str = "# <<< cAInary takeover <<<";

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Set(Vec<String>),
    Clear,
}

impl Op {
    pub fn word(&self) -> &'static str {
        match self {
            Op::Set(_) => "set",
            Op::Clear => "clear",
        }
    }
}

/// One line: its byte range, whole (`start..end`, terminator included) and without the terminator
/// (`start..content_end`). The terminator is `\n`, `\r\n` or empty (an unterminated rest at EOF).
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
}

fn split_lines(bytes: &[u8]) -> Vec<Line> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        match bytes[start..].iter().position(|b| *b == b'\n') {
            Some(offset) => {
                let nl = start + offset;
                let cr = nl > start && bytes[nl - 1] == b'\r';
                out.push(Line {
                    start,
                    content_end: if cr { nl - 1 } else { nl },
                    end: nl + 1,
                });
                start = nl + 1;
            }
            None => {
                out.push(Line {
                    start,
                    content_end: bytes.len(),
                    end: bytes.len(),
                });
                start = bytes.len();
            }
        }
    }
    out
}

fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Not a marker, but a comment that mentions the takeover (ASCII case-insensitive).
fn is_malformed_marker(content: &[u8]) -> bool {
    let start = content
        .iter()
        .position(|b| !is_blank(*b))
        .unwrap_or(content.len());
    let rest = &content[start..];
    rest.first() == Some(&b'#')
        && rest
            .windows(b"cainary takeover".len())
            .any(|w| w.eq_ignore_ascii_case(b"cainary takeover"))
}

/// The indexes of the begin and end marker lines: `None` without any marker; `DamagedBlock` for
/// anything but exactly one begin before one end and no malformed marker.
fn layout(bytes: &[u8], lines: &[Line]) -> Result<Option<(usize, usize)>, Fail> {
    let (mut begins, mut ends) = (Vec::new(), Vec::new());
    for (i, l) in lines.iter().enumerate() {
        let content = &bytes[l.start..l.content_end];
        if content == BEGIN.as_bytes() {
            begins.push(i);
        } else if content == END.as_bytes() {
            ends.push(i);
        } else if is_malformed_marker(content) {
            return Err(Fail::DamagedBlock);
        }
    }
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        _ => Err(Fail::DamagedBlock),
    }
}

/// `127.0.0.1 HOST` then `::1 HOST` per name, each checked against `[a-z0-9.:-]` plus one space.
fn block_lines(hosts: &[String]) -> Result<Vec<String>, Fail> {
    if hosts.is_empty() || hosts.iter().any(String::is_empty) {
        return Err(Fail::BadArgs);
    }
    let mut out = Vec::new();
    for h in hosts {
        out.push(format!("127.0.0.1 {h}"));
        out.push(format!("::1 {h}"));
    }
    for line in &out {
        let spaces = line.bytes().filter(|b| *b == b' ').count();
        let charset = line.bytes().all(|b| {
            b == b' ' || b.is_ascii_lowercase() || b.is_ascii_digit() || b".:-".contains(&b)
        });
        if spaces != 1 || !charset {
            return Err(Fail::BadArgs);
        }
    }
    Ok(out)
}

/// The new bytes for `old`. `old` itself back (as a copy) means there is nothing to write.
pub fn edit(old: &[u8], op: &Op) -> Result<Vec<u8>, Fail> {
    let lines = split_lines(old);
    let block = layout(old, &lines)?;
    let term = |l: &Line| &old[l.content_end..l.end];
    match (op, block) {
        (Op::Clear, None) => Ok(old.to_vec()),
        (Op::Clear, Some((b, e))) => {
            let mut out = old[..lines[b].start].to_vec();
            out.extend_from_slice(&old[lines[e].end..]);
            Ok(out)
        }
        (Op::Set(hosts), block) => {
            let body = block_lines(hosts)?;
            // The terminator of the lines written, and of the end marker.
            let (t, end_term): (&[u8], &[u8]) = match block {
                Some((b, e)) => {
                    let t = term(&lines[b]);
                    // At EOF with nothing after it, the end marker keeps its own style.
                    let end_term = if lines[e].end == old.len() {
                        term(&lines[e])
                    } else {
                        t
                    };
                    (t, end_term)
                }
                None => match lines.first().map(term) {
                    Some(t) if !t.is_empty() => (t, t),
                    _ => (b"\n", b"\n"),
                },
            };
            let (head, tail) = match block {
                Some((b, e)) => (&old[..lines[b].start], &old[lines[e].end..]),
                None => (old, &old[old.len()..]),
            };
            let mut out = head.to_vec();
            if block.is_none() && !out.is_empty() && out.last() != Some(&b'\n') {
                out.extend_from_slice(t);
            }
            out.extend_from_slice(BEGIN.as_bytes());
            out.extend_from_slice(t);
            for l in &body {
                out.extend_from_slice(l.as_bytes());
                out.extend_from_slice(t);
            }
            out.extend_from_slice(END.as_bytes());
            out.extend_from_slice(end_term);
            out.extend_from_slice(tail);
            Ok(out)
        }
    }
}

/// Reserved because of an unmanaged line (outside the block) that names both the node name (or its
/// first label) and one of `hosts`: `127.0.1.1 myhost.corp.example myhost`. `node` is lowercase.
pub fn alias_conflict(old: &[u8], hosts: &[String], node: &str) -> Result<(), Fail> {
    if node.is_empty() {
        return Ok(());
    }
    let first = node.split('.').next().unwrap_or(node);
    let lines = split_lines(old);
    let block = layout(old, &lines)?;
    for (i, l) in lines.iter().enumerate() {
        if block.is_some_and(|(b, e)| (b..=e).contains(&i)) {
            continue;
        }
        let content = &old[l.start..l.content_end];
        let code = content.split(|b| *b == b'#').next().unwrap_or_default();
        let names: Vec<Vec<u8>> = code
            .split(|b| b.is_ascii_whitespace() || *b == 0x0b)
            .filter(|t| !t.is_empty())
            .skip(1)
            .map(|t| t.to_ascii_lowercase())
            .collect();
        let names_node = names
            .iter()
            .any(|n| n == node.as_bytes() || n == first.as_bytes());
        if names_node
            && hosts
                .iter()
                .any(|h| names.iter().any(|n| n == h.as_bytes()))
        {
            return Err(Fail::ReservedName);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(old: &[u8], hosts: &[&str]) -> Result<Vec<u8>, Fail> {
        edit(old, &Op::Set(hosts.iter().map(|h| h.to_string()).collect()))
    }

    fn s(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn block(t: &str, hosts: &[&str]) -> String {
        let mut out = format!("{BEGIN}{t}");
        for h in hosts {
            out += &format!("127.0.0.1 {h}{t}::1 {h}{t}");
        }
        out + END + t
    }

    #[test]
    fn appends_when_absent() {
        let out = set(b"127.0.0.1 localhost\n", &["a.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!("127.0.0.1 localhost\n{}", block("\n", &["a.example.com"]))
        );
        // Empty file: LF.
        assert_eq!(
            s(&set(b"", &["a.example.com"]).unwrap()),
            block("\n", &["a.example.com"])
        );
    }

    #[test]
    fn replaces_in_place() {
        let old = format!("top\n{}bottom\n", block("\n", &["a.example.com"]));
        let out = set(old.as_bytes(), &["b.example.com", "c.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!(
                "top\n{}bottom\n",
                block("\n", &["b.example.com", "c.example.com"])
            )
        );
    }

    #[test]
    fn idempotent_set_and_clear() {
        let once = set(b"x\n", &["a.example.com"]).unwrap();
        assert_eq!(set(&once, &["a.example.com"]).unwrap(), once);
        let cleared = edit(&once, &Op::Clear).unwrap();
        assert_eq!(cleared, b"x\n");
        assert_eq!(edit(&cleared, &Op::Clear).unwrap(), cleared);
        assert_eq!(edit(b"", &Op::Clear).unwrap(), b"");
    }

    #[test]
    fn terminators() {
        // CRLF file without a block: CRLF.
        let out = set(b"a\r\nb\r\n", &["a.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!("a\r\nb\r\n{}", block("\r\n", &["a.example.com"]))
        );
        // Unterminated single line: LF.
        let out = set(b"a", &["a.example.com"]).unwrap();
        assert_eq!(s(&out), format!("a\n{}", block("\n", &["a.example.com"])));
        // Unterminated last line of a CRLF file: the first terminator wins.
        let out = set(b"a\r\nb", &["a.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!("a\r\nb\r\n{}", block("\r\n", &["a.example.com"]))
        );
        // An existing block keeps its begin marker's terminator, even in an LF file.
        let old = format!("a\n{}b\n", block("\r\n", &["a.example.com"]));
        let out = set(old.as_bytes(), &["b.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!("a\n{}b\n", block("\r\n", &["b.example.com"]))
        );
    }

    #[test]
    fn end_marker_at_eof_keeps_its_style() {
        let unterminated = format!("a\n{}", block("\n", &["a.example.com"]));
        let old = unterminated.trim_end_matches('\n');
        let out = set(old.as_bytes(), &["b.example.com"]).unwrap();
        let want = block("\n", &["b.example.com"]);
        assert_eq!(s(&out), format!("a\n{}", want.trim_end_matches('\n')));
        let crlf = format!("a\r\n{}", block("\r\n", &["a.example.com"]));
        let out = set(crlf.as_bytes(), &["b.example.com"]).unwrap();
        assert_eq!(
            s(&out),
            format!("a\r\n{}", block("\r\n", &["b.example.com"]))
        );
        // Mixed: CRLF begin, unterminated end at EOF.
        let mixed = format!("{BEGIN}\r\n127.0.0.1 a.example.com\r\n::1 a.example.com\r\n{END}");
        let out = set(mixed.as_bytes(), &["b.example.com"]).unwrap();
        assert!(!out.ends_with(b"\n"));
        assert!(out.starts_with(format!("{BEGIN}\r\n127.0.0.1 b.example.com\r\n").as_bytes()));
    }

    #[test]
    fn clear_removes_only_the_block() {
        let old = format!("top\r\n{}bottom", block("\r\n", &["a.example.com"]));
        assert_eq!(
            s(&edit(old.as_bytes(), &Op::Clear).unwrap()),
            "top\r\nbottom"
        );
        // Lines an admin added inside go too.
        let old = format!("a\n{BEGIN}\nfoo\n{END}\nb\n");
        assert_eq!(s(&edit(old.as_bytes(), &Op::Clear).unwrap()), "a\nb\n");
    }

    #[test]
    fn damaged_layouts_are_refused_for_set_and_clear() {
        let hosts = "127.0.0.1 a.example.com\n";
        for bad in [
            format!("{BEGIN}\n{hosts}"),
            format!("{hosts}{END}\n"),
            format!("{END}\n{BEGIN}\n"),
            format!("{BEGIN}\n{BEGIN}\n{END}\n"),
            format!("{BEGIN}\n{END}\n{END}\n"),
            format!("{BEGIN}\n{END}\n{BEGIN}\n{END}\n"),
            format!("{BEGIN}\n{BEGIN}\n{END}\n{END}\n"),
            format!("{BEGIN} \n{hosts}{END}\n"),
            format!("{BEGIN}\n{hosts}{END} \n"),
            format!("{}\n{hosts}{END}\n", BEGIN.replace("cAInary", "CAINARY")),
            format!(
                "{}\n{hosts}{END}\n",
                BEGIN.replace("remove with the app", "other")
            ),
            format!("  # cainary takeover is mine\n{hosts}"),
            format!("{BEGIN}\r\r\n{END}\n"),
        ] {
            assert_eq!(
                set(bad.as_bytes(), &["a.example.com"]),
                Err(Fail::DamagedBlock),
                "{bad:?}"
            );
            assert_eq!(
                edit(bad.as_bytes(), &Op::Clear),
                Err(Fail::DamagedBlock),
                "{bad:?}"
            );
        }
        // An unterminated marker with a CR is not a marker, and mentions the takeover.
        let cr = format!("{BEGIN}\n{END}\r");
        assert_eq!(
            set(cr.as_bytes(), &["a.example.com"]),
            Err(Fail::DamagedBlock)
        );
    }

    #[test]
    fn bytes_outside_the_block_survive() {
        let mut old = b"\xff\xfe\x00 raw\n127.0.0.1 localhost\r\n".to_vec();
        old.extend_from_slice(block("\n", &["a.example.com"]).as_bytes());
        old.extend_from_slice(b"\x00\x80 tail without newline");
        let out = set(&old, &["b.example.com"]).unwrap();
        let head = b"\xff\xfe\x00 raw\n127.0.0.1 localhost\r\n";
        let tail = b"\x00\x80 tail without newline";
        assert!(out.starts_with(head) && out.ends_with(tail));
        let cleared = edit(&old, &Op::Clear).unwrap();
        assert_eq!(cleared, [&head[..], &tail[..]].concat());
    }

    #[test]
    fn property_bytes_around_the_block_are_identical() {
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..300 {
            let chunk = |rnd: &mut dyn FnMut() -> u64| {
                let mut v = Vec::new();
                for _ in 0..(rnd() % 6) {
                    for _ in 0..(rnd() % 20) {
                        let b = rnd() as u8;
                        if b != b'\n' && b != b'#' {
                            v.push(b);
                        }
                    }
                    v.extend_from_slice(if rnd().is_multiple_of(2) {
                        b"\n"
                    } else {
                        b"\r\n"
                    });
                }
                v
            };
            let (head, tail) = (chunk(&mut rnd), chunk(&mut rnd));
            let old = [
                &head[..],
                block("\n", &["a.example.com"]).as_bytes(),
                &tail[..],
            ]
            .concat();
            let out = set(&old, &["b.example.com", "c.example.com"]).unwrap();
            assert!(out.starts_with(&head) && out.ends_with(&tail));
            let cleared = edit(&old, &Op::Clear).unwrap();
            assert_eq!(cleared, [&head[..], &tail[..]].concat());
            // Appending keeps every old byte.
            let bare = [&head[..], &tail[..]].concat();
            let out = set(&bare, &["b.example.com"]).unwrap();
            assert!(out.starts_with(&bare));
        }
    }

    #[test]
    fn block_lines_are_checked() {
        for bad in [
            "a.b\n#x",
            "A.example.com",
            "a.example.com b.example.com",
            "a_b.example.com",
            "",
        ] {
            let hosts = vec![bad.to_string()];
            assert_eq!(block_lines(&hosts), Err(Fail::BadArgs), "{bad:?}");
        }
        assert_eq!(block_lines(&[]), Err(Fail::BadArgs));
        assert!(block_lines(&["a-b.example.com".to_string()]).is_ok());
    }

    #[test]
    fn alias_conflicts() {
        let hosts = vec!["myhost.corp.example".to_string()];
        let line = b"127.0.1.1 myhost.corp.example myhost\n";
        assert_eq!(
            alias_conflict(line, &hosts, "myhost"),
            Err(Fail::ReservedName)
        );
        assert_eq!(
            alias_conflict(
                b"127.0.1.1 MYHOST.corp.example Myhost # c\n",
                &hosts,
                "myhost"
            ),
            Err(Fail::ReservedName)
        );
        // Aliasing the first label of a longer node name.
        assert_eq!(
            alias_conflict(
                b"10.0.0.1 myhost.corp.example myhost\n",
                &hosts,
                "myhost.lan"
            ),
            Err(Fail::ReservedName)
        );
        // The node name on another line, or the host without the node name: fine.
        assert_eq!(
            alias_conflict(
                b"127.0.1.1 myhost\n10.0.0.1 myhost.corp.example\n",
                &hosts,
                "myhost"
            ),
            Ok(())
        );
        // Commented out, and empty node name.
        assert_eq!(
            alias_conflict(
                b"# 127.0.1.1 myhost.corp.example myhost\n",
                &hosts,
                "myhost"
            ),
            Ok(())
        );
        assert_eq!(alias_conflict(line, &hosts, ""), Ok(()));
        // Inside our own block it does not count.
        let inside = format!("{BEGIN}\n127.0.0.1 myhost.corp.example myhost\n{END}\n");
        assert_eq!(alias_conflict(inside.as_bytes(), &hosts, "myhost"), Ok(()));
        // A damaged file is damaged, not clean.
        let bad = format!("{BEGIN}\n");
        assert_eq!(
            alias_conflict(bad.as_bytes(), &hosts, "myhost"),
            Err(Fail::DamagedBlock)
        );
    }

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../linux/crates/tray-model/tests/fixtures/hosts"
    );

    fn fixtures() -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<_> = std::fs::read_dir(FIXTURES)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "hosts"))
            .map(|p| {
                let name = p.file_stem().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&p).unwrap())
            })
            .collect();
        out.sort();
        assert!(out.len() >= 25, "fixtures missing: {}", out.len());
        out
    }

    /// The tray reader (`tray-model/src/hostsfile.rs`) calls exactly these fixtures damaged.
    #[test]
    fn agrees_with_the_tray_reader_on_every_fixture() {
        for (name, bytes) in fixtures() {
            let damaged = name.starts_with("damaged-") || name.starts_with("malformed-");
            let one = set(&bytes, &["otel.example.com"]);
            assert_eq!(one.is_err(), damaged, "{name}: {one:?}");
            assert_eq!(edit(&bytes, &Op::Clear).is_err(), damaged, "{name}");
            let Ok(one) = one else { continue };
            // Set is idempotent, and the block it writes is what the reader calls current.
            assert_eq!(set(&one, &["otel.example.com"]).unwrap(), one, "{name}");
            let body = "127.0.0.1 otel.example.com\n::1 otel.example.com\n".to_string();
            let text = String::from_utf8_lossy(&one).replace("\r\n", "\n");
            assert!(text.contains(&format!("{BEGIN}\n{body}{END}")), "{name}");
            // The same bytes outside the block as clear leaves.
            assert_eq!(
                edit(&one, &Op::Clear).unwrap(),
                edit(&bytes, &Op::Clear).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn fixtures_the_reader_calls_current_are_already_current() {
        for name in [
            "block-lf",
            "block-crlf",
            "block-eof-unterminated",
            "block-eof-crlf",
            "invalid-utf8",
            "nul-bytes",
        ] {
            let (_, bytes) = fixtures().into_iter().find(|(n, _)| n == name).unwrap();
            assert_eq!(set(&bytes, &["otel.example.com"]).unwrap(), bytes, "{name}");
        }
    }
}
