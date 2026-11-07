//! What `/etc/hosts` says about the takeover host names, read without privileges. The block
//! rules (markers, line terminators, malformed markers) must agree byte-for-byte with the hosts
//! helper's `edit`; both suites use the same fixtures (`tests/fixtures/hosts/*.hosts`).

use std::fs::OpenOptions;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::hostcheck::is_loopback;

pub const HOSTS_PATH: &str = "/etc/hosts";

/// Larger files are not read; the helper refuses them too.
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

pub const BEGIN_MARKER: &str = "# >>> cAInary takeover: managed by cAInary, lines in here are replaced; remove with the app >>>";
pub const END_MARKER: &str = "# <<< cAInary takeover <<<";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BlockState {
    /// No marker anywhere.
    Absent,
    /// A well-formed block whose lines are exactly what `set` writes for the configured names.
    Current,
    /// A well-formed block with any other content.
    Stale,
    /// A single, repeated, nested or misordered marker, or a malformed one. The helper refuses.
    Damaged,
}

/// An unmanaged line that maps a configured name to a non-loopback address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// 1-based.
    pub line: usize,
    pub address: String,
    pub host: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Unsupported {
    Symlink { target: String },
    MountPoint,
    NotRegular,
    Unprotected,
}

/// What `analyze` finds in the bytes of the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub block: BlockState,
    pub conflicts: Vec<Conflict>,
    /// Configured names the helper would refuse, in configured order.
    pub reserved: Vec<String>,
}

/// The `hostsFile` summary: the analysis, or why there is none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostsFile {
    pub unsupported: Option<Unsupported>,
    /// Set when the file couldn't be read or wasn't analyzed.
    pub error: Option<String>,
    pub analysis: Option<Analysis>,
}

/// Lines as the helper sees them: the bytes up to `\n`, minus one `\r` right before it. An
/// unterminated rest at EOF is a line too, kept as is: a lone `\r` there isn't a terminator.
fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    let rest = out.pop().unwrap_or_default();
    for line in &mut out {
        *line = line.strip_suffix(b"\r").unwrap_or(line);
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Not a marker, but a comment that mentions the takeover: the helper refuses these.
fn is_malformed_marker(content: &[u8]) -> bool {
    let start = content
        .iter()
        .position(|b| !is_blank(*b))
        .unwrap_or(content.len());
    let rest = &content[start..];
    rest.first() == Some(&b'#')
        && rest
            .windows(b"cainary takeover".len())
            .any(|window| window.eq_ignore_ascii_case(b"cainary takeover"))
}

enum Layout {
    None,
    /// Line indexes of the begin and end markers.
    Block(usize, usize),
    Damaged,
}

fn layout(lines: &[&[u8]]) -> Layout {
    let (mut begins, mut ends) = (Vec::new(), Vec::new());
    for (index, line) in lines.iter().enumerate() {
        if *line == BEGIN_MARKER.as_bytes() {
            begins.push(index);
        } else if *line == END_MARKER.as_bytes() {
            ends.push(index);
        } else if is_malformed_marker(line) {
            return Layout::Damaged;
        }
    }
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Layout::None,
        ([begin], [end]) if begin < end => Layout::Block(*begin, *end),
        _ => Layout::Damaged,
    }
}

/// What `set` writes for these names, as line contents.
fn expected_body(hosts: &[String]) -> Vec<Vec<u8>> {
    hosts
        .iter()
        .flat_map(|host| {
            [
                format!("127.0.0.1 {host}").into_bytes(),
                format!("::1 {host}").into_bytes(),
            ]
        })
        .collect()
}

fn is_space(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == 0x0b
}

/// The address and the names of a hosts line; `None` for blank and comment-only lines.
fn fields(content: &[u8]) -> Option<Vec<&[u8]>> {
    let code = content.split(|b| *b == b'#').next().unwrap_or_default();
    let tokens: Vec<&[u8]> = code
        .split(|byte| is_space(*byte))
        .filter(|token| !token.is_empty())
        .collect();
    (tokens.len() >= 2).then_some(tokens)
}

fn first_label(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

fn name_is_reserved(host: &str, nodename: &str) -> bool {
    const FIXED: [&str; 3] = [
        "localhost.localdomain",
        "localhost4.localdomain4",
        "localhost6.localdomain6",
    ];
    host.ends_with(".localhost")
        || host.ends_with(".localdomain")
        || FIXED.contains(&host)
        || (!nodename.is_empty() && first_label(host) == first_label(nodename))
}

/// Pure core. `hosts` are the valid configured names; `nodename` is `uname().nodename`.
pub fn analyze(bytes: &[u8], hosts: &[String], nodename: &str) -> Analysis {
    let lines = lines(bytes);
    let layout = layout(&lines);
    let block = match &layout {
        Layout::None => BlockState::Absent,
        Layout::Damaged => BlockState::Damaged,
        Layout::Block(begin, end) => {
            let mut body: Vec<&[u8]> = lines[begin + 1..*end].to_vec();
            let mut expected = expected_body(hosts);
            body.sort_unstable();
            expected.sort_unstable();
            if !hosts.is_empty() && body == expected.iter().map(Vec::as_slice).collect::<Vec<_>>() {
                BlockState::Current
            } else {
                BlockState::Stale
            }
        }
    };
    // Unmanaged: everything outside a well-formed block; in a damaged file, everything.
    let managed = match layout {
        Layout::Block(begin, end) => Some((begin, end)),
        _ => None,
    };
    let nodename = nodename.to_ascii_lowercase();
    let nodename_label = first_label(&nodename);
    let mut conflicts = Vec::new();
    let mut on_nodename_line = vec![false; hosts.len()];
    for (index, content) in lines.iter().enumerate() {
        if managed.is_some_and(|(begin, end)| (begin..=end).contains(&index)) {
            continue;
        }
        let Some(tokens) = fields(content) else {
            continue;
        };
        let names = &tokens[1..];
        let lower = |token: &[u8]| token.to_ascii_lowercase();
        let names_nodename = !nodename.is_empty()
            && names.iter().any(|name| {
                let name = lower(name);
                name == nodename.as_bytes() || name == nodename_label.as_bytes()
            });
        let address = std::str::from_utf8(tokens[0])
            .ok()
            .and_then(|text| text.parse::<IpAddr>().ok());
        for (slot, host) in hosts.iter().enumerate() {
            if !names.iter().any(|name| lower(name) == host.as_bytes()) {
                continue;
            }
            on_nodename_line[slot] |= names_nodename;
            if let Some(address) = address.filter(|address| !is_loopback(address)) {
                conflicts.push(Conflict {
                    line: index + 1,
                    address: address.to_string(),
                    host: host.clone(),
                });
            }
        }
    }
    let reserved = hosts
        .iter()
        .enumerate()
        .filter(|(slot, host)| name_is_reserved(host, &nodename) || on_nodename_line[*slot])
        .map(|(_, host)| host.clone())
        .collect();
    Analysis {
        block,
        conflicts,
        reserved,
    }
}

/// The node name from `uname`, or empty.
pub fn nodename() -> String {
    // SAFETY: `uname` fills the zeroed struct; `nodename` is a NUL-terminated array.
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return String::new();
        }
        std::ffi::CStr::from_ptr(uts.nodename.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// Reads `/etc/hosts` as the helper would admit it, then analyzes it.
pub fn read(hosts: &[String]) -> HostsFile {
    read_with(Path::new(HOSTS_PATH), hosts, &nodename(), 0)
}

/// `read` for any path. `owner` is the uid that must own the file (0 in production).
pub fn read_with(path: &Path, hosts: &[String], nodename: &str, owner: u32) -> HostsFile {
    let fail = |unsupported: Option<Unsupported>, error: Option<String>| HostsFile {
        unsupported,
        error,
        analysis: None,
    };
    // lstat only: a FIFO is never opened.
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) => return fail(None, Some(error.to_string())),
    };
    let mut unsupported = None;
    let meta = if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path)
            .map(|target| target.display().to_string())
            .unwrap_or_default();
        unsupported = Some(Unsupported::Symlink { target });
        match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => return fail(unsupported, Some(error.to_string())),
        }
    } else {
        meta
    };
    if !meta.file_type().is_file() {
        return fail(Some(Unsupported::NotRegular), None);
    }
    if unsupported.is_none() {
        if is_mount_point(path, &meta) {
            unsupported = Some(Unsupported::MountPoint);
        } else if meta.uid() != owner || meta.mode() & 0o022 != 0 {
            unsupported = Some(Unsupported::Unprotected);
        }
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => return fail(unsupported, Some(error.to_string())),
    };
    let mut bytes = Vec::new();
    let read = file
        .metadata()
        .map_err(|error| error.to_string())
        .and_then(|opened| {
            if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) || !opened.is_file() {
                return Err("The file changed while it was read".to_string());
            }
            (&file)
                .take(MAX_READ_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())
        });
    match read {
        Err(error) => fail(unsupported, Some(error)),
        Ok(_) if bytes.len() as u64 > MAX_READ_BYTES => {
            fail(unsupported, Some("The file is too large".into()))
        }
        Ok(_) => HostsFile {
            unsupported,
            error: None,
            analysis: Some(analyze(&bytes, hosts, nodename)),
        },
    }
}

/// A file on another mount than its directory (including a same-device bind mount, by mount
/// ID). Without mount IDs, the device number is the best available signal.
fn is_mount_point(path: &Path, meta: &std::fs::Metadata) -> bool {
    let Some(parent) = path.parent().map(PathBuf::from) else {
        return false;
    };
    match (mount_id(path), mount_id(&parent)) {
        (Some(file), Some(dir)) => file != dir,
        _ => std::fs::metadata(&parent).is_ok_and(|dir| dir.dev() != meta.dev()),
    }
}

fn mount_id(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: valid NUL-terminated path and a zeroed out-struct for `statx` to fill.
    unsafe {
        let mut out: libc::statx = std::mem::zeroed();
        let status = libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut out,
        );
        (status == 0 && out.stx_mask & libc::STATX_MNT_ID != 0).then_some(out.stx_mnt_id)
    }
}
