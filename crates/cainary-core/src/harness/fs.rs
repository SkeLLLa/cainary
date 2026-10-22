//! The only module that touches `std::fs` (architecture.md §6.3).

use super::deny::AccessPolicy;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Largest file a scanner may read.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Most entries a listing returns.
pub const MAX_LIST_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The policy refused the path (or the resolved path).
    Denied,
    Missing,
    NotRegular,
    TooLarge,
    /// `nlink != 1`.
    HardLinked,
    /// The open descriptor's path failed the policy, or couldn't be looked up (§6.3 step 5).
    Swapped,
    Io(String),
}

/// What a stat reveals; no policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub is_dir: bool,
    pub is_file: bool,
    pub uid: u32,
    pub mode: u32,
}

/// A directory listing: sorted, hidden entries skipped, denied entries left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<PathBuf>,
    /// There were more than `max` entries; only the first `max` are kept.
    pub truncated: bool,
}

fn is_missing(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Read a regular file of at most `cap` bytes, following the §6.3 steps 1–6.
pub fn read(policy: &AccessPolicy, path: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
    // 1. the requested path
    policy.check(path).map_err(|_| ReadError::Denied)?;
    // 2. where it resolves
    let resolved = std::fs::canonicalize(path).map_err(|e| {
        if is_missing(&e) {
            ReadError::Missing
        } else {
            ReadError::Io(e.to_string())
        }
    })?;
    policy.check(&resolved).map_err(|_| ReadError::Denied)?;
    // 3. open without following a swapped-in final symlink, without blocking on a FIFO
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&resolved)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => ReadError::Swapped,
            _ if is_missing(&e) => ReadError::Missing,
            _ => ReadError::Io(e.to_string()),
        })?;
    // 4. what the descriptor really is
    let meta = file.metadata().map_err(|e| ReadError::Io(e.to_string()))?;
    if !meta.is_file() {
        return Err(ReadError::NotRegular);
    }
    if meta.nlink() != 1 {
        return Err(ReadError::HardLinked);
    }
    if meta.len() > cap {
        return Err(ReadError::TooLarge);
    }
    // 5. where the kernel says the descriptor is
    match fd_path(&file) {
        Some(p) if policy.check(&p).is_ok() => {}
        _ => return Err(ReadError::Swapped),
    }
    // 6. bounded read
    read_capped(file, cap)
}

/// Read at most `cap` bytes; more than that means the file grew after the `fstat`.
fn read_capped(r: impl Read, cap: u64) -> Result<Vec<u8>, ReadError> {
    let mut buf = Vec::new();
    r.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| ReadError::Io(e.to_string()))?;
    if buf.len() as u64 > cap {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// The path the kernel reports for an open descriptor.
#[cfg(target_os = "macos")]
fn fd_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes into `buf`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let len = buf.iter().position(|b| *b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

#[cfg(not(target_os = "macos"))]
fn fd_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

/// List a directory: sorted, hidden entries skipped, at most `max` entries.
pub fn list(policy: &AccessPolicy, path: &Path, max: usize) -> Result<Listing, ReadError> {
    policy.may_list(path).map_err(|_| ReadError::Denied)?;
    let resolved = std::fs::canonicalize(path).map_err(|e| {
        if is_missing(&e) {
            ReadError::Missing
        } else {
            ReadError::Io(e.to_string())
        }
    })?;
    policy.may_list(&resolved).map_err(|_| ReadError::Denied)?;
    let rd = std::fs::read_dir(&resolved).map_err(|e| {
        if is_missing(&e) {
            ReadError::Missing
        } else {
            ReadError::Io(e.to_string())
        }
    })?;
    let mut names = Vec::new();
    for entry in rd {
        let name = entry.map_err(|e| ReadError::Io(e.to_string()))?.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        if policy.check(&resolved.join(&name)).is_err() || policy.check(&path.join(&name)).is_err()
        {
            continue;
        }
        names.push(name);
    }
    names.sort();
    let truncated = names.len() > max;
    names.truncate(max);
    Ok(Listing {
        entries: names.into_iter().map(|n| path.join(n)).collect(),
        truncated,
    })
}

/// Stat only; `Ok(None)` when the path does not exist, `Err` for any other failure.
pub fn stat(path: &Path) -> Result<Option<Stat>, String> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some(Stat {
            is_dir: m.is_dir(),
            is_file: m.is_file(),
            uid: m.uid(),
            mode: m.mode(),
        })),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// `canonicalize`, or `None` when it fails.
pub fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

#[cfg(test)]
mod tests {
    use super::super::deny::ToolHomes;
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Tmp {
            let p = std::env::temp_dir().join(format!(
                "cainary-fs-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(p.join("home")).unwrap();
            // canonical, so the policy's bases and resolved paths agree (macOS /var → /private/var)
            Tmp(std::fs::canonicalize(&p).unwrap())
        }
        fn home(&self) -> PathBuf {
            self.0.join("home")
        }
        fn policy(&self) -> AccessPolicy {
            let h = self.home();
            let homes = ToolHomes {
                claude: h.join(".claude"),
                codex: h.join(".codex"),
                copilot: h.join(".copilot"),
            };
            AccessPolicy::new(&self.0.join("root"), &h, &homes, &h.join(".config"))
        }
        fn write(&self, rel: &str, body: &[u8]) -> PathBuf {
            let p = self.home().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            p
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_a_regular_file() {
        let t = Tmp::new();
        let p = t.write(".codex/config.toml", b"model = \"x\"\n");
        assert_eq!(
            read(&t.policy(), &p, MAX_FILE_BYTES).unwrap(),
            b"model = \"x\"\n"
        );
    }

    #[test]
    fn missing_file() {
        let t = Tmp::new();
        let p = t.home().join("nope.json");
        assert_eq!(read(&t.policy(), &p, 100), Err(ReadError::Missing));
        let under_file = t.write("f", b"x").join("child");
        assert_eq!(read(&t.policy(), &under_file, 100), Err(ReadError::Missing));
    }

    #[test]
    fn denied_requested_path() {
        let t = Tmp::new();
        let p = t.write(".codex/auth.json", b"{\"k\":\"sk-test-EXAMPLE\"}");
        assert_eq!(read(&t.policy(), &p, 1000), Err(ReadError::Denied));
        let env = t.write("proj/id_rsa", b"A=1");
        assert_eq!(read(&t.policy(), &env, 1000), Err(ReadError::Denied));
    }

    #[test]
    fn symlink_into_denied_location_is_refused() {
        let t = Tmp::new();
        let secret = t.write(".codex/auth.json", b"x");
        let link = t.home().join("innocent.json");
        symlink(&secret, &link).unwrap();
        assert_eq!(read(&t.policy(), &link, 100), Err(ReadError::Denied));

        // a symlinked directory in the middle of the path
        t.write(".ssh/config", b"x");
        let dirlink = t.home().join("sshlink");
        symlink(t.home().join(".ssh"), &dirlink).unwrap();
        assert_eq!(
            read(&t.policy(), &dirlink.join("config"), 100),
            Err(ReadError::Denied)
        );
    }

    #[test]
    fn symlink_to_a_harmless_file_is_followed() {
        let t = Tmp::new();
        let real = t.write("real.json", b"{}");
        let link = t.home().join("link.json");
        symlink(&real, &link).unwrap();
        assert_eq!(read(&t.policy(), &link, 100).unwrap(), b"{}");
    }

    #[test]
    fn fifo_is_not_regular_and_does_not_block() {
        let t = Tmp::new();
        let p = t.home().join("pipe");
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read(&t.policy(), &p, 100), Err(ReadError::NotRegular));
    }

    #[test]
    fn directory_is_not_regular() {
        let t = Tmp::new();
        assert_eq!(
            read(&t.policy(), &t.home(), 100),
            Err(ReadError::NotRegular)
        );
    }

    #[test]
    fn hard_linked_file_is_refused() {
        let t = Tmp::new();
        let a = t.write("a.json", b"{}");
        std::fs::hard_link(&a, t.home().join("b.json")).unwrap();
        assert_eq!(read(&t.policy(), &a, 100), Err(ReadError::HardLinked));
    }

    #[test]
    fn cap_is_enforced() {
        let t = Tmp::new();
        let p = t.write("big.json", &[b'a'; 11]);
        assert_eq!(read(&t.policy(), &p, 10), Err(ReadError::TooLarge));
        assert_eq!(read(&t.policy(), &p, 11).unwrap().len(), 11);
    }

    #[test]
    fn growth_after_fstat_is_too_large() {
        // a reader that keeps yielding well past the cap
        let endless = io::repeat(b'a').take(110);
        assert_eq!(read_capped(endless, 100), Err(ReadError::TooLarge));
        assert_eq!(
            read_capped(io::repeat(b'a').take(100), 100).unwrap().len(),
            100
        );
        assert_eq!(read_capped(io::empty(), 100).unwrap(), b"");
    }

    #[test]
    fn read_capped_never_reads_past_cap_plus_one() {
        struct Count(usize);
        impl Read for Count {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0 += buf.len();
                buf.fill(b'a');
                Ok(buf.len())
            }
        }
        let mut c = Count(0);
        assert_eq!(read_capped(&mut c, 50), Err(ReadError::TooLarge));
        assert_eq!(c.0, 51);
    }

    #[test]
    fn fd_path_reports_the_real_path() {
        let t = Tmp::new();
        let p = t.write("x.json", b"{}");
        let f = File::open(&p).unwrap();
        assert_eq!(fd_path(&f).unwrap(), p);
    }

    #[test]
    fn list_is_sorted_skips_hidden_and_denied() {
        let t = Tmp::new();
        t.write("d/b.json", b"");
        t.write("d/a.json", b"");
        t.write("d/.hidden", b"");
        t.write("d/a.sqlite", b"");
        t.write("d/state.vscdb", b"");
        let d = t.home().join("d");
        let l = list(&t.policy(), &d, 10).unwrap();
        assert_eq!(l.entries, vec![d.join("a.json"), d.join("b.json")]);
        assert!(!l.truncated);
    }

    #[test]
    fn list_truncates() {
        let t = Tmp::new();
        for i in 0..5 {
            t.write(&format!("d/f{i}.json"), b"");
        }
        let d = t.home().join("d");
        let l = list(&t.policy(), &d, 3).unwrap();
        assert_eq!(l.entries.len(), 3);
        assert!(l.truncated);
        assert_eq!(l.entries[0], d.join("f0.json"));
        let exact = list(&t.policy(), &d, 5).unwrap();
        assert!(!exact.truncated);
    }

    #[test]
    fn list_refusals_and_missing() {
        let t = Tmp::new();
        t.write(".codex/config.toml", b"");
        assert_eq!(
            list(&t.policy(), &t.home().join(".codex"), 10),
            Err(ReadError::Denied)
        );
        t.write(".ssh/config", b"");
        assert_eq!(
            list(&t.policy(), &t.home().join(".ssh"), 10),
            Err(ReadError::Denied)
        );
        assert_eq!(
            list(&t.policy(), &t.home().join("nope"), 10),
            Err(ReadError::Missing)
        );
        // a symlink whose target has a denied child
        let link = t.home().join("codexlink");
        symlink(t.home().join(".codex"), &link).unwrap();
        assert_eq!(list(&t.policy(), &link, 10), Err(ReadError::Denied));
    }

    #[test]
    fn stat_and_canonical() {
        let t = Tmp::new();
        let p = t.write("x.json", b"{}");
        let s = stat(&p).unwrap().unwrap();
        assert!(s.is_file && !s.is_dir);
        assert!(stat(&t.home()).unwrap().unwrap().is_dir);
        assert_eq!(stat(&t.home().join("nope")), Ok(None));
        assert_eq!(canonical(&p), Some(p.clone()));
        assert_eq!(canonical(&t.home().join("nope")), None);
    }

    #[test]
    fn stat_does_not_apply_the_policy() {
        let t = Tmp::new();
        let p = t.write(".codex/auth.json", b"x");
        assert!(stat(&p).unwrap().is_some());
    }
}
