//! Everything that touches the file system for `--trust`: descriptor-relative reads and
//! writes, atomic replacement, the trust lock, backups and the narrow read of other programs'
//! certificate bundles. It is the only file under `trust/` that uses `std::fs`, `libc` or file
//! locking (guards N2 and N3).

use super::{LOCK_FILE, hook};
use crate::tls::ca_file::CaDir;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) const MAX_FILE: usize = 1 << 20;

/// A name for a system call. Names that came from a record are checked with `plain_name` first;
/// a NUL is an error with no content in it.
pub(super) fn cname(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// A plain file name: no separator, no NUL, no `.`/`..`, at most 255 bytes.
pub(super) fn plain_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 255 && n != "." && n != ".." && !n.contains(['/', '\0'])
}

pub(super) fn euid() -> u32 {
    #[cfg(test)]
    if let Some(u) = hook::FAKE_EUID.with(std::cell::Cell::get) {
        return u;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[derive(Debug)]
pub(super) enum Why {
    Symlink,
    Owner,
    NotRegular,
    TooBig,
    Io,
}

/// A file's identity when it was read: the same bytes under a different (device, inode, size,
/// mtime) is a different file, as far as a compare-then-swap is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ident {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) size: u64,
    pub(super) mtime_ns: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) bytes: Vec<u8>,
    pub(super) ident: Ident,
}

/// Reads `name` in `dir` with its identity: `Ok(None)` if absent; refuses a symlink, a file that
/// isn't ours or isn't a regular one-link file, and anything over 1 MiB.
pub(super) fn read_snapshot(dir: &CaDir, name: &str) -> Result<Option<Snapshot>, Why> {
    let n = cname(name).map_err(|_| Why::Io)?;
    // SAFETY: valid descriptor and NUL-terminated name; the flags are plain constants.
    let raw = unsafe {
        libc::openat(
            dir.raw_fd(),
            n.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(Why::Symlink),
            _ => Err(Why::Io),
        };
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    let mut f = unsafe { File::from_raw_fd(raw) };
    let md = f.metadata().map_err(|_| Why::Io)?;
    if !md.is_file() || md.nlink() != 1 {
        return Err(Why::NotRegular);
    }
    if md.uid() != euid() {
        return Err(Why::Owner);
    }
    if md.len() > MAX_FILE as u64 {
        return Err(Why::TooBig);
    }
    hook::after_stat(name);
    // Bounded by the cap, not by the size seen a moment ago: a file that grows while being read
    // is refused, not buffered.
    let mut bytes = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(&mut f, MAX_FILE as u64 + 1), &mut bytes)
        .map_err(|_| Why::Io)?;
    if bytes.len() > MAX_FILE {
        return Err(Why::TooBig);
    }
    let ident = Ident {
        dev: md.dev(),
        ino: md.ino(),
        size: md.len(),
        mtime_ns: i128::from(md.mtime()) * 1_000_000_000 + i128::from(md.mtime_nsec()),
    };
    Ok(Some(Snapshot { bytes, ident }))
}

pub(super) fn read_in(dir: &CaDir, name: &str) -> Result<Option<Vec<u8>>, Why> {
    read_snapshot(dir, name).map(|s| s.map(|s| s.bytes))
}

/// Flushes a directory's entries (a created, renamed or removed file) to disk.
pub(super) fn sync_dir(dir: &CaDir) -> io::Result<()> {
    if hook::fail_sync() {
        return Err(io::Error::other("injected failure"));
    }
    // SAFETY: the descriptor is valid for the call.
    if unsafe { libc::fsync(dir.raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn open_new(dir: &CaDir, name: &str, mode: u32) -> io::Result<File> {
    let n = cname(name)?;
    // SAFETY: valid descriptor and NUL-terminated name; `mode` is read only with O_CREAT.
    let raw = unsafe {
        libc::openat(
            dir.raw_fd(),
            n.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    let f = unsafe { File::from_raw_fd(raw) };
    let md = f.metadata()?;
    if !md.is_file() || md.uid() != euid() || md.nlink() != 1 {
        return Err(io::Error::other("not a fresh regular file of ours"));
    }
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(f)
}

pub(super) fn unlink_in(dir: &CaDir, name: &str) -> io::Result<()> {
    unlink_checked(dir, name).map_err(|_| io::Error::other("could not remove the file"))
}

/// Tmp (`create_new | O_NOFOLLOW`), 0600→`mode`, written and fsynced, not yet in place. Returns
/// its name.
pub(super) fn stage(dir: &CaDir, name: &str, bytes: &[u8], mode: u32) -> io::Result<String> {
    // SAFETY: getpid has no preconditions and cannot fail.
    let tmp = format!("{name}.cainary-tmp.{}", unsafe { libc::getpid() });
    let mut f = open_new(dir, &tmp, mode)?;
    let r = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = r {
        let _ = unlink_in(dir, &tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// How a rename or unlink that was asked for ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Done {
    /// It did not happen.
    No,
    /// It happened, but making it durable failed: what is on disk is uncertain, so nothing may be
    /// restored or declared unchanged.
    Uncertain,
}

/// `renameat(tmp, name)` and a directory fsync. The rename is the last thing before the answer.
pub(super) fn publish(dir: &CaDir, tmp: &str, name: &str) -> Result<(), Done> {
    let (Ok(t), Ok(n)) = (cname(tmp), cname(name)) else {
        return Err(Done::No);
    };
    // SAFETY: valid descriptor and NUL-terminated names.
    let r = unsafe { libc::renameat(dir.raw_fd(), t.as_ptr(), dir.raw_fd(), n.as_ptr()) };
    if r != 0 {
        let _ = unlink_in(dir, tmp);
        return Err(Done::No);
    }
    sync_dir(dir).map_err(|_| Done::Uncertain)
}

/// `unlinkat(name)` and a directory fsync, with the same two kinds of failure.
pub(super) fn unlink_checked(dir: &CaDir, name: &str) -> Result<(), Done> {
    let Ok(n) = cname(name) else {
        return Err(Done::No);
    };
    // SAFETY: valid descriptor and NUL-terminated name.
    let r = unsafe { libc::unlinkat(dir.raw_fd(), n.as_ptr(), 0) };
    if r != 0 && io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
        return Err(Done::No);
    }
    sync_dir(dir).map_err(|_| Done::Uncertain)
}

pub(super) fn discard(dir: &CaDir, tmp: &str) {
    let _ = unlink_in(dir, tmp);
}

pub(super) fn write_atomic(dir: &CaDir, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    let tmp = stage(dir, name, bytes, mode)?;
    publish(dir, &tmp, name).map_err(|_| io::Error::other("could not put the file in place"))
}

/// Why a checked replace or delete did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Replace {
    /// The target is no longer the file (bytes, device, inode, size, mtime) the caller checked.
    Changed,
    Failed,
    /// It happened but isn't known to be durable.
    Uncertain,
}

/// Whether `name` is still exactly what `before` read (`None`: still absent). `point` names the
/// moment for the tests' hook. This narrows the check-to-change window to a few system calls; it
/// cannot close it against a same-user writer that races the rename.
fn still(dir: &CaDir, name: &str, before: &Option<Snapshot>, point: &str) -> bool {
    hook::before_cas(point);
    match (read_snapshot(dir, name), before) {
        (Ok(None), None) => true,
        (Ok(Some(now)), Some(then)) => now.bytes == then.bytes && now.ident == then.ident,
        _ => false,
    }
}

/// Stages `bytes` first, then re-checks the target against `before`, then renames at once.
pub(super) fn replace_checked(
    dir: &CaDir,
    name: &str,
    bytes: &[u8],
    mode: u32,
    before: &Option<Snapshot>,
) -> Result<(), Replace> {
    let tmp = stage(dir, name, bytes, mode).map_err(|_| Replace::Failed)?;
    if !still(dir, name, before, name) {
        discard(dir, &tmp);
        return Err(Replace::Changed);
    }
    publish(dir, &tmp, name).map_err(|d| match d {
        Done::No => Replace::Failed,
        Done::Uncertain => Replace::Uncertain,
    })
}

/// Re-checks the target against `before`, then unlinks it.
pub(super) fn unlink_unchanged(
    dir: &CaDir,
    name: &str,
    before: &Option<Snapshot>,
) -> Result<(), Replace> {
    if !still(dir, name, before, name) {
        return Err(Replace::Changed);
    }
    unlink_checked(dir, name).map_err(|d| match d {
        Done::No => Replace::Failed,
        Done::Uncertain => Replace::Uncertain,
    })
}

/// The one lock every `--trust` and `--trust-status` call holds across recovery, reads, edits and
/// the final state write (design §17.2). Not the CA directory's run lock: `--trust` has to work
/// while the collector runs. Dropped (and released) with the file.
pub(crate) struct TrustLock {
    _f: File,
}

/// Takes the lock, polling for up to `wait`. `Ok(None)`: someone else holds it.
pub(super) fn lock_trust(dir: &CaDir, wait: Duration) -> io::Result<Option<TrustLock>> {
    let n = cname(LOCK_FILE)?;
    // SAFETY: valid descriptor and NUL-terminated name; the flags are plain constants.
    let raw = unsafe {
        libc::openat(
            dir.raw_fd(),
            n.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    let f = unsafe { File::from_raw_fd(raw) };
    let md = f.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail. (Not `euid()`: the tests' pretend
    // user is about the settings file, not this one.)
    let me = unsafe { libc::geteuid() };
    if !md.is_file() || md.uid() != me || md.nlink() != 1 {
        return Err(io::Error::other(
            "the lock file is not a regular file of yours",
        ));
    }
    let end = Instant::now() + wait;
    loop {
        // SAFETY: the descriptor is valid for the call.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(TrustLock { _f: f }));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(e);
        }
        if Instant::now() >= end {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A backup next to the file: `<name>.cainary-<UTC yyyymmddThhmmssZ>.bak`, 0600, never
/// overwriting an earlier one.
pub(super) fn backup(dir: &CaDir, name: &str, bytes: &[u8], stamp: &str) -> io::Result<String> {
    for n in 0..10 {
        let suffix = if n == 0 {
            String::new()
        } else {
            format!("-{n}")
        };
        let b = format!("{name}.cainary-{stamp}{suffix}.bak");
        match open_new(dir, &b, 0o600) {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
                sync_dir(dir)?;
                return Ok(b);
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("too many backups in one second"))
}

/// The text of a certificate bundle of someone else, read narrowly: a regular file of at most
/// 2 MiB that others can't write, symlinks followed (`/etc/ssl/cert.pem` is one). Anything else
/// is `None`.
pub(super) fn read_bundle_text(path: &Path) -> Option<String> {
    const CAP: u64 = 2 << 20;
    let resolved = std::fs::canonicalize(path).ok()?;
    let f = File::open(&resolved).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || md.len() > CAP || md.mode() & 0o022 != 0 {
        return None;
    }
    let mut buf = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(f, CAP + 1), &mut buf).ok()?;
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::tests::*;
    use crate::trust::*;
    use std::fs;

    #[test]
    fn a_file_that_grows_while_it_is_read_is_refused_not_buffered() {
        let fx = Fx::new("grow", "");
        fx.write_settings("{}\n");
        let p = fx.settings();
        hook::AFTER_STAT.with(|c| {
            *c.borrow_mut() = Some(Box::new(move |name| {
                if name == "settings.json" {
                    let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
                    f.write_all(&vec![b' '; 3 * MAX_FILE]).unwrap();
                }
            }));
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(a.message.contains("over 1 MiB"), "{}", a.message);
        assert!(state_bytes(&fx).is_none());
    }
}
