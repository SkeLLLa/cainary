//! Publishing the CA's *public* certificate: the only file writer of the
//! takeover mode, and the only place that touches the certificate directory.
//!
//! The directory is opened once through a descriptor (`O_DIRECTORY | O_NOFOLLOW`) and validated
//! on that descriptor (our uid, no group/other write). Everything after that is relative to it
//! (`openat`, `renameat`, `unlinkat`), so a swapped path component can't redirect a write. An
//! exclusive `flock` on a lock file in the directory is held for the whole run, so a second
//! `--tls` run can't replace the certificate under the first.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const CA_FILE: &str = "otel-debug-ca.pem";
/// The proxy mode's certificate (public part only), kept between sessions.
pub const PROXY_CA_FILE: &str = "otel-debug-proxy-ca.pem";
pub const LOCK_FILE: &str = "otel-debug-ca.lock";

#[derive(Debug)]
pub enum CaFileError {
    /// Another `--tls` run holds the lock.
    Busy(PathBuf),
    /// Anything else, as a fixed-shape message.
    Failed(String),
}

impl std::fmt::Display for CaFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaFileError::Busy(p) => write!(
                f,
                "another cainary-otel-debug --tls run owns {}",
                p.display()
            ),
            CaFileError::Failed(m) => f.write_str(m),
        }
    }
}

fn failed<T>(msg: impl Into<String>) -> Result<T, CaFileError> {
    Err(CaFileError::Failed(msg.into()))
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("fixed names have no NUL")
}

/// An opened, validated certificate directory.
pub struct CaDir {
    fd: OwnedFd,
    dir: PathBuf,
}

/// What a run holds for its whole life: the lock, and where the certificate is.
pub struct Published {
    pub path: PathBuf,
    /// Dropping it releases the lock.
    _lock: File,
    _dir: CaDir,
}

/// Symlinks followed while resolving the path: only root-owned ones (`/home -> var/home`).
const MAX_LINKS: usize = 8;

struct Stat {
    uid: u32,
    mode: u32,
}

fn fstat_fd(fd: &OwnedFd) -> io::Result<Stat> {
    let f = File::from(fd.try_clone()?);
    let m = f.metadata()?;
    Ok(Stat {
        uid: m.uid(),
        mode: m.mode(),
    })
}

/// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`: `Ok(None)` when absent.
fn lstat_at(dirfd: &OwnedFd, name: &CString) -> io::Result<Option<(Stat, bool)>> {
    // SAFETY: an all-zero `stat` is a valid value for the call to fill in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, NUL-terminated name and a live `stat` for the call.
    let r = unsafe {
        libc::fstatat(
            dirfd.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let link = st.st_mode & libc::S_IFMT == libc::S_IFLNK;
    Ok(Some((
        Stat {
            uid: st.st_uid,
            mode: st.st_mode as u32,
        },
        link,
    )))
}

fn open_dir_at(dirfd: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
    // SAFETY: valid descriptor and NUL-terminated name; the flags are plain constants.
    let raw = unsafe {
        libc::openat(
            dirfd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn readlink_at(dirfd: &OwnedFd, name: &CString) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: valid descriptor, NUL-terminated name, and a buffer of the stated length.
    let n = unsafe {
        libc::readlinkat(
            dirfd.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

impl CaDir {
    /// Walks `dir` from `/` one component at a time, each opened relative to its parent's
    /// descriptor with `O_DIRECTORY | O_NOFOLLOW`, so no ancestor can be swapped
    /// for a symlink between the check and the use.
    ///
    /// - Every directory on the way must be owned by root or by us; one that group/other can
    ///   write must have the sticky bit (`/tmp`). The final directory is stricter: ours, no
    ///   group/other write.
    /// - A symlink is refused unless root owns it (`/home -> var/home` on some systems), and
    ///   only a few such links are followed.
    /// - With `create`, missing directories are made with `mkdirat(0700)` and reopened through
    ///   the same checks. Without it, a missing one is `Ok(None)`.
    fn walk(dir: &Path, create: bool) -> Result<Option<CaDir>, CaFileError> {
        use std::path::Component;
        if !dir.is_absolute() {
            return failed(format!(
                "the certificate directory {} is not an absolute path",
                dir.display()
            ));
        }
        let bad = |why: &str| -> Result<Option<CaDir>, CaFileError> {
            failed(format!("the certificate directory {} {why}", dir.display()))
        };
        let me = euid();
        // SAFETY: a constant, valid, NUL-terminated path.
        let root = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return failed(format!("can't open /: {}", io::Error::last_os_error()));
        }
        // SAFETY: `root` is a fresh descriptor we own.
        let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
        // The names as raw bytes (no lossy conversion), and no `.` or `..`: a `..` would make the
        // directory that is checked differ from the path the exporter is told to read.
        let mut todo: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
        let mut clean = PathBuf::from("/");
        for c in dir.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(n) => {
                    todo.push_back(n.as_bytes().to_vec());
                    clean.push(n);
                }
                _ => return bad("contains a '.' or '..' component"),
            }
        }
        let total = todo.len();
        let mut links = 0usize;
        let mut depth = 0usize;
        while let Some(name) = todo.pop_front() {
            if name == b"." || name == b".." || name.contains(&0) {
                return bad("contains a component that isn't a plain name");
            }
            let shown = String::from_utf8_lossy(&name).into_owned();
            let c = CString::new(name.clone()).expect("no NUL, checked above");
            let found = lstat_at(&fd, &c)
                .map_err(|e| CaFileError::Failed(format!("can't inspect {shown}: {e}")))?;
            match found {
                None if !create => return Ok(None),
                None => {
                    // SAFETY: valid descriptor and NUL-terminated name.
                    let r = unsafe { libc::mkdirat(fd.as_raw_fd(), c.as_ptr(), 0o700) };
                    if r != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                        return failed(format!(
                            "can't create {shown} for the certificate directory: {}",
                            io::Error::last_os_error()
                        ));
                    }
                }
                Some((st, true)) => {
                    if st.uid != 0 {
                        return bad("has a symlink on its path; refusing to use it");
                    }
                    links += 1;
                    if links > MAX_LINKS {
                        return bad("has too many symlinks on its path");
                    }
                    let target = readlink_at(&fd, &c)
                        .map_err(|e| CaFileError::Failed(format!("can't read a symlink: {e}")))?;
                    let target = Path::new(std::ffi::OsStr::from_bytes(&target));
                    if target.is_absolute() {
                        // Restart from the root with the link's target in front.
                        // SAFETY: a constant, valid, NUL-terminated path.
                        let r = unsafe {
                            libc::open(
                                c"/".as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                            )
                        };
                        if r < 0 {
                            return failed(format!("can't open /: {}", io::Error::last_os_error()));
                        }
                        // SAFETY: `r` is a fresh descriptor we own.
                        fd = unsafe { OwnedFd::from_raw_fd(r) };
                    }
                    let mut front: Vec<Vec<u8>> = Vec::new();
                    for comp in target.components() {
                        match comp {
                            Component::Normal(n) => front.push(n.as_bytes().to_vec()),
                            Component::RootDir | Component::CurDir => {}
                            _ => {
                                return bad("has a symlink with a '..' target; refusing to use it");
                            }
                        }
                    }
                    for n in front.into_iter().rev() {
                        todo.push_front(n);
                    }
                    continue;
                }
                Some(_) => {}
            }
            let next = open_dir_at(&fd, &c).map_err(|e| {
                CaFileError::Failed(if e.raw_os_error() == Some(libc::ELOOP) {
                    format!(
                        "the certificate directory {} has a symlink on its path; refusing to use it",
                        dir.display()
                    )
                } else {
                    format!("can't open {shown} on the way to {}: {e}", dir.display())
                })
            })?;
            depth += 1;
            let st = fstat_fd(&next)
                .map_err(|e| CaFileError::Failed(format!("can't stat {shown}: {e}")))?;
            let last = todo.is_empty();
            let group_other_write = st.mode & 0o022 != 0;
            let ok = if last && depth >= total {
                // Group- or other-writable is refused: an authorized writer could swap the
                // temporary file between its validation and the rename.
                let bad_write = group_other_write;
                st.uid == me && !bad_write
            } else {
                (st.uid == 0 || st.uid == me) && (!group_other_write || st.mode & 0o1000 != 0)
            };
            if !ok {
                return failed(if last {
                    format!(
                        "the certificate directory {} must be owned by you and not writable by group or others (fix: chmod go-w {})",
                        dir.display(),
                        crate::setup::quote(&dir.display().to_string())
                    )
                } else {
                    format!(
                        "{shown} on the way to the certificate directory {} is not safe (owned by someone else, or writable by others without the sticky bit)",
                        dir.display()
                    )
                });
            }
            fd = next;
        }
        // The advertised path is exactly the one validated: built from the same components.
        Ok(Some(CaDir { fd, dir: clean }))
    }

    pub fn open(dir: &Path) -> Result<CaDir, CaFileError> {
        Ok(CaDir::walk(dir, true)?.expect("create always yields a directory"))
    }

    /// The same strict walk for another program's directory (`~/.claude`): `create` makes it
    /// 0700 if missing.
    pub(crate) fn open_shared(dir: &Path, create: bool) -> Result<Option<CaDir>, CaFileError> {
        CaDir::walk(dir, create)
    }

    /// An existing certificate directory, strictly validated (never created).
    pub(crate) fn open_existing(dir: &Path) -> Result<Option<CaDir>, CaFileError> {
        CaDir::walk(dir, false)
    }

    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    fn exists(&self, name: &str) -> bool {
        lstat_at(&self.fd, &cstr(name)).is_ok_and(|s| s.is_some())
    }

    /// `openat` relative to the directory; the file must be ours, regular, with one link.
    fn open_file(&self, name: &str, flags: i32, mode: u32) -> Result<File, CaFileError> {
        let n = cstr(name);
        // SAFETY: valid descriptor and NUL-terminated name; `mode` is only read with O_CREAT.
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                n.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return failed(if e.raw_os_error() == Some(libc::ELOOP) {
                format!(
                    "{name} in {} is a symlink; refusing to use it",
                    self.dir.display()
                )
            } else {
                format!("can't open {name} in {}: {e}", self.dir.display())
            });
        }
        // SAFETY: `raw` is a fresh descriptor we own.
        let f = unsafe { File::from_raw_fd(raw) };
        let md = f
            .metadata()
            .map_err(|e| CaFileError::Failed(format!("can't stat {name}: {e}")))?;
        if !md.is_file() || md.uid() != euid() || md.nlink() != 1 {
            return failed(format!(
                "{name} in {} must be a regular file of yours with one link",
                self.dir.display()
            ));
        }
        Ok(f)
    }

    fn lock(&self) -> Result<File, CaFileError> {
        let f = self.open_file(LOCK_FILE, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        // SAFETY: the descriptor is valid for the call.
        let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if r != 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(CaFileError::Busy(self.dir.join(CA_FILE)))
            } else {
                failed(format!("can't lock the certificate directory: {e}"))
            };
        }
        Ok(f)
    }

    /// Writes the certificate atomically: a `create_new` temporary in the same directory, 0644
    /// set through its descriptor, then `renameat` over the fixed name.
    fn write_cert(&self, pem: &str) -> Result<(), CaFileError> {
        // SAFETY: getpid has no preconditions and cannot fail.
        let tmp = format!("{CA_FILE}.tmp.{}", unsafe { libc::getpid() });
        let mut f = self.open_file(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        let result = (|| -> io::Result<()> {
            f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            f.write_all(pem.as_bytes())?;
            f.sync_all()
        })();
        drop(f);
        let (t, n) = (cstr(&tmp), cstr(CA_FILE));
        if let Err(e) = result {
            self.unlink(&tmp);
            return failed(format!("can't write the certificate: {e}"));
        }
        // SAFETY: valid descriptor and NUL-terminated names.
        let r = unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                t.as_ptr(),
                self.fd.as_raw_fd(),
                n.as_ptr(),
            )
        };
        if r != 0 {
            let e = io::Error::last_os_error();
            self.unlink(&tmp);
            return failed(format!("can't publish the certificate: {e}"));
        }
        Ok(())
    }

    fn unlink(&self, name: &str) -> bool {
        let n = cstr(name);
        // SAFETY: valid descriptor and NUL-terminated name.
        let r = unsafe { libc::unlinkat(self.fd.as_raw_fd(), n.as_ptr(), 0) };
        r == 0 || io::Error::last_os_error().kind() == io::ErrorKind::NotFound
    }
}

/// Takes the lock and publishes `pem` as `<dir>/otel-debug-ca.pem`. The lock is held until the
/// returned value is dropped (the end of the run).
pub fn publish(dir: &Path, pem: &str) -> Result<Published, CaFileError> {
    let d = CaDir::open(dir)?;
    let lock = d.lock()?;
    d.write_cert(pem)?;
    Ok(Published {
        path: d.dir.join(CA_FILE),
        _lock: lock,
        _dir: d,
    })
}

/// `--delete-ca`: removes the certificate file. Refuses while a run holds the lock. `before` runs
/// with the run lock held (so no `--tls` start can publish meanwhile) and the file is unlinked only
/// if it returns `Some`; what it returns (the trust lock) is held until after the unlink. Lock
/// order is always the run lock, then the trust lock.
pub fn delete_holding<G>(
    dir: &Path,
    before: impl FnOnce(&CaDir) -> Option<G>,
) -> Result<bool, CaFileError> {
    let Some(d) = CaDir::walk(dir, false)? else {
        return Ok(false);
    };
    let _lock = d.lock()?;
    let existed = d.exists(CA_FILE);
    let Some(_held) = before(&d) else {
        return Ok(existed);
    };
    if !d.unlink(CA_FILE) {
        return failed("can't delete the certificate file");
    }
    Ok(existed)
}

/// `delete_holding` for a check with nothing to hold.
pub fn delete(dir: &Path, before: impl FnOnce(&CaDir) -> bool) -> Result<bool, CaFileError> {
    delete_holding(dir, |d| before(d).then_some(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cainary-ca-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }
    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn publishes_a_public_file_in_a_private_directory() {
        let d = tmp("publish").join("state/cainary");
        let p = publish(
            &d,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert_eq!(p.path, d.join(CA_FILE));
        assert_eq!(mode(&p.path), 0o644);
        assert_eq!(mode(&d), 0o700);
        assert!(
            fs::read_to_string(&p.path)
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        let names: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.contains(".tmp.")), "{names:?}");
        fs::remove_dir_all(d.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn a_second_run_is_refused_until_the_first_ends() {
        let d = tmp("lock");
        let first = publish(&d, "one").unwrap();
        match publish(&d, "two") {
            Err(CaFileError::Busy(p)) => assert_eq!(p, d.join(CA_FILE)),
            other => panic!("expected Busy, got {:?}", other.err()),
        }
        assert_eq!(fs::read_to_string(d.join(CA_FILE)).unwrap(), "one");
        // `--delete-ca` can't pull the file out from under a live run either.
        assert!(matches!(delete(&d, |_| true), Err(CaFileError::Busy(_))));
        drop(first);
        assert!(publish(&d, "three").is_ok());
        assert_eq!(fs::read_to_string(d.join(CA_FILE)).unwrap(), "three");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn delete_removes_the_file_and_is_quiet_when_absent() {
        let d = tmp("delete");
        assert!(!delete(&d, |_| true).unwrap(), "no directory");
        drop(publish(&d, "x").unwrap());
        assert!(delete(&d, |_| true).unwrap());
        assert!(!d.join(CA_FILE).exists());
        assert!(!delete(&d, |_| true).unwrap());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn delete_ca_still_busy_while_running() {
        let d = tmp("delete-busy");
        let first = publish(&d, "x").unwrap();
        let mut called = false;
        let r = delete(&d, |_| {
            called = true;
            true
        });
        assert!(matches!(r, Err(CaFileError::Busy(_))));
        assert!(!called, "`before` never runs without the run lock");
        drop(first);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn delete_keeps_the_file_when_before_says_no() {
        let d = tmp("delete-keep");
        drop(publish(&d, "x").unwrap());
        assert!(delete(&d, |c| c.path() == d).unwrap());
        drop(publish(&d, "x").unwrap());
        assert!(delete(&d, |_| false).unwrap(), "reports it exists");
        assert!(d.join(CA_FILE).exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_a_symlinked_directory_and_a_symlinked_file() {
        let base = tmp("symlink");
        fs::create_dir_all(&base).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("link");
        symlink(&real, &link).unwrap();
        assert!(
            matches!(publish(&link, "x"), Err(CaFileError::Failed(m)) if m.contains("symlink"))
        );
        // A planted symlink at the tmp name or the lock name is never followed.
        let victim = base.join("victim");
        fs::write(&victim, "keep").unwrap();
        symlink(&victim, real.join(LOCK_FILE)).unwrap();
        assert!(publish(&real, "x").is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn refuses_a_group_writable_directory_and_hard_linked_files() {
        let base = tmp("modes");
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            matches!(publish(&base, "x"), Err(CaFileError::Failed(m)) if m.contains("not writable"))
        );
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = base.join("victim");
        fs::write(&victim, "keep").unwrap();
        fs::hard_link(&victim, base.join(LOCK_FILE)).unwrap();
        assert!(publish(&base, "x").is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn replaces_an_existing_certificate_atomically() {
        let d = tmp("replace");
        drop(publish(&d, "old").unwrap());
        drop(publish(&d, "new").unwrap());
        assert_eq!(fs::read_to_string(d.join(CA_FILE)).unwrap(), "new");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let base = tmp("ancestor");
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("state");
        symlink(&real, &link).unwrap();
        // The symlink sits above the certificate directory, as a symlinked XDG_STATE_HOME would.
        for target in [link.join("cainary"), link.join("a/b/cainary")] {
            match publish(&target, "x") {
                Err(CaFileError::Failed(m)) => assert!(m.contains("symlink"), "{m}"),
                other => panic!("expected a refusal, got {:?}", other.err()),
            }
            assert!(matches!(
                delete(&target, |_| true),
                Err(CaFileError::Failed(_))
            ));
        }
        assert!(
            !real.join("cainary").exists(),
            "nothing was created through the link"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn refuses_an_unsafe_ancestor_and_relative_paths() {
        let base = tmp("unsafe-ancestor");
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        match publish(&base.join("cainary"), "x") {
            Err(CaFileError::Failed(m)) => assert!(m.contains("not safe"), "{m}"),
            other => panic!("expected a refusal, got {:?}", other.err()),
        }
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(publish(Path::new("relative/cainary"), "x").is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn creates_missing_ancestors_privately() {
        let base = tmp("create-ancestors");
        let d = base.join("a/b/cainary");
        drop(publish(&d, "x").unwrap());
        for p in [base.join("a"), base.join("a/b"), d.clone()] {
            assert_eq!(mode(&p), 0o700, "{}", p.display());
        }
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn dot_and_dotdot_components_are_refused_and_the_path_is_the_validated_one() {
        let base = tmp("dotdot");
        fs::create_dir_all(base.join("a")).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(base.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        for p in [
            base.join("a/../state/cainary"),
            base.join("a/cainary/.."),
            base.join("../cainary"),
        ] {
            match publish(&p, "x") {
                Err(CaFileError::Failed(m)) => assert!(m.contains("'.' or '..'"), "{m}"),
                other => panic!("{}: {:?}", p.display(), other.err()),
            }
            assert!(matches!(delete(&p, |_| true), Err(CaFileError::Failed(_))));
        }
        assert!(!base.join("a/state").exists() && !base.join("state").exists());
        // An interior `.` and redundant slashes are harmless, and the advertised path is built from the components.
        let messy = PathBuf::from(format!("{}//a/./b///cainary", base.display()));
        let published = publish(&messy, "x").unwrap();
        assert_eq!(published.path, base.join("a/b/cainary").join(CA_FILE));
        assert!(published.path.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "APFS refuses names that aren't UTF-8 (EILSEQ)"
    )]
    fn names_are_kept_as_raw_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let base = tmp("bytes");
        // A directory name that isn't UTF-8 must be created and opened as itself, not as its
        // lossy rendering.
        let odd = OsString::from_vec(b"st\xffate".to_vec());
        let dir = base.join(&odd).join("cainary");
        let p = publish(&dir, "x").unwrap();
        assert_eq!(p.path, dir.join(CA_FILE));
        assert!(
            fs::read_dir(&base)
                .unwrap()
                .any(|e| e.unwrap().file_name() == odd)
        );
        assert!(
            fs::read_dir(&base).unwrap().count() == 1,
            "no lossy twin was created"
        );
        fs::remove_dir_all(&base).unwrap();
    }
}
