//! Publishing the CA's *public* certificate (design §16.2, §16.7.2): the only file writer of the
//! takeover mode, and the only place that touches the certificate directory.
//!
//! The directory is opened once through a descriptor (`O_DIRECTORY | O_NOFOLLOW`) and validated
//! on that descriptor (our uid, no group/other write). Everything after that is relative to it
//! (`openat`, `renameat`, `unlinkat`), so a swapped path component can't redirect a write. An
//! exclusive `flock` on a lock file in the directory is held for the whole run, so a second
//! `--tls` run can't replace the certificate under the first.

use std::ffi::CString;
use std::fs::{DirBuilder, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const CA_FILE: &str = "otel-debug-ca.pem";
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

impl CaDir {
    /// Creates the directory (0700, like any missing parents) if needed, refuses a symlinked
    /// final component, and validates the opened descriptor.
    pub fn open(dir: &Path) -> Result<CaDir, CaFileError> {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return failed(format!(
                    "the certificate directory {} is a symlink; refusing to use it",
                    dir.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|e| {
                        CaFileError::Failed(format!(
                            "can't create the certificate directory {}: {e}",
                            dir.display()
                        ))
                    })?;
            }
            Err(e) => {
                return failed(format!("can't inspect {}: {e}", dir.display()));
            }
        }
        let path = cstr_path(dir);
        // SAFETY: `path` is a valid NUL-terminated string; the flags are plain constants.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return failed(format!(
                "can't open the certificate directory {}: {}",
                dir.display(),
                io::Error::last_os_error()
            ));
        }
        // SAFETY: `raw` is a fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let md = File::from(fd.try_clone().map_err(|e| {
            CaFileError::Failed(format!("can't duplicate the directory descriptor: {e}"))
        })?)
        .metadata()
        .map_err(|e| CaFileError::Failed(format!("can't stat {}: {e}", dir.display())))?;
        if md.uid() != euid() || md.mode() & 0o022 != 0 {
            return failed(format!(
                "the certificate directory {} must be owned by you and not writable by group or others",
                dir.display()
            ));
        }
        Ok(CaDir {
            fd,
            dir: dir.to_path_buf(),
        })
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

fn cstr_path(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_else(|_| cstr("/nonexistent-invalid-path"))
}

/// Takes the lock and publishes `pem` as `<dir>/otel-debug-ca.pem`. The lock is held until the
/// returned value is dropped (the end of the run).
pub fn publish(dir: &Path, pem: &str) -> Result<Published, CaFileError> {
    let d = CaDir::open(dir)?;
    let lock = d.lock()?;
    d.write_cert(pem)?;
    Ok(Published {
        path: dir.join(CA_FILE),
        _lock: lock,
        _dir: d,
    })
}

/// `--delete-ca`: removes the certificate file. Refuses while a run holds the lock.
pub fn delete(dir: &Path) -> Result<bool, CaFileError> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        _ => {}
    }
    let d = CaDir::open(dir)?;
    let _lock = d.lock()?;
    let existed = std::fs::symlink_metadata(dir.join(CA_FILE)).is_ok();
    if !d.unlink(CA_FILE) {
        return failed("can't delete the certificate file");
    }
    Ok(existed)
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
        assert!(matches!(delete(&d), Err(CaFileError::Busy(_))));
        drop(first);
        assert!(publish(&d, "three").is_ok());
        assert_eq!(fs::read_to_string(d.join(CA_FILE)).unwrap(), "three");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn delete_removes_the_file_and_is_quiet_when_absent() {
        let d = tmp("delete");
        assert!(!delete(&d).unwrap(), "no directory");
        drop(publish(&d, "x").unwrap());
        assert!(delete(&d).unwrap());
        assert!(!d.join(CA_FILE).exists());
        assert!(!delete(&d).unwrap());
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
}
