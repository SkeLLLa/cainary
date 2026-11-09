//! The macOS half of the file procedure; the same interface as os_linux.rs (see there).
//!
//! macOS differences, all in this file:
//! - the trusted path is `/` → `private` → `etc` (`/etc` is a symlink to `/private/etc`), walked
//!   one directory at a time (`TRUSTED_PATH`);
//! - no `O_PATH`: a handle that can be inspected is `O_SYMLINK | O_NONBLOCK`, which opens a
//!   symlink itself and never blocks on a FIFO;
//! - no mount id: `same_mount` compares `st_dev` of `hosts` and `/private/etc` only (APFS volume
//!   boundaries between `/` and `/private` are legitimate);
//! - BSD flags (`st_flags`) with an immutable or append bit refuse the directory or the file;
//! - extended ACLs are never copied: a non-empty one on a trusted directory, on `hosts` or on the
//!   new temp file is refused. Extended attributes and labels are not carried over (there is no
//!   SELinux), so `get_label` and `set_label` are no-ops;
//! - `F_FULLFSYNC` on files, plain `fsync` on the directory;
//! - the invoker's uid is `CAINARY_HOSTS_UID` (set by the app's root script, not by pkexec).

use std::ffi::CStr;
use std::mem;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use libc::{c_int, c_uint, c_void};

use crate::file::Meta;
use crate::helper::Fail;

/// The directories between `/` and the directory that holds `hosts`, in order.
pub(crate) const TRUSTED_PATH: &[&CStr] = &[c"private", c"etc"];

/// File type bits of `Meta::mode`, as `u32` (`libc::mode_t` is `u16` here).
pub(crate) const S_IFMT: u32 = libc::S_IFMT as u32;
pub(crate) const S_IFDIR: u32 = libc::S_IFDIR as u32;
pub(crate) const S_IFLNK: u32 = libc::S_IFLNK as u32;
pub(crate) const S_IFREG: u32 = libc::S_IFREG as u32;

/// A `u32` mode as the `libc::mode_t` the system calls take.
pub(crate) fn mode_t(mode: u32) -> libc::mode_t {
    mode as libc::mode_t
}

/// The `flags` argument of `statx` that stats a symlink itself.
pub(crate) const AT_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;

const ACL_TYPE_EXTENDED: c_uint = 0x0000_0100;
const ACL_FIRST_ENTRY: c_int = 0;

const UF_IMMUTABLE: u32 = 0x0000_0002;
const UF_APPEND: u32 = 0x0000_0004;
const SF_IMMUTABLE: u32 = 0x0002_0000;
const SF_APPEND: u32 = 0x0004_0000;
/// Flags that stop a file or directory from being edited. `SF_NOUNLINK` is deliberately not one:
/// stock `/` and `/private` carry it, and a refused rename over `hosts` is a plain write error.
const RESTRICTING: u32 = UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_uint) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(obj: *mut c_void) -> c_int;
}

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn meta(st: &libc::stat) -> Meta {
    Meta {
        dev: (st.st_dev as u32, 0),
        ino: st.st_ino,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: u32::from(st.st_mode),
        nlink: u32::from(st.st_nlink),
        size: st.st_size as u64,
        mtime: (st.st_mtime, st.st_mtime_nsec as u32),
        ctime: (st.st_ctime, st.st_ctime_nsec as u32),
        mnt_id: None,
    }
}

/// `fstatat`, with the flags `statx` takes on Linux (`AT_NOFOLLOW` or 0). Also the `st_flags`.
fn stat_flags(dir: RawFd, path: &CStr, flags: i32) -> Result<(Meta, u32), i32> {
    // SAFETY: an all-zero stat is valid; the kernel fills it.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `st` is valid for the call.
    if unsafe { libc::fstatat(dir, path.as_ptr(), &mut st, flags) } != 0 {
        return Err(errno());
    }
    Ok((meta(&st), st.st_flags))
}

pub(crate) fn statx(dir: RawFd, path: &CStr, flags: i32) -> Result<Meta, i32> {
    stat_flags(dir, path, flags).map(|(m, _)| m)
}

fn fstat_flags(fd: RawFd) -> Result<(Meta, u32), i32> {
    // SAFETY: an all-zero stat is valid; the kernel fills it.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: `st` is valid for the call.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(errno());
    }
    Ok((meta(&st), st.st_flags))
}

pub(crate) fn fstatx(fd: RawFd) -> Result<Meta, i32> {
    fstat_flags(fd).map(|(m, _)| m)
}

fn open_inspect(dir: RawFd, name: &CStr, extra: i32) -> Result<OwnedFd, i32> {
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_CLOEXEC | extra,
            0,
        )
    };
    if fd < 0 {
        Err(errno())
    } else {
        // SAFETY: `fd` is a fresh descriptor nobody else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// `/`, as a directory, without following a link.
pub(crate) fn open_root() -> Result<OwnedFd, i32> {
    open_inspect(-1, c"/", libc::O_DIRECTORY)
}

/// A handle on `name` in `dir` that is only inspected; a symlink is not followed (it is opened
/// itself), a FIFO does not block.
pub(crate) fn open_path(dir: RawFd, name: &CStr) -> Result<OwnedFd, i32> {
    open_inspect(dir, name, 0)
}

/// Step 4's mount check: `hosts` must be on the same device as `/private/etc`.
pub(crate) fn same_mount(hosts: &Meta, etc: &Meta) -> Result<(), Fail> {
    if hosts.dev == etc.dev {
        Ok(())
    } else {
        Err(Fail::MountPoint)
    }
}

/// Whether `fd` has an extended ACL with at least one entry. An absent ACL, an empty one and a
/// file system without ACLs are all "no".
fn has_acl(fd: RawFd) -> Result<bool, i32> {
    // SAFETY: acl_get_fd_np(3) on a descriptor this process owns; returns NULL on error.
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return match errno() {
            libc::ENOENT | libc::ENOTSUP | libc::EOPNOTSUPP => Ok(false),
            e => Err(e),
        };
    }
    let mut entry: *mut c_void = std::ptr::null_mut();
    // SAFETY: `acl` is a live acl_t and `entry` is valid for the call.
    let found = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
    // SAFETY: `acl` came from acl_get_fd_np and is freed exactly once.
    unsafe { acl_free(acl) };
    Ok(found)
}

fn check_flags(flags: u32) -> Result<(), Fail> {
    if flags & RESTRICTING == 0 {
        Ok(())
    } else {
        Err(Fail::Unprotected)
    }
}

/// An ACL is never carried over, so a source that has one can't be reproduced.
pub(crate) fn get_acl(fd: RawFd) -> Result<Option<Vec<u8>>, i32> {
    if has_acl(fd)? {
        Err(libc::ENOTSUP)
    } else {
        Ok(None)
    }
}

/// Only "no ACL" can be set: the temp file is created without one and a non-empty one is refused
/// by `temp_extra`.
pub(crate) fn set_acl(_fd: RawFd, acl: Option<&[u8]>) -> Result<(), i32> {
    match acl {
        None => Ok(()),
        Some(_) => Err(libc::ENOTSUP),
    }
}

pub(crate) fn get_label(_fd: RawFd) -> Result<Option<Vec<u8>>, i32> {
    Ok(None)
}

pub(crate) fn set_label(_fd: RawFd, _label: &[u8]) -> Result<(), i32> {
    Ok(())
}

/// `F_FULLFSYNC` (flushes the drive's cache too), plain `fsync` where the file system can't.
pub(crate) fn fsync_file(fd: RawFd) -> Result<(), i32> {
    // SAFETY: fcntl(2) F_FULLFSYNC on a descriptor this process owns.
    if unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) } == 0 {
        return Ok(());
    }
    match errno() {
        libc::ENOTSUP | libc::ENOTTY | libc::EINVAL | libc::EOPNOTSUPP => {
            // SAFETY: fsync(2) on a descriptor this process owns.
            if unsafe { libc::fsync(fd) } == 0 {
                Ok(())
            } else {
                Err(errno())
            }
        }
        e => Err(e),
    }
}

/// The raw `CAINARY_HOSTS_UID` value (parsed by helper.rs).
pub(crate) fn invoker_uid() -> Option<String> {
    std::env::var("CAINARY_HOSTS_UID").ok()
}

/// A trusted directory (`/`, `/private`, `/private/etc`): no restricting flag, no ACL entries.
pub(crate) fn trusted_dir_extra(dir: RawFd) -> Result<(), Fail> {
    let (_, flags) = fstat_flags(dir).map_err(|_| Fail::WriteFailed)?;
    check_flags(flags)?;
    if has_acl(dir).map_err(|_| Fail::WriteFailed)? {
        return Err(Fail::Unprotected);
    }
    Ok(())
}

/// `hosts`: no restricting flag, no ACL entries.
pub(crate) fn hosts_extra(hosts: RawFd) -> Result<(), Fail> {
    trusted_dir_extra(hosts)
}

/// The finished temp file, just before it is renamed over `hosts`: no ACL (inherited or not) and
/// no restricting flag.
pub(crate) fn temp_extra(dir: RawFd, name: &CStr) -> Result<(), Fail> {
    let fd = open_path(dir, name).map_err(|_| Fail::Label)?;
    let (m, flags) = fstat_flags(std::os::fd::AsRawFd::as_raw_fd(&fd)).map_err(|_| Fail::Label)?;
    if m.mode & S_IFMT != S_IFREG || flags & RESTRICTING != 0 {
        return Err(Fail::Label);
    }
    match has_acl(std::os::fd::AsRawFd::as_raw_fd(&fd)) {
        Ok(false) => Ok(()),
        _ => Err(Fail::Label),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::Op;
    use crate::file::tests::{Etc, ORIGINAL, expected, no_temps};
    use crate::file::{Done, walk_from};
    use crate::seam;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::process::Command;

    fn chmod(args: &[&str], path: &Path) {
        let st = Command::new("/bin/chmod")
            .args(args)
            .arg(path)
            .status()
            .unwrap();
        assert!(st.success(), "chmod {args:?}");
    }

    fn chflags(flag: &str, path: &Path) {
        let st = Command::new("/usr/bin/chflags")
            .arg(flag)
            .arg(path)
            .status()
            .unwrap();
        assert!(st.success(), "chflags {flag}");
    }

    /// Clears the user immutable flag on drop, so cleanup can remove the file.
    struct Uchg<'a>(&'a Path);
    impl Drop for Uchg<'_> {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(self.0)
                .status();
        }
    }

    fn untouched(etc: &Etc) {
        assert_eq!(etc.read("hosts"), ORIGINAL);
        assert!(!etc.exists("hosts.cainary-backup"));
        no_temps(etc);
    }

    #[test]
    fn round_trip_with_backup_and_lock() {
        let etc = Etc::new();
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert_eq!(etc.read("hosts"), expected());
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
        assert!(etc.exists(".cainary-hosts.lock"));
        assert_eq!(etc.set(), Ok(Done::Unchanged));
        assert_eq!(etc.run(&Op::Clear), Ok(Done::Changed));
        assert_eq!(etc.read("hosts"), ORIGINAL);
        assert_eq!(etc.read("hosts.cainary-backup"), expected());
        no_temps(&etc);
    }

    #[test]
    fn refuses_symlink_hardlink_and_writable_modes() {
        let etc = Etc::new();
        fs::remove_file(etc.p("hosts")).unwrap();
        symlink("/private/etc/hosts", etc.p("hosts")).unwrap();
        assert_eq!(etc.set(), Err(Fail::Symlink));
        fs::remove_file(etc.p("hosts")).unwrap();

        etc.put("hosts", ORIGINAL, 0o644);
        fs::hard_link(etc.p("hosts"), etc.p("other-name")).unwrap();
        assert_eq!(etc.set(), Err(Fail::Hardlinked));
        fs::remove_file(etc.p("other-name")).unwrap();

        for mode in [0o664, 0o646, 0o666] {
            etc.put("hosts", ORIGINAL, mode);
            assert_eq!(etc.set(), Err(Fail::Unprotected), "{mode:o}");
        }
        etc.put("hosts", ORIGINAL, 0o644);
        untouched(&etc);
    }

    #[test]
    fn refuses_a_damaged_block() {
        let etc = Etc::new();
        let damaged = [ORIGINAL, crate::edit::BEGIN.as_bytes(), b"\n"].concat();
        etc.put("hosts", &damaged, 0o644);
        assert_eq!(etc.set(), Err(Fail::DamagedBlock));
        assert_eq!(etc.read("hosts"), damaged);
        assert!(!etc.exists("hosts.cainary-backup"));
        no_temps(&etc);
    }

    #[test]
    fn refuses_restricting_flags_on_hosts() {
        let etc = Etc::new();
        let _clear = Uchg(&etc.p("hosts"));
        chflags("uchg", &etc.p("hosts"));
        assert_eq!(etc.set(), Err(Fail::Unprotected));
        chflags("nouchg", &etc.p("hosts"));
        chflags("uappnd", &etc.p("hosts"));
        let _clear2 = Uchg(&etc.p("hosts"));
        let r = etc.set();
        chflags("nouappnd", &etc.p("hosts"));
        assert_eq!(r, Err(Fail::Unprotected));
        untouched(&etc);
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn refuses_restricting_flags_on_the_directory() {
        let etc = Etc::new();
        let _clear = Uchg(&etc.path);
        chflags("uchg", &etc.path);
        assert_eq!(etc.set(), Err(Fail::Unprotected));
        chflags("nouchg", &etc.path);
        untouched(&etc);
    }

    #[test]
    fn refuses_an_acl_on_hosts() {
        let etc = Etc::new();
        chmod(&["+a", "everyone allow write"], &etc.p("hosts"));
        assert_eq!(etc.set(), Err(Fail::Unprotected));
        chmod(&["-N"], &etc.p("hosts"));
        untouched(&etc);
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn refuses_an_acl_on_the_directory() {
        let etc = Etc::new();
        chmod(&["+a", "everyone allow list"], &etc.path);
        assert_eq!(etc.set(), Err(Fail::Unprotected));
        chmod(&["-N"], &etc.path);
        untouched(&etc);
    }

    #[test]
    fn an_empty_acl_is_fine() {
        let etc = Etc::new();
        chmod(&["+a", "everyone allow write"], &etc.p("hosts"));
        chmod(&["-a", "everyone allow write"], &etc.p("hosts"));
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn an_acl_appearing_on_the_temp_file_is_refused() {
        let etc = Etc::new();
        let new = etc.p(".hosts.cainary-new");
        seam::plan(
            seam::Step::PreCommit,
            seam::Action::Run(Box::new(move |_| {
                chmod(&["+a", "everyone allow write"], &new);
            })),
        );
        assert_eq!(etc.set(), Err(Fail::Label));
        assert_eq!(etc.read("hosts"), ORIGINAL);
        no_temps(&etc);
    }

    #[test]
    fn same_mount_compares_the_device_only() {
        let m = |dev| Meta {
            dev: (dev, 0),
            ino: 2,
            uid: 0,
            gid: 0,
            mode: S_IFREG | 0o644,
            nlink: 1,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mnt_id: None,
        };
        assert_eq!(same_mount(&m(5), &m(5)), Ok(()));
        assert_eq!(same_mount(&m(5), &m(6)), Err(Fail::MountPoint));
    }

    #[test]
    fn flag_mask() {
        assert_eq!(check_flags(0), Ok(()));
        for f in [UF_IMMUTABLE, UF_APPEND, SF_IMMUTABLE, SF_APPEND] {
            assert_eq!(check_flags(f), Err(Fail::Unprotected), "{f:x}");
        }
        // UF_HIDDEN, and the SF_NOUNLINK that stock `/` carries, are harmless.
        assert_eq!(check_flags(0x8000), Ok(()));
        assert_eq!(check_flags(0x0010_0000), Ok(()));
    }

    #[test]
    fn walk_follows_private_etc_and_refuses_a_link() {
        let root = Etc::new();
        let k = seam::knobs();
        let mk = |name: &str| {
            fs::create_dir(root.p(name)).unwrap();
            fs::set_permissions(root.p(name), fs::Permissions::from_mode(0o755)).unwrap();
        };
        // Like the real `/etc`: a link to private/etc is refused, private/etc itself works.
        mk("private");
        fs::create_dir(root.p("private/etc")).unwrap();
        fs::set_permissions(root.p("private/etc"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(walk_from(root.fd.as_raw_fd(), &k).is_ok());
        fs::set_permissions(root.p("private"), fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Unprotected)
        );
        fs::set_permissions(root.p("private"), fs::Permissions::from_mode(0o755)).unwrap();
        chmod(&["+a", "everyone allow list"], &root.p("private"));
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Unprotected)
        );
        chmod(&["-N"], &root.p("private"));
        fs::remove_dir(root.p("private/etc")).unwrap();
        fs::create_dir(root.p("real")).unwrap();
        symlink(root.p("real"), root.p("private/etc")).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Symlink)
        );
        fs::remove_file(root.p("private/etc")).unwrap();
        fs::remove_dir(root.p("private")).unwrap();
        symlink(root.p("real"), root.p("private")).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Symlink)
        );
    }

    #[test]
    fn the_real_chain_passes_for_root_ownership() {
        let root = open_root().unwrap();
        let mut k = seam::knobs();
        k.uid = 0;
        // Only the checks that don't depend on running as root: /, /private and /private/etc are
        // root-owned, not group or world writable, without ACLs or flags on a stock macOS.
        let etc = walk_from(root.as_raw_fd(), &k).expect("stock /private/etc");
        let hosts = statx(etc.as_raw_fd(), c"hosts", AT_NOFOLLOW).unwrap();
        let dir = fstatx(etc.as_raw_fd()).unwrap();
        assert_eq!(same_mount(&hosts, &dir), Ok(()));
    }

    #[test]
    fn invoker_uid_reads_the_macos_variable() {
        // The variable is only read, never set, by the helper.
        assert_eq!(
            invoker_uid(),
            std::env::var("CAINARY_HOSTS_UID").ok(),
            "reads CAINARY_HOSTS_UID"
        );
    }
}
