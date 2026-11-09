//! The Linux half of the file procedure: everything file.rs needs from the operating system that
//! is not portable POSIX. file.rs calls only the `pub(crate)` items here.
//!
//! An OS layer (this file or `os_macos.rs`, selected in main.rs) provides:
//! - `TRUSTED_PATH`: the directory names walked from `/` to the one holding `hosts`
//! - `S_IFMT`, `S_IFDIR`, `S_IFLNK`, `S_IFREG` (as `u32`) and `mode_t(u32)`
//! - `fsync_file(fd)`: flush a file (macOS: `F_FULLFSYNC`)
//! - `errno() -> i32`
//! - `statx(dir, path, flags) -> Result<Meta, i32>` and `fstatx(fd)`: stat into `file::Meta`
//!   (`mnt_id` is `None` when the kernel can't tell)
//! - `AT_NOFOLLOW`: the `flags` value for "stat the link itself"
//! - `open_root() -> Result<OwnedFd, i32>`: `/` without following a link, for walking
//! - `open_path(dir, name) -> Result<OwnedFd, i32>`: a no-follow handle on `name` that can be
//!   inspected but not read (`O_PATH`)
//! - `same_mount(hosts, etc) -> Result<(), Fail>`: `MountPoint` / `NoMountId` refusals
//! - `get_acl`, `set_acl`, `remove_acl`, `get_label`, `set_label`: the access ACL and the
//!   security label as opaque bytes (`None` when absent or unsupported)
//! - `ACL`, `SELINUX`: attribute names, for the tests that read them directly
//! - `invoker_uid() -> Option<String>`: the raw invoker uid (Linux: `PKEXEC_UID`)
//! - `trusted_dir_extra(fd)`, `hosts_extra(fd)`, `temp_extra(dir, name)`: extra refusals (ACLs,
//!   flags, re-check of the temp before rename); no-ops on Linux

use std::ffi::CStr;
use std::mem;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::file::Meta;
use crate::helper::Fail;

pub(crate) const SELINUX: &CStr = c"security.selinux";
pub(crate) const ACL: &CStr = c"system.posix_acl_access";

/// The directories between `/` and the directory that holds `hosts`, in order.
pub(crate) const TRUSTED_PATH: &[&CStr] = &[c"etc"];

/// File type bits of `Meta::mode`, as `u32` (`libc::mode_t` differs between the systems).
pub(crate) const S_IFMT: u32 = libc::S_IFMT;
pub(crate) const S_IFDIR: u32 = libc::S_IFDIR;
pub(crate) const S_IFLNK: u32 = libc::S_IFLNK;
pub(crate) const S_IFREG: u32 = libc::S_IFREG;

/// A `u32` mode as the `libc::mode_t` the system calls take.
pub(crate) fn mode_t(mode: u32) -> libc::mode_t {
    mode
}

/// The `flags` argument of `statx` that stats a symlink itself.
pub(crate) const AT_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

const NEEDED: u32 = libc::STATX_TYPE
    | libc::STATX_MODE
    | libc::STATX_NLINK
    | libc::STATX_UID
    | libc::STATX_GID
    | libc::STATX_MTIME
    | libc::STATX_CTIME
    | libc::STATX_INO
    | libc::STATX_SIZE;

pub(crate) fn statx(dir: RawFd, path: &CStr, flags: i32) -> Result<Meta, i32> {
    // SAFETY: an all-zero statx is valid; the kernel fills it.
    let mut sx: libc::statx = unsafe { mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `sx` is valid for the call.
    let rc = unsafe {
        libc::statx(
            dir,
            path.as_ptr(),
            flags,
            NEEDED | libc::STATX_MNT_ID,
            &mut sx,
        )
    };
    if rc != 0 {
        return Err(errno());
    }
    if sx.stx_mask & NEEDED != NEEDED {
        return Err(libc::EIO);
    }
    Ok(Meta {
        dev: (sx.stx_dev_major, sx.stx_dev_minor),
        ino: sx.stx_ino,
        uid: sx.stx_uid,
        gid: sx.stx_gid,
        mode: u32::from(sx.stx_mode),
        nlink: sx.stx_nlink,
        size: sx.stx_size,
        mtime: (sx.stx_mtime.tv_sec, sx.stx_mtime.tv_nsec),
        ctime: (sx.stx_ctime.tv_sec, sx.stx_ctime.tv_nsec),
        mnt_id: (sx.stx_mask & libc::STATX_MNT_ID != 0).then_some(sx.stx_mnt_id),
    })
}

pub(crate) fn fstatx(fd: RawFd) -> Result<Meta, i32> {
    statx(fd, c"", libc::AT_EMPTY_PATH)
}

fn open_o_path(dir: RawFd, name: &CStr, extra: i32) -> Result<OwnedFd, i32> {
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | extra,
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

/// `/`, as a directory, without following a link. The absolute path makes the descriptor
/// argument irrelevant.
pub(crate) fn open_root() -> Result<OwnedFd, i32> {
    open_o_path(-1, c"/", libc::O_DIRECTORY)
}

/// A handle on `name` in `dir` that can be inspected, not read; a symlink is not followed.
pub(crate) fn open_path(dir: RawFd, name: &CStr) -> Result<OwnedFd, i32> {
    open_o_path(dir, name, 0)
}

/// Step 4's mount check: `hosts` must be on the same mount as `/etc`.
pub(crate) fn same_mount(hosts: &Meta, etc: &Meta) -> Result<(), Fail> {
    match (hosts.mnt_id, etc.mnt_id) {
        (Some(h), Some(e)) if h == e => Ok(()),
        (Some(_), Some(_)) => Err(Fail::MountPoint),
        _ => Err(Fail::NoMountId),
    }
}

/// `fsync` of a file (macOS: `F_FULLFSYNC`).
pub(crate) fn fsync_file(fd: RawFd) -> Result<(), i32> {
    // SAFETY: fsync(2) on a descriptor this process owns.
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub(crate) fn absent(e: i32) -> bool {
    e == libc::ENODATA || e == libc::ENOTSUP || e == libc::EOPNOTSUPP
}

/// The value of an extended attribute; `None` when it is absent (or the file system has none).
pub(crate) fn get_xattr(fd: RawFd, name: &CStr) -> Result<Option<Vec<u8>>, i32> {
    for _ in 0..4 {
        // SAFETY: a null buffer with size 0 asks for the length.
        let size = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return if absent(errno()) {
                Ok(None)
            } else {
                Err(errno())
            };
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            match errno() {
                libc::ERANGE => continue,
                e if absent(e) => return Ok(None),
                e => return Err(e),
            }
        }
        buf.truncate(n as usize);
        return Ok(Some(buf));
    }
    Err(libc::ERANGE)
}

pub(crate) fn set_xattr(fd: RawFd, name: &CStr, value: &[u8]) -> Result<(), i32> {
    // SAFETY: `value` is valid for `value.len()` bytes.
    let rc = unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Removes an attribute; already absent is fine.
pub(crate) fn remove_xattr(fd: RawFd, name: &CStr) -> Result<(), i32> {
    // SAFETY: fremovexattr(2) with a NUL-terminated name.
    if unsafe { libc::fremovexattr(fd, name.as_ptr()) } == 0 || absent(errno()) {
        Ok(())
    } else {
        Err(errno())
    }
}

pub(crate) fn get_acl(fd: RawFd) -> Result<Option<Vec<u8>>, i32> {
    get_xattr(fd, ACL)
}

/// Sets the access ACL, or removes it for `None`, so an inherited one can't survive.
pub(crate) fn set_acl(fd: RawFd, acl: Option<&[u8]>) -> Result<(), i32> {
    match acl {
        Some(acl) => set_xattr(fd, ACL, acl),
        None => remove_xattr(fd, ACL),
    }
}

pub(crate) fn get_label(fd: RawFd) -> Result<Option<Vec<u8>>, i32> {
    get_xattr(fd, SELINUX)
}

pub(crate) fn set_label(fd: RawFd, label: &[u8]) -> Result<(), i32> {
    set_xattr(fd, SELINUX, label)
}

/// The raw `PKEXEC_UID` value (parsed by helper.rs); the OS layer decides where the invoker's
/// uid comes from.
pub(crate) fn invoker_uid() -> Option<String> {
    std::env::var("PKEXEC_UID").ok()
}

/// Extra checks on a trusted directory (`/`, `/etc`) beyond owner and mode; a descriptor that
/// can be inspected. Linux has none (macOS: ACLs and flags on `/`, `/private`, `/private/etc`).
pub(crate) fn trusted_dir_extra(_dir: RawFd) -> Result<(), Fail> {
    Ok(())
}

/// Extra checks on the `hosts` file beyond owner, mode, link count and mount (macOS: ACLs and
/// flags).
pub(crate) fn hosts_extra(_hosts: RawFd) -> Result<(), Fail> {
    Ok(())
}

/// Re-check of the finished temp file `name` in `dir`, just before it is renamed over `hosts`.
pub(crate) fn temp_extra(_dir: RawFd, _name: &CStr) -> Result<(), Fail> {
    Ok(())
}
