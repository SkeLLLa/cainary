//! The file procedure. Every step is descriptor-relative (`openat` and friends on a
//! directory descriptor, `O_CLOEXEC` throughout), and this is the only file that touches the file
//! system: the whole crate goes through the libc `*at` calls below. The names it may touch are the
//! `c"…"` constants right here. `apply` walks to `/etc`; `apply_in` takes the directory
//! descriptor, so a test can run the same procedure on a temp directory (see seam.rs).

use std::ffi::CStr;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use crate::edit::{self, Op};
use crate::helper::Fail;
use crate::seam::{self, Knobs, Step, Sys};

#[derive(Debug, PartialEq)]
pub enum Done {
    Unchanged,
    Changed,
    /// Replaced, but the fsync of the directory failed.
    ChangedUnsynced,
}

impl Done {
    pub fn word(&self) -> &'static str {
        match self {
            Done::Unchanged => "unchanged",
            Done::Changed => "changed",
            Done::ChangedUnsynced => "changed-unsynced",
        }
    }
}

const LOCK: &CStr = c".cainary-hosts.lock";
const NEW: &CStr = c".hosts.cainary-new";
const BAK_NEW: &CStr = c".hosts.cainary-bak-new";
const HOSTS: &CStr = c"hosts";
const BACKUP: &CStr = c"hosts.cainary-backup";
const SELINUX: &CStr = c"security.selinux";
const ACL: &CStr = c"system.posix_acl_access";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn openat(dir: RawFd, name: &CStr, flags: i32, mode: u32) -> Result<OwnedFd, i32> {
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        Err(errno())
    } else {
        // SAFETY: `fd` is a fresh descriptor nobody else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// An error that says the file system or the directory refuses writes.
fn io_fail(e: i32) -> Fail {
    if e == libc::EROFS || e == libc::EPERM {
        Fail::ReadOnly
    } else {
        Fail::WriteFailed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Meta {
    dev: (u32, u32),
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u32,
    size: u64,
    mtime: (i64, u32),
    ctime: (i64, u32),
    /// `None` when the kernel doesn't report it (Linux before 5.8).
    mnt_id: Option<u64>,
}

impl Meta {
    fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }
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

fn statx(dir: RawFd, path: &CStr, flags: i32) -> Result<Meta, i32> {
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

fn fstatx(fd: RawFd) -> Result<Meta, i32> {
    statx(fd, c"", libc::AT_EMPTY_PATH)
}

fn fsync(fd: RawFd, call: Sys) -> Result<(), i32> {
    if let Some(e) = seam::sys(call) {
        return Err(e);
    }
    // SAFETY: fsync(2) on a descriptor this process owns.
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Writes all of `data`; `part` runs after every call that wrote less than all of it.
fn write_all(
    fd: RawFd,
    mut data: &[u8],
    chunk: usize,
    mut part: impl FnMut() -> Result<(), Fail>,
) -> Result<(), Fail> {
    while !data.is_empty() {
        if let Some(e) = seam::sys(Sys::Write) {
            return Err(io_fail_write(e));
        }
        let len = data.len().min(chunk);
        // SAFETY: `data` is valid for `len` bytes.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), len) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(io_fail_write(errno()));
        }
        if n == 0 {
            return Err(Fail::WriteFailed);
        }
        data = &data[n as usize..];
        if !data.is_empty() {
            part()?;
        }
    }
    Ok(())
}

fn io_fail_write(_errno: i32) -> Fail {
    Fail::WriteFailed
}

fn absent(e: i32) -> bool {
    e == libc::ENODATA || e == libc::ENOTSUP || e == libc::EOPNOTSUPP
}

/// The value of an extended attribute; `None` when it is absent (or the file system has none).
fn get_xattr(fd: RawFd, name: &CStr) -> Result<Option<Vec<u8>>, i32> {
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

fn set_xattr(fd: RawFd, name: &CStr, value: &[u8]) -> Result<(), i32> {
    // SAFETY: `value` is valid for `value.len()` bytes.
    let rc = unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// Removes an attribute; already absent is fine.
fn remove_xattr(fd: RawFd, name: &CStr) -> Result<(), i32> {
    // SAFETY: fremovexattr(2) with a NUL-terminated name.
    if unsafe { libc::fremovexattr(fd, name.as_ptr()) } == 0 || absent(errno()) {
        Ok(())
    } else {
        Err(errno())
    }
}

fn is_protected(m: &Meta, uid: u32) -> bool {
    m.uid == uid && m.mode & 0o022 == 0
}

/// `/` and `/etc`: real directories owned by the trusted user, not writable by group or others.
fn check_dir(m: &Meta, uid: u32) -> Result<(), Fail> {
    if m.kind() == libc::S_IFDIR && is_protected(m, uid) {
        Ok(())
    } else {
        Err(Fail::Unprotected)
    }
}

/// Step 4: whether `hosts` may be edited at all.
fn admit(hosts: &Meta, etc: &Meta, uid: u32) -> Result<(), Fail> {
    match hosts.kind() {
        libc::S_IFLNK => return Err(Fail::Symlink),
        libc::S_IFREG => {}
        _ => return Err(Fail::NotRegular),
    }
    if !is_protected(hosts, uid) {
        return Err(Fail::Unprotected);
    }
    if hosts.nlink != 1 {
        return Err(Fail::Hardlinked);
    }
    match (hosts.mnt_id, etc.mnt_id) {
        (Some(h), Some(e)) if h == e => Ok(()),
        (Some(_), Some(_)) => Err(Fail::MountPoint),
        _ => Err(Fail::NoMountId),
    }
}

/// Step 1: from `root` (`/` in production) to `etc`, without following a link.
fn walk_from(root: RawFd, k: &Knobs) -> Result<OwnedFd, Fail> {
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let rm = fstatx(root).map_err(|_| Fail::WriteFailed)?;
    check_dir(&rm, k.uid)?;
    // No O_DIRECTORY here: with O_NOFOLLOW it would turn a symlink into ENOTDIR.
    let path = openat(root, c"etc", libc::O_PATH | libc::O_NOFOLLOW, 0).map_err(|e| match e {
        libc::ENOENT => Fail::NotRegular,
        _ => Fail::WriteFailed,
    })?;
    let pm = fstatx(path.as_raw_fd()).map_err(|_| Fail::WriteFailed)?;
    match pm.mode & libc::S_IFMT {
        libc::S_IFLNK => return Err(Fail::Symlink),
        libc::S_IFDIR => {}
        _ => return Err(Fail::NotRegular),
    }
    check_dir(&pm, k.uid)?;
    let dir = openat(root, c"etc", libc::O_RDONLY | flags, 0).map_err(|_| Fail::WriteFailed)?;
    let dm = fstatx(dir.as_raw_fd()).map_err(|_| Fail::WriteFailed)?;
    if (dm.dev, dm.ino) != (pm.dev, pm.ino) {
        return Err(Fail::Changed);
    }
    Ok(dir)
}

pub fn apply(op: &Op, node: &str) -> Result<Done, Fail> {
    // Absolute path: the descriptor argument is ignored by the kernel.
    let root = openat(
        -1,
        c"/",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
    .map_err(|_| Fail::WriteFailed)?;
    let etc = walk_from(root.as_raw_fd(), &seam::knobs())?;
    apply_in(&etc, op, node)
}

/// Steps 1 (admission of the directory) to 14, on an already opened directory.
pub fn apply_in(etc: &OwnedFd, op: &Op, node: &str) -> Result<Done, Fail> {
    let k = seam::knobs();
    let dir = etc.as_raw_fd();
    check_dir(&fstatx(dir).map_err(|_| Fail::WriteFailed)?, k.uid)?;
    let _lock = take_lock(dir, &k)?;
    let result = locked(dir, op, node, &k);
    // Cleanup is for failures. After a (simulated) kill nothing runs, as after SIGKILL.
    if result.is_err() && !seam::crashed() {
        remove_temps(dir);
    }
    result
}

/// Step 2: the permanent lock file, verified, then `flock` with a deadline.
fn take_lock(dir: RawFd, k: &Knobs) -> Result<OwnedFd, Fail> {
    let fd = openat(
        dir,
        LOCK,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|e| {
        if e == libc::ELOOP {
            Fail::BadLock
        } else {
            io_fail(e)
        }
    })?;
    let m = fstatx(fd.as_raw_fd()).map_err(|_| Fail::WriteFailed)?;
    if m.kind() != libc::S_IFREG || m.uid != k.uid || m.mode & 0o077 != 0 || m.nlink != 1 {
        return Err(Fail::BadLock);
    }
    seam::hook(Step::LockCreate, dir)?;
    let deadline = Instant::now() + k.lock_deadline;
    loop {
        // SAFETY: flock(2) on a descriptor this process owns.
        if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(fd);
        }
        match errno() {
            libc::EINTR => {}
            libc::EWOULDBLOCK => {
                if Instant::now() >= deadline {
                    return Err(Fail::Busy);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => return Err(Fail::WriteFailed),
        }
    }
}

fn unlink_temp(dir: RawFd, name: &CStr) -> Result<(), Fail> {
    // SAFETY: `name` is NUL-terminated; flag 0 never removes a directory.
    if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } != 0 && errno() != libc::ENOENT {
        return Err(io_fail(errno()));
    }
    Ok(())
}

fn remove_temps(dir: RawFd) {
    let _ = unlink_temp(dir, NEW);
    let _ = unlink_temp(dir, BAK_NEW);
}

fn rename(dir: RawFd, from: &CStr, to: &CStr, call: Sys) -> Result<(), i32> {
    if let Some(e) = seam::sys(call) {
        return Err(e);
    }
    // SAFETY: both names are NUL-terminated and outlive the call.
    if unsafe { libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// What a temp file must end up as.
struct Spec<'a> {
    uid: u32,
    gid: u32,
    mode: u32,
    acl: &'a Option<Vec<u8>>,
    label: &'a Option<Vec<u8>>,
}

struct Steps {
    create: Step,
    write: Step,
    part: Step,
    owner: Step,
    acl: Step,
    label: Step,
    mode: Step,
    fsync: Step,
    sys_fsync: Sys,
}

const BACKUP_STEPS: Steps = Steps {
    create: Step::BakCreate,
    write: Step::BakWrite,
    part: Step::BakPart,
    owner: Step::BakOwner,
    acl: Step::BakAcl,
    label: Step::BakLabel,
    mode: Step::BakMode,
    fsync: Step::BakFsync,
    sys_fsync: Sys::FsyncBak,
};

const NEW_STEPS: Steps = Steps {
    create: Step::NewCreate,
    write: Step::NewWrite,
    part: Step::NewPart,
    owner: Step::NewOwner,
    acl: Step::NewAcl,
    label: Step::NewLabel,
    mode: Step::NewMode,
    fsync: Step::NewFsync,
    sys_fsync: Sys::FsyncNew,
};

/// Creates `name` exclusively, writes `data`, sets owner, access ACL (set or removed, so an
/// inherited one can't survive), label and mode, checks the result and fsyncs. The temp stays;
/// the caller renames it or the cleanup removes it.
fn make_temp(dir: RawFd, name: &CStr, data: &[u8], spec: &Spec, steps: &Steps) -> Result<(), Fail> {
    let fd = openat(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(io_fail)?;
    let raw = fd.as_raw_fd();
    seam::hook(steps.create, dir)?;
    write_all(raw, data, seam::knobs().write_chunk, || {
        seam::hook(steps.part, dir)
    })?;
    seam::hook(steps.write, dir)?;

    // Owner, then ACL, then label, then mode; each is its own mutation with its own hook.
    // SAFETY: fchown(2) on a descriptor this process owns.
    if seam::sys(Sys::Chown).is_some() || unsafe { libc::fchown(raw, spec.uid, spec.gid) } != 0 {
        return Err(Fail::Label);
    }
    seam::hook(steps.owner, dir)?;
    if seam::sys(Sys::Acl).is_some() {
        return Err(Fail::Label);
    }
    match spec.acl {
        Some(acl) => set_xattr(raw, ACL, acl),
        None => remove_xattr(raw, ACL),
    }
    .map_err(|_| Fail::Label)?;
    seam::hook(steps.acl, dir)?;
    if let Some(label) = spec.label
        && get_xattr(raw, SELINUX).map_err(|_| Fail::Label)?.as_ref() != Some(label)
    {
        if seam::sys(Sys::Label).is_some() {
            return Err(Fail::Label);
        }
        set_xattr(raw, SELINUX, label).map_err(|_| Fail::Label)?;
    }
    seam::hook(steps.label, dir)?;
    // After the ACL: with an access ACL present, the group bits are its mask.
    // SAFETY: fchmod(2) on a descriptor this process owns.
    if seam::sys(Sys::Chmod).is_some() || unsafe { libc::fchmod(raw, spec.mode) } != 0 {
        return Err(Fail::Label);
    }
    seam::hook(steps.mode, dir)?;

    let m = fstatx(raw).map_err(|_| Fail::Label)?;
    let same = m.uid == spec.uid
        && m.gid == spec.gid
        && m.mode & 0o7777 == spec.mode
        && get_xattr(raw, ACL).map_err(|_| Fail::Label)? == *spec.acl
        && get_xattr(raw, SELINUX).map_err(|_| Fail::Label)? == *spec.label;
    if !same {
        return Err(Fail::Label);
    }
    fsync(raw, steps.sys_fsync).map_err(|_| Fail::WriteFailed)?;
    seam::hook(steps.fsync, dir)
}

/// Steps 3 to 14, under the lock.
fn locked(dir: RawFd, op: &Op, node: &str, k: &Knobs) -> Result<Done, Fail> {
    // 3. Stale temps.
    unlink_temp(dir, NEW)?;
    seam::hook(Step::UnlinkNew, dir)?;
    unlink_temp(dir, BAK_NEW)?;
    seam::hook(Step::UnlinkBakNew, dir)?;

    // 4. Admit `hosts` without opening it.
    let path = openat(dir, HOSTS, libc::O_PATH | libc::O_NOFOLLOW, 0).map_err(|e| match e {
        libc::ENOENT => Fail::NotRegular,
        _ => Fail::WriteFailed,
    })?;
    let pm = fstatx(path.as_raw_fd()).map_err(|_| Fail::WriteFailed)?;
    let em = fstatx(dir).map_err(|_| Fail::WriteFailed)?;
    admit(&pm, &em, k.uid)?;

    // 5. Reopen for reading; same file, then the snapshot.
    let read = openat(
        dir,
        HOSTS,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
        0,
    )
    .map_err(|_| Fail::Changed)?;
    let rfd = read.as_raw_fd();
    let s = fstatx(rfd).map_err(|_| Fail::WriteFailed)?;
    if (s.dev, s.ino) != (pm.dev, pm.ino) {
        return Err(Fail::Changed);
    }
    admit(&s, &em, k.uid)?;

    // 6. Read, bounded by the bytes actually read.
    let mut data = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // Never more than one byte past the limit, so refusing costs at most that byte.
        let want = buf.len().min(k.max_read + 1 - data.len());
        // SAFETY: `buf` is valid for `want` (at most `buf.len()`) bytes.
        let n = unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), want) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Fail::WriteFailed);
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
        if data.len() > k.max_read {
            return Err(Fail::TooLarge);
        }
        seam::hook(Step::ReadChunk, dir)?;
    }

    // 7. Edit.
    if let Op::Set(hosts) = op {
        edit::alias_conflict(&data, hosts, node)?;
    }
    let new = edit::edit(&data, op)?;
    if new == data {
        return Ok(Done::Unchanged);
    }

    // 8. What the source carries; an unreadable attribute is a refusal.
    let label = get_xattr(rfd, SELINUX).map_err(|_| Fail::Label)?;
    let acl = get_xattr(rfd, ACL).map_err(|_| Fail::Label)?;

    // 9. Backup from the snapshot bytes, in its own temp, root-only, never removed by us.
    let none = None;
    make_temp(
        dir,
        BAK_NEW,
        &data,
        &Spec {
            uid: k.uid,
            gid: k.gid,
            mode: 0o600,
            acl: &none,
            label: &label,
        },
        &BACKUP_STEPS,
    )?;
    rename(dir, BAK_NEW, BACKUP, Sys::RenameBak).map_err(io_fail)?;
    seam::hook(Step::BakRename, dir)?;
    fsync(dir, Sys::FsyncBakDir).map_err(|_| Fail::WriteFailed)?;
    seam::hook(Step::BakDirFsync, dir)?;

    // 10. The new file, with the source's owner, mode, ACL and label.
    make_temp(
        dir,
        NEW,
        &new,
        &Spec {
            uid: s.uid,
            gid: s.gid,
            mode: s.mode & 0o777,
            acl: &acl,
            label: &label,
        },
        &NEW_STEPS,
    )?;

    // 11. Still the same file, by descriptor and by path (best effort against other editors).
    seam::hook(Step::PreCommit, dir)?;
    let by_fd = fstatx(rfd).map_err(|_| Fail::Changed)?;
    let by_path = statx(dir, HOSTS, libc::AT_SYMLINK_NOFOLLOW).map_err(|_| Fail::Changed)?;
    if by_fd != s || by_path != s {
        return Err(Fail::Changed);
    }

    // 12. Commit: after this no error is ever reported.
    rename(dir, NEW, HOSTS, Sys::RenameNew).map_err(io_fail)?;
    seam::hook(Step::Commit, dir)?;

    // 13. Durability of the rename.
    let injected = seam::hook(Step::FinalFsync, dir).is_err();
    if injected || fsync(dir, Sys::FsyncFinal).is_err() {
        Ok(Done::ChangedUnsynced)
    } else {
        Ok(Done::Changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seam::Action;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ORIGINAL: &[u8] = b"127.0.0.1 localhost\n::1 localhost\n";
    const HOST: &str = "otel.example.com";

    /// A temp directory standing in for `/etc`, with an `hosts` file in it.
    struct Etc {
        path: PathBuf,
        fd: OwnedFd,
    }

    impl Etc {
        fn new() -> Etc {
            static N: AtomicUsize = AtomicUsize::new(0);
            seam::reset();
            let path = std::env::temp_dir().join(format!(
                "cainary-hosts-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let fd = openat(
                -1,
                &std::ffi::CString::new(path.to_str().unwrap()).unwrap(),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )
            .unwrap();
            let etc = Etc { path, fd };
            etc.put("hosts", ORIGINAL, 0o644);
            etc
        }

        fn p(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn put(&self, name: &str, data: &[u8], mode: u32) {
            fs::write(self.p(name), data).unwrap();
            fs::set_permissions(self.p(name), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn read(&self, name: &str) -> Vec<u8> {
            fs::read(self.p(name)).unwrap()
        }

        fn exists(&self, name: &str) -> bool {
            fs::symlink_metadata(self.p(name)).is_ok()
        }

        fn run(&self, op: &Op) -> Result<Done, Fail> {
            apply_in(&self.fd, op, "myhost")
        }

        fn set(&self) -> Result<Done, Fail> {
            self.run(&Op::Set(vec![HOST.to_string()]))
        }
    }

    impl Drop for Etc {
        fn drop(&mut self) {
            seam::reset();
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn expected() -> Vec<u8> {
        edit::edit(ORIGINAL, &Op::Set(vec![HOST.to_string()])).unwrap()
    }

    fn no_temps(etc: &Etc) {
        assert!(!etc.exists(".hosts.cainary-new"), "new temp left");
        assert!(!etc.exists(".hosts.cainary-bak-new"), "backup temp left");
    }

    #[test]
    fn set_then_clear_round_trip() {
        let etc = Etc::new();
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert_eq!(etc.read("hosts"), expected());
        // The backup holds the pre-edit bytes, root-only (here: owner-only).
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
        let b = fs::metadata(etc.p("hosts.cainary-backup")).unwrap();
        assert_eq!(b.mode() & 0o7777, 0o600);
        assert_eq!(etc.set(), Ok(Done::Unchanged));
        assert_eq!(etc.run(&Op::Clear), Ok(Done::Changed));
        assert_eq!(etc.read("hosts"), ORIGINAL);
        assert_eq!(etc.run(&Op::Clear), Ok(Done::Unchanged));
        // Clear keeps the backup, which now holds the file as it was with the block.
        assert_eq!(etc.read("hosts.cainary-backup"), expected());
        no_temps(&etc);
    }

    #[test]
    fn unchanged_writes_nothing() {
        let etc = Etc::new();
        assert_eq!(etc.run(&Op::Clear), Ok(Done::Unchanged));
        assert!(!etc.exists("hosts.cainary-backup"));
        no_temps(&etc);
        let before = fs::metadata(etc.p("hosts")).unwrap();
        assert_eq!(etc.run(&Op::Clear), Ok(Done::Unchanged));
        let after = fs::metadata(etc.p("hosts")).unwrap();
        assert_eq!(
            (before.ino(), before.mtime_nsec()),
            (after.ino(), after.mtime_nsec())
        );
    }

    #[test]
    fn mode_and_owner_are_preserved() {
        let etc = Etc::new();
        etc.put("hosts", ORIGINAL, 0o640);
        let before = fs::metadata(etc.p("hosts")).unwrap();
        assert_eq!(etc.set(), Ok(Done::Changed));
        let after = fs::metadata(etc.p("hosts")).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_ne!(after.ino(), before.ino());
        assert_eq!(after.nlink(), 1);
    }

    #[test]
    fn absent_attributes_stay_absent() {
        let etc = Etc::new();
        assert_eq!(etc.set(), Ok(Done::Changed));
        let fd = openat(etc.fd.as_raw_fd(), c"hosts", libc::O_RDONLY, 0).unwrap();
        assert_eq!(get_xattr(fd.as_raw_fd(), ACL), Ok(None));
        // Label: equal to the source's, whatever it is (none without SELinux).
        let bak = openat(etc.fd.as_raw_fd(), BACKUP, libc::O_RDONLY, 0).unwrap();
        assert_eq!(
            get_xattr(fd.as_raw_fd(), SELINUX),
            get_xattr(bak.as_raw_fd(), SELINUX)
        );
    }

    #[test]
    fn refuses_symlink_fifo_hardlink_and_unprotected() {
        let etc = Etc::new();
        fs::remove_file(etc.p("hosts")).unwrap();
        symlink("/etc/static/hosts", etc.p("hosts")).unwrap();
        assert_eq!(etc.set(), Err(Fail::Symlink));
        fs::remove_file(etc.p("hosts")).unwrap();

        // A FIFO is never opened, so this returns at once instead of blocking.
        let fifo = std::ffi::CString::new(etc.p("hosts").to_str().unwrap()).unwrap();
        // SAFETY: mkfifo(3) with a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let t = Instant::now();
        assert_eq!(etc.set(), Err(Fail::NotRegular));
        assert!(t.elapsed() < Duration::from_secs(2));
        fs::remove_file(etc.p("hosts")).unwrap();

        etc.put("hosts", ORIGINAL, 0o644);
        fs::hard_link(etc.p("hosts"), etc.p("other-name")).unwrap();
        assert_eq!(etc.set(), Err(Fail::Hardlinked));
        fs::remove_file(etc.p("other-name")).unwrap();

        for mode in [0o664, 0o646, 0o666] {
            etc.put("hosts", ORIGINAL, mode);
            assert_eq!(etc.set(), Err(Fail::Unprotected), "{mode:o}");
        }
        fs::remove_file(etc.p("hosts")).unwrap();
        assert_eq!(etc.set(), Err(Fail::NotRegular));
        // Nothing was replaced and nothing is left behind.
        assert!(!etc.exists("hosts.cainary-backup"));
        no_temps(&etc);
    }

    fn meta(uid: u32, mode: u32, nlink: u32, mnt: Option<u64>) -> Meta {
        Meta {
            dev: (0, 1),
            ino: 2,
            uid,
            gid: 0,
            mode,
            nlink,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mnt_id: mnt,
        }
    }

    #[test]
    fn admission_rules() {
        let reg = libc::S_IFREG | 0o644;
        let etc = meta(0, libc::S_IFDIR | 0o755, 2, Some(7));
        assert_eq!(admit(&meta(0, reg, 1, Some(7)), &etc, 0), Ok(()));
        assert_eq!(
            admit(&meta(0, libc::S_IFLNK | 0o777, 1, Some(7)), &etc, 0),
            Err(Fail::Symlink)
        );
        assert_eq!(
            admit(&meta(0, libc::S_IFIFO | 0o644, 1, Some(7)), &etc, 0),
            Err(Fail::NotRegular)
        );
        assert_eq!(
            admit(&meta(0, libc::S_IFDIR | 0o755, 1, Some(7)), &etc, 0),
            Err(Fail::NotRegular)
        );
        // Not owned by the trusted user, or writable by group or others.
        assert_eq!(
            admit(&meta(1000, reg, 1, Some(7)), &etc, 0),
            Err(Fail::Unprotected)
        );
        assert_eq!(
            admit(&meta(0, libc::S_IFREG | 0o664, 1, Some(7)), &etc, 0),
            Err(Fail::Unprotected)
        );
        assert_eq!(
            admit(&meta(0, libc::S_IFREG | 0o646, 1, Some(7)), &etc, 0),
            Err(Fail::Unprotected)
        );
        assert_eq!(
            admit(&meta(0, reg, 2, Some(7)), &etc, 0),
            Err(Fail::Hardlinked)
        );
        // A bind mount on the same file system has another mount id.
        assert_eq!(
            admit(&meta(0, reg, 1, Some(8)), &etc, 0),
            Err(Fail::MountPoint)
        );
        assert_eq!(admit(&meta(0, reg, 1, None), &etc, 0), Err(Fail::NoMountId));
        let old = meta(0, libc::S_IFDIR | 0o755, 2, None);
        assert_eq!(
            admit(&meta(0, reg, 1, Some(7)), &old, 0),
            Err(Fail::NoMountId)
        );
        // Directories.
        assert_eq!(check_dir(&etc, 0), Ok(()));
        assert_eq!(
            check_dir(&meta(0, libc::S_IFDIR | 0o775, 2, Some(7)), 0),
            Err(Fail::Unprotected)
        );
        assert_eq!(
            check_dir(&meta(5, libc::S_IFDIR | 0o755, 2, Some(7)), 0),
            Err(Fail::Unprotected)
        );
        assert_eq!(
            check_dir(&meta(0, libc::S_IFLNK | 0o755, 2, Some(7)), 0),
            Err(Fail::Unprotected)
        );
    }

    #[test]
    fn real_mount_id_is_reported_for_both() {
        let etc = Etc::new();
        let hosts = statx(etc.fd.as_raw_fd(), HOSTS, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        let dir = fstatx(etc.fd.as_raw_fd()).unwrap();
        assert!(hosts.mnt_id.is_some() && hosts.mnt_id == dir.mnt_id);
    }

    #[test]
    fn too_large_counts_bytes_actually_read() {
        let etc = Etc::new();
        seam::set_max_read(ORIGINAL.len() - 1);
        assert_eq!(etc.set(), Err(Fail::TooLarge));
        no_temps(&etc);
        assert_eq!(etc.read("hosts"), ORIGINAL);
        // Exactly the limit is fine.
        seam::set_max_read(ORIGINAL.len());
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn growth_during_the_read_is_too_large() {
        let etc = Etc::new();
        seam::set_max_read(ORIGINAL.len() + 10);
        let path = etc.p("hosts");
        seam::plan(
            Step::ReadChunk,
            Action::Run(Box::new(move |_| {
                let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
                std::io::Write::write_all(&mut f, &[b'#'; 64]).unwrap();
            })),
        );
        assert_eq!(etc.set(), Err(Fail::TooLarge));
        no_temps(&etc);
    }

    #[test]
    fn a_change_before_commit_is_refused() {
        for change in ["append", "replace", "chmod", "touch"] {
            let etc = Etc::new();
            let path = etc.p("hosts");
            let tmp = etc.p("replacement");
            seam::plan(
                Step::PreCommit,
                Action::Run(Box::new(move |_| match change {
                    "append" => {
                        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
                        std::io::Write::write_all(&mut f, b"# sudoedit\n").unwrap();
                    }
                    "replace" => {
                        fs::write(&tmp, b"other\n").unwrap();
                        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();
                        fs::rename(&tmp, &path).unwrap();
                    }
                    "chmod" => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap()
                    }
                    _ => {
                        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
                        f.set_modified(std::time::SystemTime::UNIX_EPOCH).unwrap();
                    }
                })),
            );
            assert_eq!(etc.set(), Err(Fail::Changed), "{change}");
            no_temps(&etc);
            assert!(
                !String::from_utf8_lossy(&etc.read("hosts")).contains("cAInary"),
                "{change}"
            );
        }
    }

    #[test]
    fn a_bad_lock_file_is_refused() {
        let etc = Etc::new();
        etc.put("target", b"", 0o600);
        symlink(etc.p("target"), etc.p(".cainary-hosts.lock")).unwrap();
        assert_eq!(etc.set(), Err(Fail::BadLock));
        fs::remove_file(etc.p(".cainary-hosts.lock")).unwrap();

        etc.put(".cainary-hosts.lock", b"", 0o644);
        assert_eq!(etc.set(), Err(Fail::BadLock));
        etc.put(".cainary-hosts.lock", b"", 0o600);
        fs::hard_link(etc.p(".cainary-hosts.lock"), etc.p("second-link")).unwrap();
        assert_eq!(etc.set(), Err(Fail::BadLock));
        fs::remove_file(etc.p("second-link")).unwrap();
        // A directory in its place is not a lock either.
        fs::remove_file(etc.p(".cainary-hosts.lock")).unwrap();
        fs::create_dir(etc.p(".cainary-hosts.lock")).unwrap();
        assert!(etc.set().is_err());
        fs::remove_dir(etc.p(".cainary-hosts.lock")).unwrap();
        // Nothing was edited, and a good lock file works and is never unlinked.
        assert_eq!(etc.read("hosts"), ORIGINAL);
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert!(etc.exists(".cainary-hosts.lock"));
    }

    #[test]
    fn lock_contention_is_busy_within_the_deadline() {
        let etc = Etc::new();
        etc.put(".cainary-hosts.lock", b"", 0o600);
        let held = openat(etc.fd.as_raw_fd(), LOCK, libc::O_RDWR, 0).unwrap();
        // SAFETY: flock(2) on a descriptor this test owns.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let t = Instant::now();
        assert_eq!(etc.set(), Err(Fail::Busy));
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(etc.read("hosts"), ORIGINAL);
        drop(held);
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn stale_temps_are_cleaned_and_a_foreign_temp_name_is_never_followed() {
        let etc = Etc::new();
        etc.put(".hosts.cainary-new", b"stale", 0o600);
        // A symlink under the temp name: unlinkat removes the link, never its target.
        etc.put("victim", b"keep", 0o600);
        symlink(etc.p("victim"), etc.p(".hosts.cainary-bak-new")).unwrap();
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert_eq!(etc.read("victim"), b"keep");
        no_temps(&etc);
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
    }

    #[test]
    fn crash_after_every_mutation_then_rerun() {
        // A clean run records the steps; each one is then killed in turn.
        let probe = Etc::new();
        seam::set_write_chunk(7);
        seam::set_write_chunk(7);
        probe.put(".hosts.cainary-new", b"stale", 0o600);
        probe.put(".hosts.cainary-bak-new", b"stale", 0o600);
        assert_eq!(probe.set(), Ok(Done::Changed));
        let mut steps = seam::trace();
        steps.dedup();
        for must in [
            Step::LockCreate,
            Step::UnlinkNew,
            Step::UnlinkBakNew,
            Step::BakCreate,
            Step::BakWrite,
            Step::BakPart,
            Step::BakOwner,
            Step::BakAcl,
            Step::BakLabel,
            Step::BakMode,
            Step::BakFsync,
            Step::BakRename,
            Step::BakDirFsync,
            Step::NewCreate,
            Step::NewWrite,
            Step::NewPart,
            Step::NewOwner,
            Step::NewAcl,
            Step::NewLabel,
            Step::NewMode,
            Step::NewFsync,
            Step::PreCommit,
            Step::Commit,
            Step::FinalFsync,
        ] {
            assert!(steps.contains(&must), "{must:?} never reached");
        }
        drop(probe);

        for step in steps {
            let etc = Etc::new();
            seam::set_write_chunk(7);
            etc.put(".hosts.cainary-new", b"stale", 0o600);
            etc.put(".hosts.cainary-bak-new", b"stale", 0o600);
            seam::plan(step, Action::Crash);
            let first = etc.set();
            // A kill at the very end is a success the caller never sees; here it reads as unsynced.
            if step == Step::FinalFsync {
                assert_eq!(first, Ok(Done::ChangedUnsynced), "{step:?}");
            } else {
                assert!(first.is_err(), "{step:?}: {first:?}");
            }
            assert!(seam::crashed(), "{step:?}");
            let committed = matches!(step, Step::Commit | Step::FinalFsync);
            if committed {
                assert_eq!(etc.read("hosts"), expected(), "{step:?}");
            } else {
                assert_eq!(
                    etc.read("hosts"),
                    ORIGINAL,
                    "{step:?}: hosts changed before commit"
                );
            }
            // hosts is never hardlinked and never partial, whatever was left behind.
            assert_eq!(fs::metadata(etc.p("hosts")).unwrap().nlink(), 1, "{step:?}");
            seam::reset();
            let again = etc.set();
            assert_eq!(
                again,
                Ok(if committed {
                    Done::Unchanged
                } else {
                    Done::Changed
                }),
                "{step:?}"
            );
            assert_eq!(etc.read("hosts"), expected(), "{step:?}");
            no_temps(&etc);
            let backup = etc.read("hosts.cainary-backup");
            assert!(
                backup == ORIGINAL || (committed && backup == ORIGINAL),
                "{step:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_failure_before_commit_cleans_up() {
        for step in [
            Step::BakWrite,
            Step::BakRename,
            Step::NewCreate,
            Step::NewWrite,
            Step::NewPart,
            Step::NewOwner,
            Step::NewAcl,
            Step::NewLabel,
            Step::NewFsync,
            Step::PreCommit,
        ] {
            let etc = Etc::new();
            seam::set_write_chunk(7);
            seam::plan(step, Action::Fail);
            assert_eq!(etc.set(), Err(Fail::WriteFailed), "{step:?}");
            assert!(!seam::crashed());
            assert_eq!(etc.read("hosts"), ORIGINAL, "{step:?}");
            no_temps(&etc);
        }
    }

    #[test]
    fn every_syscall_failure_is_refused_before_commit_and_leaves_hosts_alone() {
        use crate::seam::Sys;
        // (call, which occurrence, errno, expected). Occurrence 0 is the backup temp's, 1 the new one's.
        let cases = [
            (Sys::Write, 0, libc::EIO, Fail::WriteFailed),
            (Sys::Write, 1, libc::EIO, Fail::WriteFailed),
            (Sys::Chown, 0, libc::EPERM, Fail::Label),
            (Sys::Chown, 1, libc::EPERM, Fail::Label),
            (Sys::Acl, 0, libc::EIO, Fail::Label),
            (Sys::Acl, 1, libc::EIO, Fail::Label),
            (Sys::Chmod, 0, libc::EPERM, Fail::Label),
            (Sys::Chmod, 1, libc::EPERM, Fail::Label),
            (Sys::FsyncBak, 0, libc::EIO, Fail::WriteFailed),
            (Sys::FsyncNew, 0, libc::EIO, Fail::WriteFailed),
            (Sys::FsyncBakDir, 0, libc::EIO, Fail::WriteFailed),
            (Sys::RenameBak, 0, libc::EIO, Fail::WriteFailed),
            (Sys::RenameBak, 0, libc::EROFS, Fail::ReadOnly),
            (Sys::RenameNew, 0, libc::EIO, Fail::WriteFailed),
            (Sys::RenameNew, 0, libc::EROFS, Fail::ReadOnly),
        ];
        for (call, nth, errno, want) in cases {
            for chunk in [usize::MAX, 5] {
                let etc = Etc::new();
                seam::set_write_chunk(chunk);
                // With 5-byte chunks the nth write is a later piece of the same temp: still a
                // failure of that temp, so the same outcome.
                seam::fail_sys(call, nth, errno);
                assert_eq!(
                    etc.set(),
                    Err(want),
                    "{call:?} #{nth} errno {errno} chunk {chunk}"
                );
                assert!(!seam::crashed());
                assert_eq!(etc.read("hosts"), ORIGINAL, "{call:?} #{nth}");
                no_temps(&etc);
            }
        }
    }

    #[test]
    fn a_failed_label_change_is_refused_when_there_is_a_label_to_set() {
        use crate::seam::Sys;
        let etc = Etc::new();
        seam::fail_sys(Sys::Label, 0, libc::EPERM);
        // Without SELinux there is no label to copy and the call never happens.
        match etc.set() {
            Ok(Done::Changed) => assert_eq!(etc.read("hosts"), expected()),
            Err(Fail::Label) => assert_eq!(etc.read("hosts"), ORIGINAL),
            other => panic!("{other:?}"),
        }
        no_temps(&etc);
    }

    #[test]
    fn partial_writes_still_produce_the_exact_bytes() {
        let etc = Etc::new();
        seam::set_write_chunk(3);
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert_eq!(etc.read("hosts"), expected());
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
        let steps = seam::trace();
        assert!(steps.contains(&Step::BakPart) && steps.contains(&Step::NewPart));
    }

    #[test]
    fn a_big_file_is_refused_without_reading_past_the_limit() {
        let etc = Etc::new();
        let mut big = vec![b'#'; 70_000];
        big.push(b'\n');
        etc.put("hosts", &big, 0o644);
        seam::set_max_read(70_000);
        assert_eq!(etc.set(), Err(Fail::TooLarge));
        seam::set_max_read(70_001);
        assert_eq!(etc.set(), Ok(Done::Changed));
    }

    #[test]
    fn a_failed_directory_fsync_after_commit_is_unsynced_not_an_error() {
        let etc = Etc::new();
        seam::plan(Step::FinalFsync, Action::Fail);
        assert_eq!(etc.set(), Ok(Done::ChangedUnsynced));
        assert_eq!(etc.read("hosts"), expected());
        no_temps(&etc);
    }

    #[test]
    fn a_real_final_fsync_failure_is_unsynced() {
        let etc = Etc::new();
        seam::fail_sys(crate::seam::Sys::FsyncFinal, 0, libc::EIO);
        assert_eq!(etc.set(), Ok(Done::ChangedUnsynced));
        assert_eq!(etc.read("hosts"), expected());
        no_temps(&etc);
    }

    #[test]
    fn a_pre_commit_directory_fsync_failure_leaves_hosts_alone() {
        let etc = Etc::new();
        seam::plan(Step::BakDirFsync, Action::Fail);
        assert_eq!(etc.set(), Err(Fail::WriteFailed));
        assert_eq!(etc.read("hosts"), ORIGINAL);
        // The backup was published and is harmless.
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
    }

    #[test]
    fn an_existing_backup_that_is_a_symlink_is_replaced_not_followed() {
        let etc = Etc::new();
        etc.put("victim", b"keep", 0o600);
        symlink(etc.p("victim"), etc.p("hosts.cainary-backup")).unwrap();
        assert_eq!(etc.set(), Ok(Done::Changed));
        assert_eq!(etc.read("victim"), b"keep");
        assert_eq!(etc.read("hosts.cainary-backup"), ORIGINAL);
        assert!(
            !fs::symlink_metadata(etc.p("hosts.cainary-backup"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn damaged_block_and_reserved_alias_refuse_before_any_write() {
        let etc = Etc::new();
        let damaged = [ORIGINAL, edit::BEGIN.as_bytes(), b"\n"].concat();
        etc.put("hosts", &damaged, 0o644);
        assert_eq!(etc.set(), Err(Fail::DamagedBlock));
        assert_eq!(etc.run(&Op::Clear), Err(Fail::DamagedBlock));
        assert_eq!(etc.read("hosts"), damaged);
        assert!(!etc.exists("hosts.cainary-backup"));
        etc.put("hosts", b"127.0.1.1 otel.example.com myhost\n", 0o644);
        assert_eq!(etc.set(), Err(Fail::ReservedName));
        no_temps(&etc);
    }

    #[test]
    fn the_backup_label_and_acl_plumbing_on_a_synthetic_attribute() {
        let etc = Etc::new();
        let fd = openat(etc.fd.as_raw_fd(), c"hosts", libc::O_RDONLY, 0).unwrap();
        let name = c"user.cainary-test";
        match set_xattr(fd.as_raw_fd(), name, b"value") {
            Err(e) if absent(e) || e == libc::EPERM || e == libc::EACCES => return,
            other => other.unwrap(),
        }
        assert_eq!(get_xattr(fd.as_raw_fd(), name), Ok(Some(b"value".to_vec())));
        remove_xattr(fd.as_raw_fd(), name).unwrap();
        assert_eq!(get_xattr(fd.as_raw_fd(), name), Ok(None));
        remove_xattr(fd.as_raw_fd(), name).unwrap();
    }

    #[test]
    fn a_state_that_cannot_be_reproduced_is_a_label_refusal() {
        let etc = Etc::new();
        let bogus = Some(vec![1u8, 2, 3]);
        let none = None;
        let r = make_temp(
            etc.fd.as_raw_fd(),
            NEW,
            b"x",
            &Spec {
                uid: seam::knobs().uid,
                gid: seam::knobs().gid,
                mode: 0o644,
                acl: &bogus,
                label: &none,
            },
            &NEW_STEPS,
        );
        assert_eq!(r, Err(Fail::Label));
        // A label the source never had can't be absent on a labeled file system either way: the
        // verification compares what is really there.
        let wrong = Some(b"not-a-context\0".to_vec());
        let r = make_temp(
            etc.fd.as_raw_fd(),
            BAK_NEW,
            b"x",
            &Spec {
                uid: seam::knobs().uid,
                gid: seam::knobs().gid,
                mode: 0o600,
                acl: &none,
                label: &wrong,
            },
            &NEW_STEPS,
        );
        // Without SELinux the attribute can't be set; with it the context is invalid. Either way.
        assert_eq!(r, Err(Fail::Label));
    }

    #[test]
    fn walk_refuses_links_and_unprotected_directories() {
        let root = Etc::new();
        let k = seam::knobs();
        let fd = |p: &Path| {
            openat(
                -1,
                &std::ffi::CString::new(p.to_str().unwrap()).unwrap(),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )
            .unwrap()
        };
        fs::create_dir(root.p("etc")).unwrap();
        fs::set_permissions(root.p("etc"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(walk_from(root.fd.as_raw_fd(), &k).is_ok());
        fs::set_permissions(root.p("etc"), fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Unprotected)
        );
        fs::remove_dir(root.p("etc")).unwrap();
        fs::create_dir(root.p("real")).unwrap();
        symlink(root.p("real"), root.p("etc")).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::Symlink)
        );
        fs::remove_file(root.p("etc")).unwrap();
        assert_eq!(
            walk_from(root.fd.as_raw_fd(), &k).err(),
            Some(Fail::NotRegular)
        );
        // A root that anyone can write to is not trusted.
        fs::create_dir(root.p("etc")).unwrap();
        fs::set_permissions(root.p("."), fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            walk_from(fd(&root.path).as_raw_fd(), &k).err(),
            Some(Fail::Unprotected)
        );
    }
}
