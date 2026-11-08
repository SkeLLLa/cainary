//! The only place production and test builds differ (guarded: no other `cfg(` in the crate's
//! non-test code, no cargo features). Production values are fixed constants and the hook does
//! nothing. Under `cfg(test)` the trusted owner is the test user, so a temp directory can stand in
//! for `/etc`, and a thread-local plan injects a crash, a failure or a concurrent change after any
//! step of the file procedure.

use std::os::fd::RawFd;
use std::time::Duration;

use crate::helper::Fail;

pub struct Knobs {
    /// The owner `/etc`, `hosts` and the lock file must have; the owner of the backup.
    pub uid: u32,
    pub gid: u32,
    pub lock_deadline: Duration,
    /// More bytes than this read from `hosts` is `too-large`.
    pub max_read: usize,
    /// The most bytes one `write` call is given, so a write can be cut short.
    pub write_chunk: usize,
}

/// A point in the file procedure, named for the mutation that just happened.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    LockCreate,
    UnlinkNew,
    UnlinkBakNew,
    ReadChunk,
    BakCreate,
    BakWrite,
    BakPart,
    BakOwner,
    BakAcl,
    BakLabel,
    BakMode,
    BakFsync,
    BakRename,
    BakDirFsync,
    NewCreate,
    NewWrite,
    NewPart,
    NewOwner,
    NewAcl,
    NewLabel,
    NewMode,
    NewFsync,
    PreCommit,
    Commit,
    FinalFsync,
}

#[cfg(not(test))]
pub fn knobs() -> Knobs {
    Knobs {
        uid: 0,
        gid: 0,
        lock_deadline: Duration::from_secs(5),
        max_read: 16 * 1024 * 1024,
        write_chunk: usize::MAX,
    }
}

/// Called after every mutation, with the descriptor of the directory being edited.
#[cfg(not(test))]
pub fn hook(_step: Step, _etc: RawFd) -> Result<(), Fail> {
    Ok(())
}

/// A system call whose failure a test can inject (the call then returns the errno instead of
/// running). Production never injects.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Sys {
    Write,
    Chown,
    Acl,
    Label,
    Chmod,
    FsyncBak,
    FsyncNew,
    FsyncBakDir,
    FsyncFinal,
    RenameBak,
    RenameNew,
}

#[cfg(not(test))]
pub fn sys(_call: Sys) -> Option<i32> {
    None
}

/// Whether the injected failure was a simulated kill (no cleanup runs, as after SIGKILL).
#[cfg(not(test))]
pub fn crashed() -> bool {
    false
}

#[cfg(test)]
pub enum Action {
    /// Stop here without cleaning up.
    Crash,
    /// Fail the step as an ordinary error.
    Fail,
    /// Change something in the directory, then carry on.
    Run(Box<dyn FnOnce(RawFd)>),
}

#[cfg(test)]
thread_local! {
    static PLAN: std::cell::RefCell<Option<(Step, Action)>> = const { std::cell::RefCell::new(None) };
    static TRACE: std::cell::RefCell<Vec<Step>> = const { std::cell::RefCell::new(Vec::new()) };
    static CRASHED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SYS: std::cell::RefCell<Option<(Sys, usize, i32)>> = const { std::cell::RefCell::new(None) };
    static WRITE_CHUNK: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    static MAX_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(1 << 20) };
}

#[cfg(test)]
pub fn knobs() -> Knobs {
    // SAFETY: geteuid(2) and getegid(2) cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Knobs {
        uid,
        gid,
        lock_deadline: Duration::from_millis(400),
        max_read: MAX_READ.with(|m| m.get()),
        write_chunk: WRITE_CHUNK.with(|m| m.get()),
    }
}

#[cfg(test)]
pub fn hook(step: Step, etc: RawFd) -> Result<(), Fail> {
    TRACE.with(|t| t.borrow_mut().push(step));
    let due = PLAN.with(|p| {
        let mut p = p.borrow_mut();
        match p.as_ref() {
            Some((s, _)) if *s == step => p.take().map(|(_, a)| a),
            _ => None,
        }
    });
    match due {
        None => Ok(()),
        Some(Action::Crash) => {
            CRASHED.with(|c| c.set(true));
            Err(Fail::WriteFailed)
        }
        Some(Action::Fail) => Err(Fail::WriteFailed),
        Some(Action::Run(f)) => {
            f(etc);
            Ok(())
        }
    }
}

#[cfg(test)]
pub fn sys(call: Sys) -> Option<i32> {
    SYS.with(|p| {
        let mut p = p.borrow_mut();
        match p.as_mut() {
            Some((c, nth, errno)) if *c == call => {
                if *nth == 0 {
                    let e = *errno;
                    *p = None;
                    Some(e)
                } else {
                    *nth -= 1;
                    None
                }
            }
            _ => None,
        }
    })
}

/// Fails the `nth` (0-based) next call of `call` with `errno`.
#[cfg(test)]
pub fn fail_sys(call: Sys, nth: usize, errno: i32) {
    SYS.with(|p| *p.borrow_mut() = Some((call, nth, errno)));
}

#[cfg(test)]
pub fn set_write_chunk(n: usize) {
    WRITE_CHUNK.with(|m| m.set(n));
}

#[cfg(test)]
pub fn crashed() -> bool {
    CRASHED.with(|c| c.get())
}

/// Forgets the plan, the trace and the crash flag, and restores the read limit.
#[cfg(test)]
pub fn reset() {
    PLAN.with(|p| *p.borrow_mut() = None);
    TRACE.with(|t| t.borrow_mut().clear());
    CRASHED.with(|c| c.set(false));
    MAX_READ.with(|m| m.set(1 << 20));
    SYS.with(|p| *p.borrow_mut() = None);
    WRITE_CHUNK.with(|m| m.set(usize::MAX));
}

#[cfg(test)]
pub fn plan(step: Step, action: Action) {
    PLAN.with(|p| *p.borrow_mut() = Some((step, action)));
}

#[cfg(test)]
pub fn trace() -> Vec<Step> {
    TRACE.with(|t| t.borrow().clone())
}

#[cfg(test)]
pub fn set_max_read(n: usize) {
    MAX_READ.with(|m| m.set(n));
}
