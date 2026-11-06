//! Dropping `CAP_NET_BIND_SERVICE` after the listeners are bound (design §16.7.5).
//!
//! The collector never runs as root. If it was given the capability (`setcap` on an installed
//! binary), it needs it only for `bind`; this clears every capability set right after, before the
//! first `accept`, and forbids regaining privilege. This file is the only user of `capset`.

#[cfg(target_os = "linux")]
mod imp {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct Data {
        pub effective: u32,
        pub permitted: u32,
        pub inheritable: u32,
    }

    const VERSION_3: u32 = 0x2008_0522;
    pub(super) const NET_BIND_SERVICE: u32 = 10;

    fn get() -> std::io::Result<[Data; 2]> {
        let mut h = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut d = [Data::default(); 2];
        // SAFETY: both pointers refer to live, correctly laid out structs for the whole call.
        let r = unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut Header, d.as_mut_ptr()) };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(d)
    }

    /// Whether the process currently holds the capability to bind low ports.
    pub fn holds_bind_capability() -> bool {
        get().is_ok_and(|d| {
            let bit = 1u32 << NET_BIND_SERVICE;
            d[0].permitted & bit != 0 || d[0].effective & bit != 0 || d[0].inheritable & bit != 0
        })
    }

    fn any(d: &[Data; 2]) -> bool {
        d.iter()
            .any(|x| x.effective | x.permitted | x.inheritable != 0)
    }

    /// The three system calls, so the fail-closed logic can be tested with a fake.
    pub(super) trait Sys {
        fn get(&self) -> std::io::Result<[Data; 2]>;
        fn clear(&self) -> std::io::Result<()>;
        fn no_new_privs(&self) -> std::io::Result<()>;
    }

    struct Real;

    impl Sys for Real {
        fn get(&self) -> std::io::Result<[Data; 2]> {
            get()
        }
        fn clear(&self) -> std::io::Result<()> {
            let mut h = Header {
                version: VERSION_3,
                pid: 0,
            };
            let zero = [Data::default(); 2];
            // SAFETY: both pointers refer to live structs for the whole call.
            let r =
                unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut Header, zero.as_ptr()) };
            if r != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        fn no_new_privs(&self) -> std::io::Result<()> {
            // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integer arguments.
            let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if r != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Fail-closed: a failed query is an error (not "no capabilities"), the clear and the
    /// no_new_privs must both succeed, and a second query must find nothing left.
    pub(super) fn drop_with(sys: &dyn Sys) -> std::io::Result<()> {
        let before = sys.get()?;
        if any(&before) {
            sys.clear()?;
        }
        sys.no_new_privs()?;
        if any(&sys.get()?) {
            return Err(std::io::Error::other("capabilities remain after the drop"));
        }
        Ok(())
    }

    /// Clears every capability set of the calling thread and sets no_new_privs. Succeeds when
    /// there was nothing to drop; any failure to find out, drop or verify is an error.
    pub fn drop_capabilities() -> std::io::Result<()> {
        drop_with(&Real)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn holds_bind_capability() -> bool {
        false
    }
    pub fn drop_capabilities() -> std::io::Result<()> {
        Ok(())
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);

/// How many times the process has completed a verified drop (the server does one after
/// binding in every mode of a build with the `tls` feature).
pub fn completed_drops() -> usize {
    DROPS.load(Ordering::SeqCst)
}

/// Drops and verifies; counted only on success.
pub fn drop_capabilities() -> std::io::Result<()> {
    imp::drop_capabilities()?;
    DROPS.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

pub use imp::holds_bind_capability;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_is_idempotent_and_leaves_nothing() {
        // Run in a thread-less way: no_new_privs and an empty set are harmless for the test
        // process, and the call must succeed whether or not there was anything to drop.
        drop_capabilities().unwrap();
        drop_capabilities().unwrap();
        assert!(!holds_bind_capability());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::imp::{Data, NET_BIND_SERVICE, Sys, drop_with};
    use std::cell::Cell;
    use std::io::{Error, ErrorKind};

    struct Fake {
        caps: Cell<bool>,
        get_fails: bool,
        clear_fails: bool,
        clear_noop: bool,
        nnp_fails: bool,
        cleared: Cell<u32>,
    }

    fn fake() -> Fake {
        Fake {
            caps: Cell::new(true),
            get_fails: false,
            clear_fails: false,
            clear_noop: false,
            nnp_fails: false,
            cleared: Cell::new(0),
        }
    }

    impl Sys for Fake {
        fn get(&self) -> std::io::Result<[Data; 2]> {
            if self.get_fails {
                return Err(Error::from(ErrorKind::PermissionDenied));
            }
            let bit = if self.caps.get() {
                1 << NET_BIND_SERVICE
            } else {
                0
            };
            Ok([
                Data {
                    effective: bit,
                    permitted: bit,
                    inheritable: 0,
                },
                Data::default(),
            ])
        }
        fn clear(&self) -> std::io::Result<()> {
            self.cleared.set(self.cleared.get() + 1);
            if self.clear_fails {
                return Err(Error::from(ErrorKind::PermissionDenied));
            }
            if !self.clear_noop {
                self.caps.set(false);
            }
            Ok(())
        }
        fn no_new_privs(&self) -> std::io::Result<()> {
            if self.nnp_fails {
                Err(Error::from(ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn a_held_capability_is_cleared_and_verified() {
        let f = fake();
        drop_with(&f).unwrap();
        assert_eq!(f.cleared.get(), 1);
        assert!(!f.caps.get());
    }

    #[test]
    fn nothing_to_drop_is_fine_and_clears_nothing() {
        let f = fake();
        f.caps.set(false);
        drop_with(&f).unwrap();
        assert_eq!(f.cleared.get(), 0);
    }

    #[test]
    fn every_failure_is_fail_closed() {
        // capget denied: we can't know, so it is an error, and nothing is assumed dropped.
        let f = Fake {
            get_fails: true,
            ..fake()
        };
        assert!(drop_with(&f).is_err());
        assert_eq!(f.cleared.get(), 0);
        // capset fails.
        assert!(
            drop_with(&Fake {
                clear_fails: true,
                ..fake()
            })
            .is_err()
        );
        // capset "succeeds" but the capability is still there.
        assert!(
            drop_with(&Fake {
                clear_noop: true,
                ..fake()
            })
            .is_err()
        );
        // no_new_privs fails.
        assert!(
            drop_with(&Fake {
                nnp_fails: true,
                ..fake()
            })
            .is_err()
        );
    }
}
