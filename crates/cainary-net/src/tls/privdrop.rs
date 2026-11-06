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
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const VERSION_3: u32 = 0x2008_0522;
    const NET_BIND_SERVICE: u32 = 10;

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

    fn any_capability() -> bool {
        get().is_ok_and(|d| {
            d.iter()
                .any(|x| x.effective | x.permitted | x.inheritable != 0)
        })
    }

    /// Clears every capability set and sets no_new_privs. Succeeds trivially when there is
    /// nothing to drop; fails (so the caller exits) if something is left afterwards.
    pub fn drop_capabilities() -> std::io::Result<()> {
        if any_capability() {
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
        }
        // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integer arguments.
        let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if any_capability() {
            return Err(std::io::Error::other("capabilities remain after the drop"));
        }
        Ok(())
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

pub use imp::{drop_capabilities, holds_bind_capability};

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
