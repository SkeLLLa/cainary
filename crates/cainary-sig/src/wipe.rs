//! Volatile zeroing for key material.

use core::sync::atomic::{Ordering, compiler_fence};

pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Owns a buffer and zeroes it on every exit path. A `Vec` must not grow after wrapping
/// (a reallocation would leave the old copy behind), so size it up front.
pub(crate) struct Wiped<T: AsMut<[u8]>>(pub T);

impl<T: AsMut<[u8]>> Drop for Wiped<T> {
    fn drop(&mut self) {
        wipe(self.0.as_mut());
    }
}
