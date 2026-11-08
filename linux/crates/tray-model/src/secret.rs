//! Rules-key decisions: pure logic over what the secret store returned. No D-Bus and no I/O; the
//! caller (the tray, through tray-dbus) maps the store's answer to [`Stored`], asks [`decide`],
//! and does whatever I/O the [`Decision`] calls for. A stored key that is the wrong length, or
//! that no saved rule carries, is never overwritten; a locked or unavailable store never creates one.

use cainary_sig::{Key, KeyId};
use core::sync::atomic::{Ordering, compiler_fence};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;

fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Secret bytes from the store: zeroed on drop, `Debug` shows only the length.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> SecretBytes {
        SecretBytes(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes(<{} bytes>)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// What the store returned for `rules-key/v1`, mapped by the caller.
#[derive(Debug)]
pub enum Stored {
    Present(SecretBytes),
    Missing,
    Locked,
    Unavailable(String),
}

/// Why saved rules can or cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    Ready {
        id: KeyId,
    },
    Missing,
    Locked,
    Unavailable {
        reason: String,
    },
    /// The stored item is not 32 bytes. Never overwritten automatically.
    Malformed,
    /// The stored key's id differs from the one saved rules were signed with.
    KeyMismatch,
}

impl KeyState {
    /// Short UI text. Every non-ready state is shown as "Saved rules inactive" plus a reason.
    pub fn label(&self) -> &'static str {
        match self {
            KeyState::Ready { .. } => "Saved rules active",
            KeyState::Missing => "Saved rules inactive: rules key not found",
            KeyState::Locked => "Saved rules inactive: keyring locked",
            KeyState::Unavailable { .. } => "Saved rules inactive: keyring unavailable",
            KeyState::Malformed => "Saved rules inactive: stored rules key is damaged",
            KeyState::KeyMismatch => "Saved rules inactive: rules key was replaced",
        }
    }
}

/// What the caller should do next.
#[derive(Debug)]
pub enum Decision {
    /// Sign and verify with this key.
    Use(Key),
    /// Generate a key and store it (the store had none and there are no saved rules).
    Create,
    /// Saved rules stay inactive; never fall back to weaker matching.
    Inactive(KeyState),
}

/// Decide from the store's answer. `saved_rule_key_ids` are the `keyId`s carried by saved rules.
/// `create_requested` is true only for a user action (or first use), never for a bare startup.
pub fn decide(stored: Stored, saved_rule_key_ids: &[KeyId], create_requested: bool) -> Decision {
    match stored {
        Stored::Present(mut bytes) => {
            let Ok(arr) = <[u8; KEY_LEN]>::try_from(bytes.0.as_slice()) else {
                return Decision::Inactive(KeyState::Malformed);
            };
            let key = Key::from_bytes(arr);
            // `arr` is a Copy of the key bytes; `Key` zeroes its own copy, so wipe this one.
            let mut arr = arr;
            wipe(&mut arr);
            wipe(&mut bytes.0);
            let id = key.id();
            if saved_rule_key_ids.is_empty() || saved_rule_key_ids.contains(&id) {
                Decision::Use(key)
            } else {
                Decision::Inactive(KeyState::KeyMismatch)
            }
        }
        Stored::Missing => {
            if create_requested && saved_rule_key_ids.is_empty() {
                Decision::Create
            } else {
                Decision::Inactive(KeyState::Missing)
            }
        }
        Stored::Locked => Decision::Inactive(KeyState::Locked),
        Stored::Unavailable(reason) => Decision::Inactive(KeyState::Unavailable { reason }),
    }
}

/// Whether the UI may offer the explicit reset. Reset is a user action: the caller deletes the
/// saved rules (their hashes can't be migrated), then stores a new key. Offered only when the
/// key is gone, replaced or damaged and rules exist; never for a locked or unavailable store
/// (the key may still be fine) and never automatically.
pub fn reset_allowed(state: &KeyState, has_saved_rules: bool) -> bool {
    has_saved_rules
        && matches!(
            state,
            KeyState::Missing | KeyState::KeyMismatch | KeyState::Malformed
        )
}

/// 32 random bytes from the kernel (`getrandom(2)`, flags 0). No other RNG is used.
pub fn generate_rules_key() -> Result<[u8; KEY_LEN], String> {
    let mut key = [0u8; KEY_LEN];
    let mut filled = 0;
    while filled < KEY_LEN {
        // SAFETY: the pointer and length describe the unfilled tail of `key`.
        let n = unsafe { libc::getrandom(key[filled..].as_mut_ptr().cast(), KEY_LEN - filled, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            wipe(&mut key);
            return Err(format!("getrandom failed: {err}"));
        }
        filled += n as usize;
    }
    Ok(key)
}
