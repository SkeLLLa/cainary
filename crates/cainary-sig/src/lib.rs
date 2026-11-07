//! Pure cryptographic primitives shared by cAInary's collector and tray.

pub mod canon;
pub mod domain;
pub mod hmac;
pub mod key;
pub mod sha256;
mod wipe;

pub use canon::{EncodeError, Value, encode};
pub use domain::Domain;
pub use hmac::hmac_sha256;
pub use key::{Digest, Key, KeyId, message, sign};
pub use sha256::{sha256, sha256_hex};
