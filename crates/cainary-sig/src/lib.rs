//! Pure cryptographic primitives shared by cAInary's collector and tray.

pub mod hmac;
pub mod sha256;

pub use hmac::hmac_sha256;
pub use sha256::{sha256, sha256_hex};
