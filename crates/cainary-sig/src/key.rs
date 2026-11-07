//! The rules key, signing, and digests.

use crate::canon::{EncodeError, Value, encode};
use crate::domain::{self, Domain};
use crate::hmac::hmac_sha256;
use crate::wipe::wipe;

/// `List[Str "cainary-sig", U64 1, Str domain, Map fields]`, encoded.
pub fn message(domain: Domain, fields: Vec<(String, Value)>) -> Result<Vec<u8>, EncodeError> {
    encode(&Value::List(vec![
        Value::Str("cainary-sig".to_string()),
        Value::U64(1),
        Value::Str(domain.as_str().to_string()),
        Value::Map(fields),
    ]))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 15)] as char);
    }
    s
}

/// A 256-bit rules key. Not `Clone`/`Copy`; zeroed on drop; `Debug` is redacted.
pub struct Key([u8; 32]);

impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Key {
        Key(bytes)
    }

    pub fn id(&self) -> KeyId {
        let msg = message(domain::KEY_ID, Vec::new()).expect("empty message encodes");
        let mac = hmac_sha256(&self.0, &msg);
        KeyId(to_hex(&mac)[..16].to_string())
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// First 16 lowercase hex characters of a key-derived MAC; safe to display and store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(String);

impl KeyId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `HMAC-SHA256(K, message(domain, fields))`.
pub fn sign(
    key: &Key,
    domain: Domain,
    fields: Vec<(String, Value)>,
) -> Result<Digest, EncodeError> {
    Ok(Digest(hmac_sha256(&key.0, &message(domain, fields)?)))
}

/// A 256-bit MAC. Deliberately not `PartialEq`: compare with [`Digest::ct_eq`].
#[derive(Clone, Copy)]
pub struct Digest([u8; 32]);

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl Digest {
    /// 64 lowercase hex characters.
    pub fn hex(&self) -> String {
        to_hex(&self.0)
    }

    /// First 8 hex characters, for display only.
    pub fn short(&self) -> String {
        to_hex(&self.0[..4])
    }

    pub fn from_hex(s: &str) -> Option<Digest> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, pair) in b.chunks(2).enumerate() {
            out[i] = nib(pair[0])? << 4 | nib(pair[1])?;
        }
        Some(Digest(out))
    }

    /// Constant-time comparison: folds over every byte, no early return.
    pub fn ct_eq(&self, other: &Digest) -> bool {
        let mut acc = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }
}
