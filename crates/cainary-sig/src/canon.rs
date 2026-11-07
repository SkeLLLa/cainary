//! Canonical encoding v1: a typed, length-prefixed TLV form with sorted map keys.
//!
//! Every item is `tag:u8 ‖ len:u32 big-endian ‖ payload`. See `docs/design/signatures.md`.

const TAG_ABSENT: u8 = 0x00;
const TAG_NULL: u8 = 0x01;
const TAG_BOOL: u8 = 0x02;
const TAG_U64: u8 = 0x03;
const TAG_I64: u8 = 0x04;
const TAG_BYTES: u8 = 0x05;
const TAG_STR: u8 = 0x06;
const TAG_LIST: u8 = 0x07;
const TAG_MAP: u8 = 0x08;

/// Maximum nesting depth; a scalar at the top level has depth 1.
pub const MAX_DEPTH: usize = 32;
/// Maximum total encoded size in bytes.
pub const MAX_SIZE: usize = 1 << 20;

/// A typed value. There are no floats on purpose.
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    Absent,
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    Bytes(Vec<u8>),
    Str(String),
    List(Vec<Value>),
    /// Pairs in any order; the encoder sorts them by key bytes.
    Map(Vec<(String, Value)>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    DuplicateKey(String),
    TooDeep,
    TooLarge,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateKey(k) => write!(f, "duplicate map key {k:?}"),
            Self::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
            Self::TooLarge => write!(f, "encoding larger than {MAX_SIZE} bytes"),
        }
    }
}

impl std::error::Error for EncodeError {}

pub fn encode(value: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    item(value, 1, &mut out)?;
    Ok(out)
}

fn put(tag: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if payload.len() > MAX_SIZE || out.len() + 5 + payload.len() > MAX_SIZE {
        return Err(EncodeError::TooLarge);
    }
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

fn item(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if depth > MAX_DEPTH {
        return Err(EncodeError::TooDeep);
    }
    match value {
        Value::Absent => put(TAG_ABSENT, &[], out),
        Value::Null => put(TAG_NULL, &[], out),
        Value::Bool(b) => put(TAG_BOOL, &[u8::from(*b)], out),
        Value::U64(n) => put(TAG_U64, &n.to_be_bytes(), out),
        Value::I64(n) => put(TAG_I64, &n.to_be_bytes(), out),
        Value::Bytes(b) => put(TAG_BYTES, b, out),
        Value::Str(s) => put(TAG_STR, s.as_bytes(), out),
        Value::List(items) => {
            let mut payload = Vec::new();
            for v in items {
                item(v, depth + 1, &mut payload)?;
            }
            put(TAG_LIST, &payload, out)
        }
        Value::Map(pairs) => {
            let mut sorted: Vec<&(String, Value)> = pairs.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            if let Some(w) = sorted.windows(2).find(|w| w[0].0 == w[1].0) {
                return Err(EncodeError::DuplicateKey(w[0].0.clone()));
            }
            let mut payload = Vec::new();
            for (k, v) in sorted {
                put(TAG_STR, k.as_bytes(), &mut payload)?;
                item(v, depth + 1, &mut payload)?;
            }
            put(TAG_MAP, &payload, out)
        }
    }
}
