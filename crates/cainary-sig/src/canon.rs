//! Canonical encoding v1: a typed, length-prefixed TLV form with sorted map keys.
//!
//! Every item is `tag:u8 ‖ len:u32 big-endian ‖ payload`. Map pairs are sorted by the
//! key's UTF-8 bytes with no Unicode normalization; depth is at most 32 and the total size at most
//! 1 MiB, and exceeding either is an error, never a truncation.

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
    let len = measure(value, 1)?;
    let mut out = Vec::with_capacity(len);
    write(value, &mut out);
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

fn sorted(pairs: &[(String, Value)]) -> Vec<&(String, Value)> {
    let mut refs: Vec<&(String, Value)> = pairs.iter().collect();
    refs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    refs
}

/// First pass: the exact encoded length of `value`, rejecting depth, size and duplicate keys
/// before anything is written. Every sum is checked and capped at `MAX_SIZE`.
fn measure(value: &Value, depth: usize) -> Result<usize, EncodeError> {
    if depth > MAX_DEPTH {
        return Err(EncodeError::TooDeep);
    }
    let payload = match value {
        Value::Absent | Value::Null => 0,
        Value::Bool(_) => 1,
        Value::U64(_) | Value::I64(_) => 8,
        Value::Bytes(b) => b.len(),
        Value::Str(s) => s.len(),
        Value::List(items) => {
            let mut sum = 0usize;
            for v in items {
                sum = add(sum, measure(v, depth + 1)?)?;
            }
            sum
        }
        Value::Map(pairs) => {
            let refs = sorted(pairs);
            if let Some(w) = refs.windows(2).find(|w| w[0].0 == w[1].0) {
                return Err(EncodeError::DuplicateKey(w[0].0.clone()));
            }
            let mut sum = 0usize;
            for (k, v) in refs {
                sum = add(sum, add(HEADER, k.len())?)?;
                sum = add(sum, measure(v, depth + 1)?)?;
            }
            sum
        }
    };
    add(HEADER, payload)
}

const HEADER: usize = 5;

fn add(a: usize, b: usize) -> Result<usize, EncodeError> {
    match a.checked_add(b) {
        Some(n) if n <= MAX_SIZE => Ok(n),
        _ => Err(EncodeError::TooLarge),
    }
}

/// Payload length of an already measured value.
fn payload_len(value: &Value) -> usize {
    match value {
        Value::Absent | Value::Null => 0,
        Value::Bool(_) => 1,
        Value::U64(_) | Value::I64(_) => 8,
        Value::Bytes(b) => b.len(),
        Value::Str(s) => s.len(),
        Value::List(items) => items.iter().map(|v| HEADER + payload_len(v)).sum(),
        Value::Map(pairs) => pairs
            .iter()
            .map(|(k, v)| HEADER + k.len() + HEADER + payload_len(v))
            .sum(),
    }
}

fn head(tag: u8, len: usize, out: &mut Vec<u8>) {
    out.push(tag);
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

/// Second pass: writes into a buffer sized by `measure`; lengths come from the values.
fn write(value: &Value, out: &mut Vec<u8>) {
    let len = payload_len(value);
    match value {
        Value::Absent => head(TAG_ABSENT, len, out),
        Value::Null => head(TAG_NULL, len, out),
        Value::Bool(b) => {
            head(TAG_BOOL, len, out);
            out.push(u8::from(*b));
        }
        Value::U64(n) => {
            head(TAG_U64, len, out);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::I64(n) => {
            head(TAG_I64, len, out);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Bytes(b) => {
            head(TAG_BYTES, len, out);
            out.extend_from_slice(b);
        }
        Value::Str(s) => {
            head(TAG_STR, len, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::List(items) => {
            head(TAG_LIST, len, out);
            for v in items {
                write(v, out);
            }
        }
        Value::Map(pairs) => {
            head(TAG_MAP, len, out);
            for (k, v) in sorted(pairs) {
                head(TAG_STR, k.len(), out);
                out.extend_from_slice(k.as_bytes());
                write(v, out);
            }
        }
    }
}
