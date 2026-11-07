use cainary_sig::domain::{self, Domain};
use cainary_sig::{Digest, EncodeError, Key, Value, encode, sign};

fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

fn pair(k: &str, v: Value) -> (String, Value) {
    (k.to_string(), v)
}

#[test]
fn map_keys_sorted_bytewise() {
    // "Z" (5a) < "a" (61) < "é" (c3 a9) < "中" (e4 b8 ad)
    let a = encode(&Value::Map(vec![
        pair("中", Value::Null),
        pair("a", Value::Null),
        pair("é", Value::Null),
        pair("Z", Value::Null),
    ]))
    .unwrap();
    let b = encode(&Value::Map(vec![
        pair("Z", Value::Null),
        pair("a", Value::Null),
        pair("é", Value::Null),
        pair("中", Value::Null),
    ]))
    .unwrap();
    assert_eq!(a, b);
    let z = a
        .windows(6)
        .position(|w| w == [6, 0, 0, 0, 1, b'Z'])
        .unwrap();
    let lo = a
        .windows(6)
        .position(|w| w == [6, 0, 0, 0, 1, b'a'])
        .unwrap();
    assert!(z < lo);
}

#[test]
fn duplicate_key_rejected() {
    let v = Value::Map(vec![pair("k", Value::Null), pair("k", Value::U64(1))]);
    assert_eq!(encode(&v), Err(EncodeError::DuplicateKey("k".to_string())));
}

#[test]
fn depth_limit() {
    let nest = |n: usize| {
        let mut v = Value::Null;
        for _ in 1..n {
            v = Value::List(vec![v]);
        }
        v
    };
    assert!(encode(&nest(32)).is_ok());
    assert_eq!(encode(&nest(33)), Err(EncodeError::TooDeep));
}

#[test]
fn size_limit() {
    // 1 MiB of payload plus the 5-byte header exceeds the limit.
    assert_eq!(
        encode(&Value::Bytes(vec![0; 1 << 20])),
        Err(EncodeError::TooLarge)
    );
    assert!(encode(&Value::Bytes(vec![0; (1 << 20) - 5])).is_ok());
    // Many small items add up too.
    let many = Value::List((0..(1 << 17)).map(|_| Value::U64(0)).collect());
    assert_eq!(encode(&many), Err(EncodeError::TooLarge));
}

#[test]
fn absent_null_distinct() {
    assert_eq!(encode(&Value::Absent).unwrap(), [0, 0, 0, 0, 0]);
    assert_eq!(encode(&Value::Null).unwrap(), [1, 0, 0, 0, 0]);
    assert_ne!(
        encode(&Value::List(vec![Value::Absent])).unwrap(),
        encode(&Value::List(vec![Value::Null])).unwrap()
    );
}

#[test]
fn key_id_stable() {
    let k = || Key::from_bytes([7; 32]);
    assert_eq!(k().id(), k().id());
    assert_eq!(k().id().as_str().len(), 16);
    assert!(
        k().id()
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_ne!(k().id(), Key::from_bytes([8; 32]).id());
}

#[test]
fn key_debug_redacted() {
    let k = Key::from_bytes([0xab; 32]);
    let shown = format!("{k:?} {k:#?}");
    assert!(shown.contains("redacted"));
    assert!(!shown.contains("ab") && !shown.contains("171"));
}

#[test]
fn digest_hex_roundtrip() {
    let k = Key::from_bytes([1; 32]);
    let d = sign(&k, domain::NOTIFY_DEDUP, vec![pair("x", s("y"))]).unwrap();
    assert_eq!(d.hex().len(), 64);
    assert_eq!(d.short(), d.hex()[..8]);
    assert_eq!(Digest::from_hex(&d.hex()), Some(d));
    assert_eq!(Digest::from_hex(&d.hex().to_uppercase()), Some(d));
    assert_eq!(Digest::from_hex("zz"), None);
    assert_eq!(Digest::from_hex(&"g".repeat(64)), None);
    assert_eq!(Digest::from_hex(&d.hex()[..62]), None);
}

#[test]
fn ct_eq_works() {
    let k = Key::from_bytes([1; 32]);
    let a = sign(&k, domain::KNOWN_FINDING, vec![pair("x", s("1"))]).unwrap();
    let b = sign(&k, domain::KNOWN_FINDING, vec![pair("x", s("2"))]).unwrap();
    let c = sign(&k, domain::ALERT_PATTERN, vec![pair("x", s("1"))]).unwrap();
    assert!(a.ct_eq(&a));
    assert!(!a.ct_eq(&b));
    assert!(!a.ct_eq(&c), "domains separate digests");
    let mut last = a;
    last.0[31] ^= 1;
    assert!(!a.ct_eq(&last));
    assert_eq!(Domain::from_name("key-id/v1"), Some(domain::KEY_ID));
    assert_eq!(Domain::from_name("nope"), None);
}
