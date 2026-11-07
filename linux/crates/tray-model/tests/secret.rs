use cainary_sig::{Key, KeyId};
use cainary_tray_model::secret::{
    Decision, KeyState, SecretBytes, Stored, decide, generate_rules_key, reset_allowed,
};

fn present(b: u8, n: usize) -> Stored {
    Stored::Present(SecretBytes::new(vec![b; n]))
}

fn id_of(b: u8) -> KeyId {
    Key::from_bytes([b; 32]).id()
}

#[test]
fn decide_missing_creates_only_without_key_ids() {
    assert!(matches!(
        decide(Stored::Missing, &[], true),
        Decision::Create
    ));
    assert!(matches!(
        decide(Stored::Missing, &[], false),
        Decision::Inactive(KeyState::Missing)
    ));
    assert!(matches!(
        decide(present(1, 32), &[], false),
        Decision::Use(_)
    ));
    assert!(matches!(
        decide(present(1, 32), &[id_of(1)], false),
        Decision::Use(_)
    ));
}

#[test]
fn missing_with_saved_rules_is_inactive() {
    let d = decide(Stored::Missing, &[id_of(1)], true);
    assert!(matches!(d, Decision::Inactive(KeyState::Missing)));
    assert!(reset_allowed(&KeyState::Missing, true));
    assert!(!reset_allowed(&KeyState::Missing, false));
}

#[test]
fn malformed_never_overwritten() {
    for n in [0, 1, 31, 33, 64] {
        for create in [false, true] {
            assert!(matches!(
                decide(present(7, n), &[], create),
                Decision::Inactive(KeyState::Malformed)
            ));
        }
    }
}

#[test]
fn lost_key_needs_reset() {
    let d = decide(present(1, 32), &[id_of(2)], true);
    assert!(matches!(d, Decision::Inactive(KeyState::KeyMismatch)));
    assert!(reset_allowed(&KeyState::KeyMismatch, true));
}

#[test]
fn locked_and_unavailable_never_create() {
    for ids in [vec![], vec![id_of(1)]] {
        assert!(matches!(
            decide(Stored::Locked, &ids, true),
            Decision::Inactive(KeyState::Locked)
        ));
        match decide(Stored::Unavailable("x".into()), &ids, true) {
            Decision::Inactive(KeyState::Unavailable { reason }) => assert_eq!(reason, "x"),
            other => panic!("{other:?}"),
        }
    }
    assert!(!reset_allowed(&KeyState::Locked, true));
    assert!(!reset_allowed(
        &KeyState::Unavailable { reason: "x".into() },
        true
    ));
}

#[test]
fn key_is_32_bytes() {
    let k = generate_rules_key().unwrap();
    assert_eq!(k.len(), 32);
    assert_ne!(k, [0u8; 32]);
}

#[test]
fn generated_keys_differ() {
    assert_ne!(generate_rules_key().unwrap(), generate_rules_key().unwrap());
}

#[test]
fn secret_debug_redacted() {
    let s = present(0xAB, 32);
    let text = format!("{s:?}");
    assert!(!text.contains("171") && !text.contains("ab") && !text.contains("AB"));
    assert!(text.contains("32 bytes"));
    let d = format!("{:?}", decide(present(0xAB, 32), &[], false));
    assert_eq!(d, "Use(Key(<redacted>))");
}
