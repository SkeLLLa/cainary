//! The hosts helper's trust walk (shared with the bind helper's), its identity (paths, policy
//! files, action ids, `--version` line) and the states `assess` reports, against a fake tree in
//! which "root" is the test's own uid.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cainary_tray_model::hostsedit::{
    self, ACTION_LOCAL, ACTION_PACKAGED, HELPER_LOCAL, HELPER_PACKAGED, HostsHelperState,
    POLICY_LOCAL, POLICY_PACKAGED, SPEC,
};
use cainary_tray_model::privport::{self, TrustError};
use common::hosts_tree::{Tree, mkdir, policy_text, tree, write};

fn version_ok(_: &Path) -> Result<String, String> {
    Ok(format!(
        "cainary-hosts-helper {} protocol 1\n",
        env!("CARGO_PKG_VERSION")
    ))
}

fn state(tree: &Tree) -> HostsHelperState {
    hostsedit::assess_hosts_in(false, &tree.env, version_ok)
}

fn why(state: HostsHelperState) -> String {
    match state {
        HostsHelperState::NoHelper(why) => why,
        other => panic!("expected NoHelper, got {other:?}"),
    }
}

#[test]
fn ready() {
    let tree = tree("ready");
    match state(&tree) {
        HostsHelperState::Ready { helper } => {
            assert_eq!(helper.helper_path(), Path::new(HELPER_PACKAGED));
            assert_eq!(helper.policy_path(), Path::new(POLICY_PACKAGED));
            helper.recheck().unwrap();
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_identity_is_the_hosts_helpers() {
    assert_eq!(SPEC.candidates[0].helper, HELPER_PACKAGED);
    assert_eq!(SPEC.candidates[1].helper, HELPER_LOCAL);
    assert_eq!(SPEC.candidates[0].policy, POLICY_PACKAGED);
    assert_eq!(SPEC.candidates[1].policy, POLICY_LOCAL);
    assert_eq!(SPEC.candidates[0].action, ACTION_PACKAGED);
    assert_eq!(SPEC.candidates[1].action, ACTION_LOCAL);
    assert!(HELPER_PACKAGED.ends_with("/cainary-hosts-helper"));
    assert!(POLICY_PACKAGED.ends_with(".hosts.policy"));
    assert!(POLICY_LOCAL.ends_with(".hosts.local.policy"));
    // Nothing is shared with the bind helper: not a path, not a policy file, not an action.
    for (bind, hosts) in privport::CANDIDATES.iter().zip(SPEC.candidates) {
        assert_ne!(bind.helper, hosts.helper);
        assert_ne!(bind.policy, hosts.policy);
        assert_ne!(bind.action, hosts.action);
    }
}

#[test]
fn local_install_is_found_when_the_packaged_one_is_missing() {
    let tree = tree("local");
    std::fs::remove_file(tree.path(HELPER_PACKAGED)).unwrap();
    write(&tree.path(HELPER_LOCAL), &tree.root, "#!/bin/sh\n", 0o755);
    write(
        &tree.path(POLICY_LOCAL),
        &tree.root,
        &policy_text(ACTION_LOCAL, HELPER_LOCAL),
        0o644,
    );
    match state(&tree) {
        HostsHelperState::Ready { helper } => {
            assert_eq!(helper.helper_path(), Path::new(HELPER_LOCAL));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn nothing_installed() {
    let tree = tree("none");
    std::fs::remove_file(tree.path(HELPER_PACKAGED)).unwrap();
    assert!(why(state(&tree)).contains("isn't installed"));
}

#[test]
fn the_bind_helpers_policy_does_not_authorise_the_hosts_helper() {
    let tree = tree("wrongpolicy");
    // The hosts policy file holds the bind helper's action and path.
    write(
        &tree.path(POLICY_PACKAGED),
        &tree.root,
        &policy_text(privport::ACTION_PACKAGED, privport::HELPER_PACKAGED),
        0o644,
    );
    assert!(why(state(&tree)).contains("doesn't match"));
}

#[test]
fn a_policy_for_the_wrong_path_or_action_is_refused() {
    let tree = tree("policy");
    for text in [
        policy_text(ACTION_PACKAGED, HELPER_LOCAL),
        policy_text(ACTION_LOCAL, HELPER_PACKAGED),
        policy_text("ua.other.action", HELPER_PACKAGED),
    ] {
        write(&tree.path(POLICY_PACKAGED), &tree.root, &text, 0o644);
        assert!(why(state(&tree)).contains("doesn't match"), "{text}");
    }
}

#[test]
fn missing_policy() {
    let tree = tree("nopolicy");
    std::fs::remove_file(tree.path(POLICY_PACKAGED)).unwrap();
    assert!(why(state(&tree)).contains("policy"));
}

#[test]
fn every_trust_check_still_applies() {
    // Writable by others, writable directory above it, setuid, symlink, non-regular.
    let t = tree("writable");
    std::fs::set_permissions(
        t.path(HELPER_PACKAGED),
        std::fs::Permissions::from_mode(0o757),
    )
    .unwrap();
    assert!(why(state(&t)).contains("writable by group or others"));

    let t = tree("dirwritable");
    let dir = t.path(HELPER_PACKAGED);
    std::fs::set_permissions(
        dir.parent().unwrap(),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert!(why(state(&t)).contains("writable by group or others"));

    let t = tree("setuid");
    std::fs::set_permissions(
        t.path(HELPER_PACKAGED),
        std::fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    assert!(why(state(&t)).contains("setuid"));

    let t = tree("symlink");
    let helper = t.path(HELPER_PACKAGED);
    std::fs::rename(&helper, helper.with_extension("real")).unwrap();
    std::os::unix::fs::symlink(helper.with_extension("real"), &helper).unwrap();
    assert!(why(state(&t)).contains("symlink"));

    let t = tree("dirlink");
    let libexec = t.path("/usr/libexec/cainary");
    let moved = t.path("/usr/libexec/cainary-real");
    std::fs::rename(&libexec, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &libexec).unwrap();
    assert!(why(state(&t)).contains("symlink"));

    let t = tree("notregular");
    let helper = t.path(HELPER_PACKAGED);
    std::fs::remove_file(&helper).unwrap();
    mkdir(&helper, &t.root);
    assert!(why(state(&t)).contains("not a regular file"));

    let t = tree("capability");
    let helper = t.path(HELPER_PACKAGED);
    let name = std::ffi::CString::new(common::hosts_tree::TEST_CAP_XATTR).unwrap();
    let path = std::ffi::CString::new(helper.to_str().unwrap()).unwrap();
    // SAFETY: a user xattr on a file we own, with a 1-byte value.
    let rc = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), b"x".as_ptr().cast(), 1, 0) };
    if rc == 0 {
        assert!(why(state(&t)).contains("file capabilities"));
    } else {
        eprintln!("skipping: no user xattrs on this filesystem");
    }
}

#[test]
fn recheck_catches_a_change_after_verification() {
    let tree = tree("recheck");
    let helper = tree.verified();
    helper.recheck().unwrap();
    std::fs::remove_file(tree.path(POLICY_PACKAGED)).unwrap();
    assert!(helper.recheck().is_err());
    write(
        &tree.path(POLICY_PACKAGED),
        &tree.root,
        &policy_text(ACTION_PACKAGED, HELPER_PACKAGED),
        0o644,
    );
    helper.recheck().unwrap();
    std::fs::set_permissions(
        tree.path(HELPER_PACKAGED),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(helper.recheck().is_err());
    assert!(matches!(
        privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)),
        Err(TrustError::Untrusted(_))
    ));
}

#[test]
fn version_states() {
    let tree = tree("version");
    let ver = env!("CARGO_PKG_VERSION");
    // Another build of the same protocol: usable, with a warning.
    let older = |_: &Path| Ok("cainary-hosts-helper 0.0.1 protocol 1\n".to_owned());
    match hostsedit::assess_hosts_in(false, &tree.env, older) {
        HostsHelperState::Mismatch { warn, .. } => assert!(warn.contains("0.0.1"), "{warn}"),
        other => panic!("{other:?}"),
    }
    // Another protocol: blocked, and the text says what to update.
    let newer = move |_: &Path| Ok(format!("cainary-hosts-helper {ver} protocol 2\n"));
    let blocked = why(hostsedit::assess_hosts_in(false, &tree.env, newer));
    assert!(blocked.contains("Update the hosts helper"), "{blocked}");
    // The bind helper's line is not this helper's.
    let bind = move |_: &Path| Ok(format!("cainary-bind-helper {ver} protocol 1\n"));
    assert!(why(hostsedit::assess_hosts_in(false, &tree.env, bind)).contains("didn't identify"));
    let failing = |_: &Path| Err("no such file".to_owned());
    assert!(why(hostsedit::assess_hosts_in(false, &tree.env, failing)).contains("version"));
}

#[test]
fn sandboxed_wins_over_everything() {
    let tree = tree("sandbox");
    assert_eq!(
        hostsedit::assess_hosts_in(true, &tree.env, version_ok),
        HostsHelperState::Sandboxed
    );
}
