//! The privileged-port trust walk, the polkit policy check and the helper's reply grammar,
//! against a fake tree in which "root" is the test's own uid.

use std::ffi::CString;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use cainary_tray_model::privport::{
    self, ACTION_PACKAGED, HELPER_PACKAGED, HelperError, POLICY_PACKAGED, PrivState, Reply,
    ReplyError, TrustEnv, TrustError, VersionCheck,
};

const TEST_CAP_XATTR: &str = "user.cainary-test-cap";

struct Tree {
    root: PathBuf,
    env: TrustEnv,
}

impl Tree {
    fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }
}

fn uid() -> u32 {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() }
}

fn policy_text(action: &str, helper: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<!-- a comment -->
<policyconfig>
  <action id="{action}">
    <description>Reserve a loopback port</description>
    <message>Authentication is required</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{helper}</annotate>
  </action>
</policyconfig>
"#
    )
}

fn mkdir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    let mut dir = path;
    // Fixed modes, whatever the umask.
    loop {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        match dir.parent() {
            Some(parent) if parent.to_string_lossy().contains("privport-") => dir = parent,
            _ => break,
        }
    }
}

fn tree(tag: &str) -> Tree {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let root = base.join(format!("privport-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    mkdir(&root);
    let tree = Tree {
        env: TrustEnv {
            root: root.canonicalize().unwrap(),
            uid: uid(),
            capability_xattr: TEST_CAP_XATTR,
        },
        root: root.canonicalize().unwrap(),
    };
    let helper = tree.path(HELPER_PACKAGED);
    mkdir(helper.parent().unwrap());
    std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let policy = tree.path(POLICY_PACKAGED);
    mkdir(policy.parent().unwrap());
    std::fs::write(&policy, policy_text(ACTION_PACKAGED, HELPER_PACKAGED)).unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
    tree
}

fn version_ok(_: &Path) -> Result<String, String> {
    Ok(format!(
        "cainary-bind-helper/1 {}\n",
        env!("CARGO_PKG_VERSION")
    ))
}

fn state(tree: &Tree, version: impl Fn(&Path) -> Result<String, String>) -> PrivState {
    privport::assess(443, false, 1024, &tree.env, version)
}

fn no_helper_reason(state: PrivState) -> String {
    match state {
        PrivState::NoHelper(why) => why,
        other => panic!("expected NoHelper, got {other:?}"),
    }
}

#[test]
fn trust_ok() {
    let tree = tree("ok");
    assert_eq!(
        privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)),
        Ok(())
    );
    assert_eq!(
        state(&tree, version_ok),
        PrivState::Ready {
            helper: PathBuf::from(HELPER_PACKAGED),
            policy: PathBuf::from(POLICY_PACKAGED),
        }
    );
}

#[test]
fn states_for_unneeded_and_held_ports() {
    let tree = tree("states");
    assert_eq!(
        privport::assess(8080, false, 1024, &tree.env, version_ok),
        PrivState::NotNeeded
    );
    assert_eq!(
        privport::assess(80, true, 1024, &tree.env, version_ok),
        PrivState::Held(80)
    );
    assert_eq!(
        privport::assess(80, false, 80, &tree.env, version_ok),
        PrivState::NotNeeded
    );
    assert!(privport::needs_privilege_with(1023, 1024));
    assert!(!privport::needs_privilege_with(1024, 1024));
}

#[test]
fn no_helper_when_nothing_is_installed() {
    let tree = tree("none");
    std::fs::remove_file(tree.path(HELPER_PACKAGED)).unwrap();
    assert_eq!(
        privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)),
        Err(TrustError::Missing)
    );
    assert!(no_helper_reason(state(&tree, version_ok)).contains("isn't installed"));
}

#[test]
fn rejects_symlink_in_chain() {
    let tree = tree("symlink");
    let libexec = tree.path("/usr/libexec");
    let moved = tree.root.join("elsewhere");
    std::fs::rename(&libexec, &moved).unwrap();
    symlink(&moved, &libexec).unwrap();
    let error = privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(
        matches!(&error, TrustError::Untrusted(why) if why.contains("symlink")),
        "{error:?}"
    );
    assert!(no_helper_reason(state(&tree, version_ok)).contains("symlink"));
}

#[test]
fn rejects_symlink_leaf() {
    let tree = tree("symleaf");
    let helper = tree.path(HELPER_PACKAGED);
    let real = tree.root.join("real-helper");
    std::fs::rename(&helper, &real).unwrap();
    symlink(&real, &helper).unwrap();
    let error = privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(matches!(error, TrustError::Untrusted(_)), "{error:?}");
}

#[test]
fn rejects_group_writable_dir() {
    let tree = tree("gw");
    let dir = tree.path("/usr/libexec/cainary");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    let error = privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(
        matches!(&error, TrustError::Untrusted(why) if why.contains("writable")),
        "{error:?}"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert!(privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).is_err());
}

#[test]
fn rejects_foreign_owner() {
    let tree = tree("owner");
    let mut env = tree.env.clone();
    env.uid = uid().wrapping_add(1);
    let error = privport::check_helper(&env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(
        matches!(&error, TrustError::Untrusted(why) if why.contains("not owned by root")),
        "{error:?}"
    );
}

#[test]
fn rejects_writable_helper_and_setuid() {
    let tree = tree("setuid");
    let helper = tree.path(HELPER_PACKAGED);
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).is_err());
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let error = privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(
        matches!(&error, TrustError::Untrusted(why) if why.contains("setuid")),
        "{error:?}"
    );
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o2755)).unwrap();
    assert!(privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).is_err());
}

#[test]
fn rejects_file_caps() {
    use std::os::unix::ffi::OsStrExt;
    let tree = tree("caps");
    let helper = tree.path(HELPER_PACKAGED);
    let path = CString::new(helper.as_os_str().as_bytes()).unwrap();
    let name = CString::new(TEST_CAP_XATTR).unwrap();
    // SAFETY: valid NUL-terminated strings and a 1-byte value.
    let rc = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), b"x".as_ptr().cast(), 1, 0) };
    if rc != 0 {
        eprintln!(
            "skipping: no user xattrs here ({})",
            std::io::Error::last_os_error()
        );
        return;
    }
    let error = privport::check_helper(&tree.env, Path::new(HELPER_PACKAGED)).unwrap_err();
    assert!(
        matches!(&error, TrustError::Untrusted(why) if why.contains("capabilities")),
        "{error:?}"
    );
}

#[test]
fn rejects_policy_mismatch() {
    let policy_file = |tag: &str, text: String| {
        let tree = tree(tag);
        std::fs::write(tree.path(POLICY_PACKAGED), text).unwrap();
        no_helper_reason(state(&tree, version_ok))
    };
    let good = policy_text(ACTION_PACKAGED, HELPER_PACKAGED);
    for (tag, text) in [
        ("pm-id", good.replace(ACTION_PACKAGED, "ua.other.action")),
        (
            "pm-path",
            good.replace(
                HELPER_PACKAGED,
                "/usr/local/libexec/cainary/cainary-bind-helper",
            ),
        ),
        ("pm-any", good.replace("<allow_any>no<", "<allow_any>yes<")),
        (
            "pm-inactive",
            good.replace("<allow_inactive>no<", "<allow_inactive>auth_admin<"),
        ),
        ("pm-active", good.replace("auth_admin", "auth_admin_keep")),
        (
            "pm-two",
            good.replace(
                "</policyconfig>",
                "<action id=\"x\"><defaults/></action></policyconfig>",
            ),
        ),
        (
            "pm-hidden",
            good.replace("<allow_any>no", "<allow_any>no</allow_any><allow_any>yes"),
        ),
        ("pm-comment", good.replace("<!-- a comment -->", "<!-- ")),
    ] {
        let why = policy_file(tag, text);
        assert!(why.contains("polkit policy"), "{tag}: {why}");
    }
}

#[test]
fn policy_comments_cannot_hide_a_wrong_value() {
    let good = policy_text(ACTION_PACKAGED, HELPER_PACKAGED);
    assert_eq!(
        privport::check_policy_text(&good, ACTION_PACKAGED, HELPER_PACKAGED),
        Ok(())
    );
    let sneaky = good.replace(
        "<allow_active>auth_admin</allow_active>",
        "<allow_active>yes</allow_active><!-- <allow_active>auth_admin</allow_active> -->",
    );
    assert!(privport::check_policy_text(&sneaky, ACTION_PACKAGED, HELPER_PACKAGED).is_err());
}

#[test]
fn rejects_unsafe_policy_file() {
    let tree = tree("policyperm");
    std::fs::set_permissions(
        tree.path(POLICY_PACKAGED),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(no_helper_reason(state(&tree, version_ok)).contains("writable"));
}

#[test]
fn version_mismatch_warns_and_protocol_mismatch_blocks() {
    let tree = tree("version");
    let other = |_: &Path| Ok("cainary-bind-helper/1 0.0.1".to_owned());
    assert!(matches!(
        state(&tree, other),
        PrivState::Mismatch { warn, .. } if warn.contains("0.0.1")
    ));
    let newer = |_: &Path| Ok("cainary-bind-helper/2 9.9.9".to_owned());
    assert!(no_helper_reason(state(&tree, newer)).contains("Update the helper"));
    let failing = |_: &Path| Err("boom".to_owned());
    assert!(no_helper_reason(state(&tree, failing)).contains("boom"));
    assert!(matches!(
        privport::check_version("garbage", "1"),
        VersionCheck::Blocked(_)
    ));
}

#[test]
fn replies_parse_strictly() {
    let ok = |text: &str| privport::parse_reply(text.as_bytes());
    assert_eq!(
        ok("cainary-bind-helper/1 ok 443 2 0.5.2"),
        Ok(Reply::Ok {
            port: 443,
            count: 2,
            version: "0.5.2".into(),
            ipv6_unavailable: false
        })
    );
    assert_eq!(
        ok("cainary-bind-helper/1 ok 443 1 0.5.2 ipv6-unavailable\n"),
        Ok(Reply::Ok {
            port: 443,
            count: 1,
            version: "0.5.2".into(),
            ipv6_unavailable: true
        })
    );
    assert_eq!(
        ok("cainary-bind-helper/1 error port-in-use"),
        Ok(Reply::Error(HelperError::PortInUse))
    );
    for bad in [
        "",
        "hello",
        "cainary-bind-helper/1 ok 443 1 0.5.2",
        "cainary-bind-helper/1 ok 443 2 0.5.2 ipv6-unavailable",
        "cainary-bind-helper/1 ok 0 2 0.5.2",
        "cainary-bind-helper/1 ok 99999 2 0.5.2",
        "cainary-bind-helper/1 ok 443 3 0.5.2",
        "cainary-bind-helper/1 ok 443 2",
        "cainary-bind-helper/1 ok 443 2 0.5.2 extra",
        "cainary-bind-helper/1 error nonsense",
        "cainary-bind-helper/1  ok 443 2 0.5.2",
    ] {
        assert_eq!(ok(bad), Err(ReplyError::Malformed), "{bad:?}");
    }
    assert!(matches!(
        ok("cainary-bind-helper/2 ok 443 2 1"),
        Err(ReplyError::Protocol(_))
    ));
    assert_eq!(
        privport::parse_reply(&[0xff, 0xfe]),
        Err(ReplyError::Malformed)
    );
}
