//! A fake filesystem tree for the hosts helper's trust walk, in which "root" is the test's own
//! uid and the helper is a shell stub.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cainary_tray_model::hostsedit::{
    ACTION_PACKAGED, HELPER_PACKAGED, POLICY_PACKAGED, VerifiedHostsHelper, verify_hosts_in,
};
use cainary_tray_model::privport::TrustEnv;

pub const TEST_CAP_XATTR: &str = "user.cainary-test-cap";

pub struct Tree {
    pub root: PathBuf,
    pub env: TrustEnv,
}

impl Tree {
    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    pub fn verified(&self) -> VerifiedHostsHelper {
        verify_hosts_in(&self.env, cainary_tray_model::hostsedit::SPEC.candidates[0])
            .expect("the fake tree is trusted")
    }
}

pub fn uid() -> u32 {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() }
}

pub fn policy_text(action: &str, helper: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <action id="{action}">
    <description>Edit /etc/hosts</description>
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

pub fn mkdir(path: &Path, top: &Path) {
    std::fs::create_dir_all(path).unwrap();
    // Fixed modes, whatever the umask.
    let mut dir = path;
    while dir.starts_with(top) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
}

pub fn write(path: &Path, top: &Path, content: &str, mode: u32) {
    mkdir(path.parent().unwrap(), top);
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A tree with a trusted packaged hosts helper and its policy.
pub fn tree(tag: &str) -> Tree {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let root = base.join(format!("hostsedit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    mkdir(&root, &root);
    let root = root.canonicalize().unwrap();
    let tree = Tree {
        env: TrustEnv {
            root: root.clone(),
            uid: uid(),
            capability_xattr: TEST_CAP_XATTR,
        },
        root: root.clone(),
    };
    write(&tree.path(HELPER_PACKAGED), &root, "#!/bin/sh\n", 0o755);
    write(
        &tree.path(POLICY_PACKAGED),
        &root,
        &policy_text(ACTION_PACKAGED, HELPER_PACKAGED),
        0o644,
    );
    tree
}
