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
        "cainary-bind-helper {} protocol 1\n",
        env!("CARGO_PKG_VERSION")
    ))
}

fn state(tree: &Tree, version: impl Fn(&Path) -> Result<String, String>) -> PrivState {
    privport::assess_in(443, false, 1024, &tree.env, version)
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
    match state(&tree, version_ok) {
        PrivState::Ready { helper } => {
            assert_eq!(helper.helper_path(), Path::new(HELPER_PACKAGED));
            assert_eq!(helper.policy_path(), Path::new(POLICY_PACKAGED));
            assert_eq!(helper.recheck(), Ok(()));
            // A policy edited after verification fails the re-walk.
            std::fs::write(tree.path(POLICY_PACKAGED), "<policyconfig/>").unwrap();
            assert!(helper.recheck().is_err());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn states_for_unneeded_and_held_ports() {
    let tree = tree("states");
    assert_eq!(
        privport::assess_in(8080, false, 1024, &tree.env, version_ok),
        PrivState::NotNeeded
    );
    assert_eq!(
        privport::assess_in(80, true, 1024, &tree.env, version_ok),
        PrivState::Held(80)
    );
    assert_eq!(
        privport::assess_in(80, false, 80, &tree.env, version_ok),
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
    let other = |_: &Path| Ok("cainary-bind-helper 0.0.1 protocol 1".to_owned());
    assert!(matches!(
        state(&tree, other),
        PrivState::Mismatch { warn, .. } if warn.contains("0.0.1")
    ));
    let newer = |_: &Path| Ok("cainary-bind-helper 9.9.9 protocol 2".to_owned());
    assert!(no_helper_reason(state(&tree, newer)).contains("Update the helper"));
    let failing = |_: &Path| Err("boom".to_owned());
    assert!(no_helper_reason(state(&tree, failing)).contains("boom"));
    assert!(matches!(
        privport::check_version("garbage", "1"),
        VersionCheck::Blocked(_)
    ));
    assert!(matches!(
        privport::check_version("cainary-bind-helper/1 0.5.2", "0.5.2"),
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

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn real_policy_files_match_their_own_helper_only() {
    use cainary_tray_model::privport::{ACTION_LOCAL, HELPER_LOCAL};
    let packaged = repo_file("packaging/linux/polkit/ua.SkeLLLa.cAInary.policy");
    let local = repo_file("packaging/linux/polkit/ua.SkeLLLa.cAInary.local.policy");
    assert_eq!(
        privport::check_policy_text(&packaged, ACTION_PACKAGED, HELPER_PACKAGED),
        Ok(())
    );
    assert_eq!(
        privport::check_policy_text(&local, ACTION_LOCAL, HELPER_LOCAL),
        Ok(())
    );
    assert!(privport::check_policy_text(&packaged, ACTION_LOCAL, HELPER_LOCAL).is_err());
    assert!(privport::check_policy_text(&local, ACTION_PACKAGED, HELPER_PACKAGED).is_err());
    assert!(privport::check_policy_text(&packaged, ACTION_PACKAGED, HELPER_LOCAL).is_err());
    assert!(privport::check_policy_text(&local, ACTION_LOCAL, HELPER_PACKAGED).is_err());
}

/// The real helper's `--version` line, and the reply builders, as written in its source: if the
/// helper changes them, this fails and the parsers here must follow.
#[test]
fn real_helper_output_formats_still_parse() {
    let source = repo_file("crates/cainary-bind-helper/src/helper.rs");
    assert!(
        source.contains(r#"format!("cainary-bind-helper {VERSION} protocol 1\n")"#),
        "helper --version format changed"
    );
    assert!(source.contains(r#"format!("{PROTOCOL} ok {port} {count} {VERSION}{warn}")"#));
    assert!(source.contains(r#"format!("{PROTOCOL} error {}", fail.token())"#));
    assert!(source.contains(r#"const PROTOCOL: &str = "cainary-bind-helper/1";"#));
    for token in [
        "bad-args",
        "not-pkexec",
        "bad-channel",
        "port-in-use",
        "bind-failed",
        "send-failed",
    ] {
        assert!(source.contains(&format!("\"{token}\"")), "{token}");
        let reply = format!("cainary-bind-helper/1 error {token}");
        assert!(
            matches!(privport::parse_reply(reply.as_bytes()), Ok(Reply::Error(_))),
            "{token}"
        );
    }
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        privport::check_version(
            &format!("cainary-bind-helper {version} protocol 1\n"),
            version
        ),
        VersionCheck::Match
    );
    assert!(
        privport::parse_reply(format!("cainary-bind-helper/1 ok 443 2 {version}").as_bytes())
            .is_ok()
    );
    assert!(
        privport::parse_reply(
            format!("cainary-bind-helper/1 ok 80 1 {version} ipv6-unavailable").as_bytes()
        )
        .is_ok()
    );
}

fn accepts(text: &str) -> bool {
    privport::check_policy_text(text, ACTION_PACKAGED, HELPER_PACKAGED).is_ok()
}

#[test]
fn policy_reader_rejects_hidden_and_misplaced_actions() {
    let good = policy_text(ACTION_PACKAGED, HELPER_PACKAGED);
    assert!(accepts(&good));
    let start = good.find("  <action").unwrap();
    let end = good.find("</action>").unwrap() + "</action>\n".len();
    let action = &good[start..end];
    let without = format!("{}{}", &good[..start], &good[end..]);
    let wrap = |inner: &str| without.replace("</policyconfig>", &format!("{inner}</policyconfig>"));

    // Inside a processing instruction, a comment, CDATA, an attribute value.
    assert!(!accepts(&wrap(&format!("<?audit {action} ?>"))));
    assert!(!accepts(&wrap(&format!("<!-- {action} -->"))));
    assert!(!accepts(&wrap(&format!("<![CDATA[{action}]]>"))));
    assert!(!accepts(&wrap(&format!(
        "<vendor note=\"{}\"/>",
        action.replace('"', "&quot;")
    ))));
    // Nested in another element, or duplicated.
    assert!(!accepts(&wrap(&format!("<vendor>{action}</vendor>"))));
    assert!(!accepts(&good.replace(
        "</policyconfig>",
        &format!("{action}</policyconfig>")
    )));
    // Wrong root, text outside elements, trailing content, a second root.
    assert!(!accepts(&good.replace("policyconfig>", "other>")));
    assert!(!accepts(
        &good.replace("<policyconfig>", "<policyconfig>stray")
    ));
    assert!(!accepts(&format!("{good}<policyconfig/>")));
    assert!(!accepts(&format!("{good}junk")));
    // Entity and DOCTYPE tricks.
    assert!(!accepts(&good.replace(
        "<policyconfig>",
        "<!DOCTYPE x [<!ENTITY e \"no\">]><policyconfig>"
    )));
    assert!(!accepts(&good.replace(
        "<!DOCTYPE policyconfig",
        "<!DOCTYPE policyconfig [<!ENTITY e \"x\">]"
    )));
    assert!(!accepts(&good.replace("<allow_any>no<", "<allow_any>&e;<")));
    assert!(!accepts(
        &good.replace("<allow_any>no<", "<allow_any>&#110;o<")
    ));
    assert!(!accepts(
        &good.replace("<allow_any>no<", "<allow_any>n&amp;o<")
    ));
    assert!(!accepts(
        &good.replace("<?xml version", "<?pi?><?xml version")
    ));
    // Structure inside the action.
    assert!(!accepts(&good.replace(
        "<allow_any>no</allow_any>",
        "<allow_any>no</allow_any><allow_any>no</allow_any>"
    )));
    assert!(!accepts(&good.replace(
        "<allow_any>no</allow_any>",
        "<x><allow_any>no</allow_any></x>"
    )));
    assert!(!accepts(&good.replace(
        "<defaults>",
        "<defaults><allow_active>yes</allow_active>"
    )));
    assert!(!accepts(&good.replace(
        "<annotate",
        "<annotate key=\"org.freedesktop.policykit.exec.path\">/bin/sh</annotate><annotate"
    )));
    assert!(!accepts(
        &good.replace("<policyconfig>", "<policyconfig><action id=\"y\"/>")
    ));
    assert!(!accepts(&good.replace("</action>", "</actio>")));
    assert!(!accepts(
        &good.replace("<action id", "<action id=\"dup\" id")
    ));
}

#[test]
fn policy_reader_accepts_harmless_variations() {
    let good = policy_text(ACTION_PACKAGED, HELPER_PACKAGED);
    // Attribute quoting and whitespace, extra attributes, comments, other elements, no prolog.
    assert!(accepts(&good.replace(
        &format!("<action id=\"{ACTION_PACKAGED}\">"),
        &format!("<action  id = '{ACTION_PACKAGED}'\n   other=\"x\" >")
    )));
    assert!(accepts(&good.replace(
        "key=\"org.freedesktop.policykit.exec.path\"",
        "\n key='org.freedesktop.policykit.exec.path'"
    )));
    assert!(accepts(&good.replace(
        "<allow_any>no</allow_any>",
        "<!-- c --><allow_any> no </allow_any>"
    )));
    assert!(accepts(&good.replace(
        "<description>",
        "<vendor>cAInary &amp; co</vendor><description>"
    )));
    assert!(accepts(
        good.split_once("<policyconfig>")
            .map(|(_, r)| format!("<policyconfig>{r}"))
            .unwrap()
            .as_str()
    ));
    // The two public ids polkit has shipped.
    assert!(accepts(&good.replace("PolicyKit Policy", "polkit Policy")));
    assert!(!accepts(&good.replace("PolicyKit Policy", "Evil Policy")));
}

/// The accepted grammar is a strict subset of XML 1.0: whatever we accept, expat must parse.
fn expat_parses(text: &str) -> Option<bool> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import sys,xml.etree.ElementTree as E; E.fromstring(sys.stdin.buffer.read())",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .ok()?;
    Some(child.wait().ok()?.success())
}

fn good_policy() -> String {
    policy_text(ACTION_PACKAGED, HELPER_PACKAGED)
}

#[test]
fn policy_reader_is_a_strict_subset_of_xml() {
    let good = good_policy();
    let bad: Vec<(&str, String)> = vec![
        (
            "garbage declaration",
            good.replace(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                "<?xml garbage?>",
            ),
        ),
        (
            "standalone",
            good.replace(
                "encoding=\"UTF-8\"",
                "encoding=\"UTF-8\" standalone=\"yes\"",
            ),
        ),
        ("other encoding", good.replace("UTF-8", "ISO-8859-1")),
        (
            "other version",
            good.replace("version=\"1.0\"", "version=\"1.1\""),
        ),
        (
            "mixed quotes",
            good.replace("version=\"1.0\"", "version=\"1.0'"),
        ),
        ("space before declaration", format!(" {good}")),
        ("newline before declaration", format!("\n{good}")),
        (
            "declaration twice",
            good.replacen("<!DOCTYPE", "<?xml version=\"1.0\"?><!DOCTYPE", 1),
        ),
        (
            "bad comment",
            good.replace("<!-- a comment -->", "<!-- bad -- comment -->"),
        ),
        (
            "comment ending ---",
            good.replace("<!-- a comment -->", "<!-- a --->"),
        ),
        ("comment --->", good.replace("<!-- a comment -->", "<!--->")),
        ("BOM", format!("\u{feff}{good}")),
        ("control character", good.replace("Reserve", "Re\u{1}serve")),
        ("U+FFFE", good.replace("Reserve", "Re\u{fffe}serve")),
        ("]]> in text", good.replace("Reserve a", "Reserve ]]> a")),
        (
            "lt in attribute",
            good.replace("<action id=\"", "<action x=\"a<b\" id=\""),
        ),
        ("unquoted attribute", good.replace("id=\"", "x=1 id=\"")),
        (
            "no space between attributes",
            good.replace(
                "<action id=\"ua.SkeLLLa.cAInary.bind-loopback-port\">",
                "<action x=\"1\"id=\"ua.SkeLLLa.cAInary.bind-loopback-port\">",
            ),
        ),
        (
            "name with colon",
            good.replace("<description>", "<a:description>")
                .replace("</description>", "</a:description>"),
        ),
        (
            "name starting with digit",
            good.replace("<description>", "<1d>")
                .replace("</description>", "</1d>"),
        ),
        ("numeric reference", good.replace("Reserve", "Res&#101;rve")),
        ("unknown entity", good.replace("Reserve", "Res&nbsp;erve")),
        ("bare ampersand", good.replace("Reserve", "Res & erve")),
        ("two roots", format!("{good}<policyconfig/>")),
        ("no root", "<?xml version=\"1.0\"?>".to_owned()),
        (
            "PI in prolog",
            good.replace("<policyconfig>", "<?pi x?><policyconfig>"),
        ),
        (
            "self-closing with space",
            good.replace("<allow_any>no</allow_any>", "<allow_any / >"),
        ),
        (
            "DOCTYPE twice",
            good.replace("<policyconfig>", "<!DOCTYPE policyconfig><policyconfig>"),
        ),
    ];
    for (why, text) in &bad {
        assert!(!accepts(text), "accepted: {why}");
    }
}

#[test]
fn policy_reader_accepts_exactly_the_declaration_forms() {
    let good = good_policy();
    let bare = good.replace(" encoding=\"UTF-8\"", "");
    let single = good.replace("\"1.0\" encoding=\"UTF-8\"", "'1.0' encoding='UTF-8'");
    let none = good.split_once("?>\n").unwrap().1.to_owned();
    for (why, text) in [("bare", bare), ("single quotes", single), ("none", none)] {
        assert!(accepts(&text), "rejected: {why}");
    }
}

#[test]
fn everything_accepted_also_parses_in_expat() {
    let good = good_policy();
    let mut samples = vec![
        good.clone(),
        good.replace(" encoding=\"UTF-8\"", ""),
        good.replace("\"1.0\" encoding=\"UTF-8\"", "'1.0' encoding='UTF-8'"),
        good.replace(
            "<allow_any>no</allow_any>",
            "<!-- c --><allow_any> no </allow_any>",
        ),
        good.replace(
            "<description>",
            "<vendor>cAInary &amp; co &lt;3 &quot;x&quot; &apos;y&apos; &gt;</vendor><description>",
        ),
        good.replace("PolicyKit Policy", "polkit Policy"),
        good.replace("<action id", "<action  other='x' id"),
        good.replace("</policyconfig>", "</policyconfig>\n<!-- trailer -->\n"),
    ];
    for name in [
        "ua.SkeLLLa.cAInary.policy",
        "ua.SkeLLLa.cAInary.local.policy",
    ] {
        samples.push(repo_file(&format!("packaging/linux/polkit/{name}")));
    }
    let mut ran = false;
    for (index, text) in samples.iter().enumerate() {
        let ours = if index >= samples.len() - 2 {
            let local = index == samples.len() - 1;
            let (action, helper) = if local {
                (privport::ACTION_LOCAL, privport::HELPER_LOCAL)
            } else {
                (ACTION_PACKAGED, HELPER_PACKAGED)
            };
            privport::check_policy_text(text, action, helper).is_ok()
        } else {
            accepts(text)
        };
        assert!(ours, "sample {index} should be accepted");
        match expat_parses(text) {
            Some(parsed) => {
                ran = true;
                assert!(
                    parsed,
                    "expat rejects a sample we accept (index {index}):\n{text}"
                );
            }
            None => {
                eprintln!("skipping the expat cross-check: no python3");
                return;
            }
        }
    }
    assert!(ran);
}

#[test]
fn nothing_expat_rejects_is_accepted_by_the_reader() {
    // The other direction on the malformed cases: if python3 is there, each is malformed XML too
    // or is rejected for its content, never accepted by us.
    let good = good_policy();
    for text in [
        good.replace("<!-- a comment -->", "<!-- bad -- comment -->"),
        good.replace(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<?xml garbage?>",
        ),
    ] {
        assert!(!accepts(&text));
        if let Some(parsed) = expat_parses(&text) {
            assert!(!parsed, "expat accepts what the test calls malformed");
        }
    }
}
