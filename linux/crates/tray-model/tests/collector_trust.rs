//! One-shot trust commands are exercised with a stub helper, including the preview/confirm gate.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cainary_tray_model::collector::{self, TrustAction, TrustReply};
use cainary_tray_model::runner;

fn stub() -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("cainary-trust-stub-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, line: &str| fs::write(dir.join(name), format!("{line}\n")).unwrap();
    write(
        "status-absent.json",
        r#"{"v":1,"type":"trust-status","claudeCode":{"state":"absent","settingsPath":"/tmp/home/.claude/settings.json","value":null},"codex":{"state":"absent","bundlePath":null,"command":null},"caPath":"/tmp/home/.local/state/cainary/otel-debug-ca.pem","caExists":false,"note":null}"#,
    );
    write(
        "status-applied.json",
        r#"{"v":1,"type":"trust-status","claudeCode":{"state":"applied","settingsPath":"/tmp/home/.claude/settings.json","value":"/tmp/home/ca.pem"},"codex":{"state":"ready","bundlePath":"/tmp/home/codex.pem","command":"env CODEX_CA_CERTIFICATE=/tmp/home/codex.pem codex"},"caPath":"/tmp/home/ca.pem","caExists":true,"note":"An interrupted change was cleared."}"#,
    );
    write(
        "preview.json",
        r#"{"v":1,"type":"trust","target":"claude-code","action":"preview","message":"Would set env.NODE_EXTRA_CA_CERTS after a backup. Close Claude Code before applying this, and restart it afterwards.","settingsPath":"/tmp/home/.claude/settings.json","backupPath":"/tmp/home/settings.json.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/tmp/home/ca.pem","bundlePath":null,"command":null}"#,
    );
    write(
        "applied.json",
        r#"{"v":1,"type":"trust","target":"claude-code","action":"applied","message":"Restart Claude Code afterwards.","settingsPath":"/tmp/home/.claude/settings.json","backupPath":"/tmp/home/settings.json.bak","key":"NODE_EXTRA_CA_CERTS","from":null,"to":"/tmp/home/ca.pem","bundlePath":null,"command":null}"#,
    );
    write(
        "undone.json",
        r#"{"v":1,"type":"trust","target":"claude-code","action":"undone","message":"Restored the previous setting.","settingsPath":"/tmp/home/.claude/settings.json","backupPath":"/tmp/home/settings.json.bak","key":"NODE_EXTRA_CA_CERTS","from":"/tmp/home/ca.pem","to":null,"bundlePath":null,"command":null}"#,
    );
    write(
        "codex-refused.json",
        r#"{"v":1,"type":"trust","target":"codex","action":"refused","message":"Start the takeover once so the collector certificate exists, then try again.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#,
    );
    write(
        "codex-removed.json",
        r#"{"v":1,"type":"trust","target":"codex","action":"nothing-to-undo","message":"No Codex certificate bundle was prepared.","settingsPath":null,"backupPath":null,"key":null,"from":null,"to":null,"bundlePath":null,"command":null}"#,
    );
    let calls = dir.join("calls.txt");
    let script = dir.join("otel-debug-stub");
    let contents = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\ncase \"$*\" in\n  *--trust-status*) if [ -f '{dir}/status-applied.flag' ]; then cat '{dir}/status-applied.json'; else cat '{dir}/status-absent.json'; fi ;;\n  *--dry-run*) cat '{dir}/preview.json' ;;\n  *'--trust claude-code --undo'*) cat '{dir}/undone.json' ;;\n  *'--trust claude-code --json'*) cat '{dir}/applied.json'; touch '{dir}/status-applied.flag' ;;\n  *'--trust codex --undo'*) cat '{dir}/codex-removed.json' ;;\n  *'--trust codex --json'*) cat '{dir}/codex-refused.json'; exit 1 ;;\nesac\n",
        calls = calls.display(),
        dir = dir.display()
    );
    fs::write(&script, contents).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    (script, calls, dir)
}

fn call(program: &Path, action: TrustAction) -> (i32, TrustReply) {
    let args = action.args().iter().map(OsString::from).collect::<Vec<_>>();
    let output = runner::run_one_shot(program, &args).expect("stub process runs within bounds");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        collector::decode_trust_output(&output.stdout).unwrap(),
    )
}

#[test]
fn stub_covers_dialog_preview_confirm_cancel_and_every_trust_action() {
    let (program, calls, dir) = stub();

    let (code, TrustReply::Status(absent)) = call(&program, TrustAction::Status) else {
        panic!("expected trust status");
    };
    assert_eq!(code, 0);
    assert_eq!(absent.claude_code.state, "absent");

    let (code, TrustReply::Trust(preview)) = call(&program, TrustAction::PreviewClaude) else {
        panic!("expected Claude preview");
    };
    assert_eq!(code, 0);
    assert_eq!(preview.action, "preview");
    assert!(preview.backup_path.is_some());
    assert!(
        !fs::read_to_string(&calls)
            .unwrap()
            .contains("--trust claude-code --json")
    );

    // Cancel closes the preview without applying anything; a second preview represents a new
    // dialog. The apply call below represents Confirm and is the first write action.
    let _ = TrustAction::PreviewClaude;
    let (code, TrustReply::Trust(preview)) = call(&program, TrustAction::PreviewClaude) else {
        panic!("expected a second Claude preview");
    };
    assert_eq!(code, 0);
    assert_eq!(preview.action, "preview");
    let (code, TrustReply::Trust(applied)) = call(&program, TrustAction::ApplyClaude) else {
        panic!("expected Claude apply result");
    };
    assert_eq!(code, 0);
    assert_eq!(applied.action, "applied");

    let (code, TrustReply::Status(status)) = call(&program, TrustAction::Status) else {
        panic!("expected updated status");
    };
    assert_eq!(code, 0);
    assert_eq!(status.claude_code.state, "applied");
    assert_eq!(status.codex.state, "ready");
    assert!(status.ca_exists);
    assert_eq!(
        status.note.as_deref(),
        Some("An interrupted change was cleared.")
    );
    assert!(
        status
            .codex
            .command
            .unwrap()
            .contains("CODEX_CA_CERTIFICATE")
    );

    let (code, TrustReply::Trust(undone)) = call(&program, TrustAction::UndoClaude) else {
        panic!("expected Claude undo result");
    };
    assert_eq!(code, 0);
    assert_eq!(undone.action, "undone");

    let (code, TrustReply::Trust(refused)) = call(&program, TrustAction::PrepareCodex) else {
        panic!("expected Codex refusal");
    };
    assert_eq!(code, 1);
    assert_eq!(refused.action, "refused");
    assert!(refused.message.contains("certificate exists"));

    let (code, TrustReply::Trust(removed)) = call(&program, TrustAction::UndoCodex) else {
        panic!("expected Codex remove result");
    };
    assert_eq!(code, 0);
    assert_eq!(removed.action, "nothing-to-undo");

    let calls = fs::read_to_string(&calls).unwrap();
    assert!(calls.contains("--trust-status --json"));
    assert!(calls.contains("--trust claude-code --dry-run --json"));
    assert!(calls.contains("--trust claude-code --undo --json"));
    assert!(calls.contains("--trust codex --json"));
    assert!(calls.contains("--trust codex --undo --json"));
    let _ = fs::remove_dir_all(dir);
}
