//! Shared test helpers: the macOS stub CLIs, the core's golden reports, and synthetic reports
//! with `since`/`changes`.

#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::{Value, json};

/// The repository root (this crate is `linux/crates/tray-model`).
pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A stub CLI from `macos/Tests/stubs`.
pub fn stub(name: &str) -> PathBuf {
    repo().join("macos/Tests/stubs").join(name)
}

/// A golden report from the core's tests.
pub fn golden(name: &str) -> PathBuf {
    repo().join("crates/cainary-core/tests/golden").join(name)
}

pub fn golden_json(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(golden(name)).unwrap()).unwrap()
}

/// A change record as the core prints it.
pub fn change(id: &str, entry: &str, text: &str) -> Value {
    cainary_tray_model::fixtures::change_record(id, entry, text)
}

/// `name` with `since` and `changes` added, as a `--since` scan prints it.
pub fn with_changes(name: &str, changes: Vec<Value>, since_error: Option<&str>) -> Vec<u8> {
    let mut v = golden_json(name);
    v["since"] = json!({"scannedAt": "2026-01-01T00:00:00Z", "error": since_error});
    v["changes"] = Value::Array(changes);
    serde_json::to_vec(&v).unwrap()
}

/// A fresh, empty directory under the target dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cainary-tray-test-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A CLI that records its pid in `dir/pid`, then sleeps for a minute (ignoring its arguments).
/// Returns the script and the pid file.
pub fn sleeper(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let pid_file = dir.join("pid");
    let script = dir.join("sleeper.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 60\n",
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, pid_file)
}
