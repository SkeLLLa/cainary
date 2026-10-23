use cainary_tray_model::fixtures;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn self_test_loads_qml_and_writes_snapshots() {
    let executable = env!("CARGO_BIN_EXE_cainary-tray");
    let snapshots = std::env::var_os("CAINARY_UI_SNAPSHOTS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_TARGET_TMPDIR")).join("ui-snapshots"));
    let mut child = Command::new(executable)
        .arg("--self-test")
        .env("CAINARY_UI_SNAPSHOTS", &snapshots)
        .env("QT_QPA_PLATFORM", "offscreen")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cainary-tray --self-test");
    let started = Instant::now();
    while child.try_wait().expect("poll self-test").is_none() {
        if started.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            panic!("self-test did not exit within 90s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let result = child.wait_with_output().expect("collect self-test output");
    assert!(
        result.status.success(),
        "self-test failed (status {}):\n{}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );

    for scenario in fixtures::scenarios() {
        let path = snapshots.join(format!("{}.png", scenario.name));
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("missing snapshot {}: {error}", path.display()));
        assert!(bytes.len() > 1024, "tiny snapshot: {}", path.display());
        if scenario.name == "popup" {
            // PNG IHDR: width is the big-endian u32 at bytes 16..20.
            let width = u32::from_be_bytes(bytes[16..20].try_into().expect("IHDR width"));
            assert_eq!(width, 360, "popup is 360 px wide");
        }
    }
}
