//! Runs the `cainary` binary on the core fixtures. `CAINARY_BLESS=1` rewrites the goldens.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cainary-core/tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cainary"))
        .args(args)
        .env_remove("NO_COLOR")
        .output()
        .expect("cainary runs")
}

fn golden(name: &str, args: &[&str]) {
    golden_on("empty-macos", name, args);
}

fn golden_on(fixture_name: &str, name: &str, args: &[&str]) {
    let mut full = args.to_vec();
    let fx = fixture(fixture_name);
    full.extend(["--fixture", &fx]);
    let out = run(&full);
    assert_eq!(out.status.code(), Some(0), "{args:?}");
    let got = String::from_utf8(out.stdout).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var("CAINARY_BLESS").is_ok_and(|v| v == "1") {
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with CAINARY_BLESS=1", path.display()));
    assert_eq!(want, got, "{name} differs from its golden");
}

#[test]
fn empty_macos_goldens() {
    golden("empty-macos.scan.txt", &["scan"]);
    golden("empty-macos.scan.json", &["scan", "--json"]);
    for format in ["emoji", "text", "nerd", "json"] {
        golden(
            &format!("empty-macos.status-{format}.txt"),
            &["status", "--format", format],
        );
    }
    golden("empty-macos.sources.txt", &["sources"]);
}

#[test]
fn missing_fixture_exits_1() {
    let out = run(&["scan", "--fixture", "/nonexistent/cainary-fixture"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bad_flag_exits_2() {
    let out = run(&["scan", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn os_without_roots_exits_2() {
    let out = run(&["scan", "--os", "linux"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn version_prints() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("cainary ")
    );
}

#[test]
fn summary_and_rich_goldens() {
    golden("empty-macos.scan-summary.txt", &["scan", "--summary"]);
    golden_on(
        "claude-code-org-macos",
        "claude-code-org-macos.scan.txt",
        &["scan"],
    );
    golden_on(
        "claude-code-org-macos",
        "claude-code-org-macos.scan-summary.txt",
        &["scan", "--summary"],
    );
}

// --- `--since` ---

use serde_json::Value;
use std::io::Write;
use std::process::Stdio;

/// `scan --json` on a core fixture, saved as a baseline file in a per-test temp dir.
fn baseline(test: &str, fixture_name: &str) -> String {
    let fx = fixture(fixture_name);
    let out = run(&["scan", "--json", "--fixture", &fx]);
    save(test, &String::from_utf8(out.stdout).unwrap())
}

fn save(test: &str, contents: &str) -> String {
    let dir = std::env::temp_dir().join(format!("cainary-cli-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("baseline.json");
    std::fs::write(&path, contents).unwrap();
    path.to_string_lossy().into_owned()
}

fn scan_json_since(fixture_name: &str, since: &str) -> Value {
    let fx = fixture(fixture_name);
    let out = run(&["scan", "--json", "--fixture", &fx, "--since", since]);
    assert_eq!(out.status.code(), Some(0));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn changes(report: &Value) -> Vec<&Value> {
    report["changes"].as_array().unwrap().iter().collect()
}

fn has(report: &Value, scope: &str, kind: &str) -> bool {
    changes(report)
        .iter()
        .any(|c| c["scope"] == scope && c["kind"] == kind)
}

#[test]
fn managed_hook_added_since_empty() {
    let base = baseline("added", "empty-macos");
    let r = scan_json_since("claude-code-org-macos", &base);
    assert_eq!(r["since"]["scannedAt"], "2026-01-01T00:00:00Z");
    assert!(has(&r, "entry", "raised"));
    assert!(has(&r, "finding", "added"));
    assert!(
        changes(&r)
            .iter()
            .any(|c| c["scope"] == "source" && c["from"] == "absent" && c["to"] == "present")
    );
    assert!(
        changes(&r)
            .iter()
            .any(|c| c["scope"] == "entry" && c["entry"] == "claude" && c["to"] == "high")
    );
    assert!(!has(&r, "finding", "removed"));

    golden_on(
        "claude-code-org-macos",
        "claude-code-org-macos.since-empty.summary.txt",
        &["scan", "--summary", "--since", &base],
    );
}

#[test]
fn unchanged_scan_has_no_changes() {
    let base = baseline("same", "claude-code-org-macos");
    let r = scan_json_since("claude-code-org-macos", &base);
    assert!(changes(&r).is_empty());
    let fx = fixture("claude-code-org-macos");
    let out = run(&["scan", "--summary", "--fixture", &fx, "--since", &base]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("\nNo changes since 2026-01-01 00:00 UTC\n"));
}

#[test]
fn refused_source_does_not_remove_findings() {
    // A baseline in which the helper's path carried a finding that this scan can no longer see.
    let mut r: Value = {
        let fx = fixture("claude-code-helper");
        let out = run(&["scan", "--json", "--fixture", &fx]);
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let mut ghost = r["apps"][0]["findings"][0].clone();
    ghost["key"] = "00000000deadbeef".into();
    ghost["config"]["path"] = "/opt/acme/policy-helper".into();
    r["apps"][0]["findings"].as_array_mut().unwrap().push(ghost);
    let base = save("refused", &r.to_string());

    let r = scan_json_since("claude-code-helper", &base);
    assert!(!has(&r, "finding", "removed"));
    assert!(!has(&r, "entry", "removed"));
}

#[test]
fn bad_baselines_report_an_error_and_exit_0() {
    let fx = fixture("empty-macos");
    for (name, contents, want) in [
        ("notjson", "nope", "not valid JSON"),
        ("schema", "{\"schema\": 2}", "schema 2"),
    ] {
        let path = save(name, contents);
        let r = scan_json_since("empty-macos", &path);
        assert!(
            r["since"]["error"].as_str().unwrap().contains(want),
            "{name}"
        );
        assert!(changes(&r).is_empty());
    }

    let out = run(&[
        "scan",
        "--fixture",
        &fx,
        "--since",
        "/nonexistent/baseline.json",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Can't compare with the baseline: baseline file not found\n"));
}

fn run_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cainary"))
        .args(args)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The child may stop reading at its cap; a closed pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

#[test]
fn since_reads_stdin() {
    let fx = fixture("empty-macos");
    let base = std::fs::read(baseline("stdin", "empty-macos")).unwrap();
    let out = run_stdin(&["scan", "--json", "--fixture", &fx, "--since", "-"], &base);
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["since"]["error"], Value::Null);

    let big = vec![b' '; 1024 * 1024 + 2];
    let out = run_stdin(&["scan", "--json", "--fixture", &fx, "--since", "-"], &big);
    assert_eq!(out.status.code(), Some(0));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(r["since"]["error"].as_str().unwrap().contains("1 MiB"));
}

/// `status` goldens in every format for fixtures covering each state: high, medium, low,
/// incomplete and a badge of 2 or more.
#[test]
fn status_goldens_cover_every_state() {
    for fixture_name in [
        "claude-code-linux",
        "codex-linux",
        "cursor-linux",
        "copilot-linux",
        "device-linux",
        "claude-code-helper",
        "codex-bad-base64",
        "device-macos-managed",
    ] {
        for format in ["emoji", "text", "nerd", "json"] {
            golden_on(
                fixture_name,
                &format!("{fixture_name}.status-{format}.txt"),
                &["status", "--format", format],
            );
        }
    }
}

/// The same state prints the same bytes whichever OS it was scanned on.
#[test]
fn status_matches_for_the_same_state_on_macos_and_linux() {
    let status = |fixture_name: &str, format: &str| {
        let fx = fixture(fixture_name);
        let out = run(&["status", "--format", format, "--fixture", &fx]);
        assert_eq!(out.status.code(), Some(0), "{fixture_name} {format}");
        String::from_utf8(out.stdout).unwrap()
    };
    for (linux, macos) in [
        ("cursor-linux", "cursor-macos-managed"),
        ("codex-linux", "codex-mdm-macos"),
        ("copilot-linux", "copilot-managed-mdm"),
    ] {
        for format in ["emoji", "text", "nerd", "json"] {
            assert_eq!(
                status(linux, format),
                status(macos, format),
                "status --format {format}: {linux} vs {macos}"
            );
        }
    }
}

/// Prompt integrations (starship, tmux, statusline) share one config across macOS and Linux, so
/// `status` must print the same bytes for the same state on both, and `scan --json` must keep the
/// same shape.
#[test]
fn output_is_the_same_on_macos_and_linux() {
    let out = |fixture_name: &str, args: &[&str]| {
        let fx = fixture(fixture_name);
        let mut full = args.to_vec();
        full.extend(["--fixture", &fx]);
        let out = run(&full);
        assert_eq!(out.status.code(), Some(0), "{fixture_name} {args:?}");
        out.stdout
    };
    for format in ["emoji", "text", "nerd", "json"] {
        let args = ["status", "--format", format];
        assert_eq!(
            String::from_utf8(out("empty-macos", &args)).unwrap(),
            String::from_utf8(out("empty-linux", &args)).unwrap(),
            "status --format {format}"
        );
    }
    let mac: Value = serde_json::from_slice(&out("empty-macos", &["scan", "--json"])).unwrap();
    let linux: Value = serde_json::from_slice(&out("empty-linux", &["scan", "--json"])).unwrap();
    assert_eq!(mac["schema"], linux["schema"]);
    assert_eq!(mac["os"], "macos");
    assert_eq!(linux["os"], "linux");
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&mac), keys(&linux), "scan --json top-level keys");
    let ids = |v: &Value| {
        v["apps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&mac), ids(&linux), "scan --json apps");
}
