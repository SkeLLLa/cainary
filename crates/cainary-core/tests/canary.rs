//! Canary guard (architecture.md §10, guard 5): plant a marker in credential files, point tool
//! configs at them through symlinks, scan every tool, and check the marker never reaches the
//! report. The fixture is built in a temp dir, so no credential-shaped file is committed.

use cainary_core::harness::Harness;
use cainary_core::model::SourceState;
use cainary_core::{ScanOptions, scan};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const CANARY: &str = "CANARY-7f3a9c2e";

/// Credential locations from the deny-list, relative to the fixture home.
const CREDENTIALS: &[&str] = &[
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    ".claude.json",
    ".claude/.claude.json",
    ".claude/history.jsonl",
    ".codex/auth.json",
    ".codex/history.jsonl",
    ".copilot/config.json",
    ".config/gh/hosts.yml",
    ".config/github-copilot/hosts.json",
];

/// Config paths the scanners do read, each a symlink into a credential location.
const LINKS: &[(&str, &str)] = &[
    (".claude/settings.json", ".ssh/id_ed25519"),
    (".codex/config.toml", ".codex/auth.json"),
    (".copilot/settings.json", ".aws/credentials"),
    (".cursor/hooks.json", ".netrc"),
    (
        "Library/Application Support/Claude/claude_desktop_config.json",
        ".claude.json",
    ),
];

fn fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cainary-canary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let home = dir.join("home");
    fs::create_dir_all(dir.join("root")).unwrap();
    for rel in CREDENTIALS {
        write(&home.join(rel), &format!("{{\"token\": \"{CANARY}\"}}\n"));
    }
    for (link, target) in LINKS {
        let link = home.join(link);
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(home.join(target), &link).unwrap();
    }
    fs::write(dir.join("fixture.json"), "{\"os\": \"macos\"}\n").unwrap();
    dir
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn guard5_credentials_never_reach_the_report() {
    let dir = fixture();
    let h = Harness::from_fixture(&dir).expect("fixture loads");
    let report = scan(&h, &ScanOptions::default());
    let json = serde_json::to_string(&report).unwrap();
    let _ = fs::remove_dir_all(&dir);

    assert!(!json.contains(CANARY), "canary leaked into the report");
    for (link, _) in LINKS {
        let shown = format!("~/{link}");
        let src = report.sources.iter().find(|s| s.source.path == shown);
        assert!(
            src.is_some_and(|s| s.state == SourceState::Refused),
            "{shown} should be refused, got {:?}",
            src.map(|s| s.state)
        );
    }
    assert!(
        !report.complete,
        "a refused source makes the scan incomplete"
    );
}
