//! Fixture → Report JSON == golden (architecture.md §10). `CAINARY_BLESS=1` rewrites goldens.

use cainary_core::harness::Harness;
use cainary_core::model::Level;
use cainary_core::{ScanOptions, scan};
use std::fs;
use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn render(fixture: &std::path::Path) -> String {
    let h = Harness::from_fixture(fixture).expect("fixture loads");
    let report = scan(&h, &ScanOptions::default());
    let mut json = serde_json::to_string_pretty(&report).expect("report serializes");
    json.push('\n');
    json
}

fn diff(want: &str, got: &str) -> String {
    let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
    let mut out = String::new();
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (w.get(i), g.get(i));
        if a != b {
            out.push_str(&format!(
                "line {}:\n  golden: {}\n  actual: {}\n",
                i + 1,
                a.unwrap_or(&"<missing>"),
                b.unwrap_or(&"<missing>")
            ));
        }
    }
    out
}

#[test]
fn fixtures_match_goldens() {
    let bless = std::env::var("CAINARY_BLESS").is_ok_and(|v| v == "1");
    // `CAINARY_GOLDEN=<prefix>` limits the run (and any bless) to fixtures with that prefix.
    let only = std::env::var("CAINARY_GOLDEN").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = fs::read_dir(tests_dir().join("fixtures"))
        .expect("tests/fixtures exists")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .is_some_and(|n| !n.starts_with('.') && n.starts_with(&only))
        })
        .collect();
    dirs.sort();
    let mut failures = String::new();
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let got = render(&dir);
        let golden = tests_dir().join("golden").join(format!("{name}.json"));
        if bless {
            fs::create_dir_all(golden.parent().unwrap()).unwrap();
            fs::write(&golden, &got).unwrap();
            continue;
        }
        match fs::read_to_string(&golden) {
            Ok(want) if want == got => {}
            Ok(want) => failures.push_str(&format!("{name}:\n{}\n", diff(&want, &got))),
            Err(e) => failures.push_str(&format!(
                "{name}: no golden ({e}); run with CAINARY_BLESS=1\n"
            )),
        }
    }
    assert!(failures.is_empty(), "golden mismatch:\n{failures}");
}

#[test]
fn empty_fixtures_have_four_apps_and_no_tools_found() {
    for name in ["empty-macos", "empty-linux"] {
        let h = Harness::from_fixture(&tests_dir().join("fixtures").join(name)).unwrap();
        let r = scan(&h, &ScanOptions::default());
        assert_eq!(r.apps.len(), 4, "{name}");
        assert_eq!(r.status.level, Level::NotInstalled, "{name}");
        // Only the notes-only "This device" entry, which has no findings.
        assert!(
            r.others
                .iter()
                .all(|e| e.id == "device" && e.findings.is_empty()),
            "{name}"
        );
        assert!(r.complete, "{name}");
    }
}

#[test]
fn a_modified_golden_fails() {
    let fixture = tests_dir().join("fixtures/empty-macos");
    let want = fs::read_to_string(tests_dir().join("golden/empty-macos.json")).unwrap();
    let tampered = want.replace("Not installed", "Nothing sent");
    assert_ne!(tampered, render(&fixture));
}
