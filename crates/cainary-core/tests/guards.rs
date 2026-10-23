//! Source-level safety guards (architecture.md §10, guards 1–4).
//!
//! These are regression checks over marker strings, not proofs. Each file is cut at its first
//! `#[cfg(test)] mod` (the guarded files keep their test modules last), and whole-line `//`
//! comments are dropped, so prose that mentions `std::fs` doesn't trip a guard.

use std::fs;
use std::path::{Path, PathBuf};

/// A source file: its path relative to `crates/` (`cainary-core/src/harness/fs.rs`) and its
/// non-test, non-comment text.
struct Src {
    rel: String,
    code: String,
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is the parent of the crate dir")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Text before the first `#[cfg(test)] mod …`, without whole-line `//` comments. A
/// `#[cfg(test)]` on a single item (a test-only counter, say) doesn't end the production code.
fn production_code(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let next = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty() && !l.starts_with("#["));
            if next.is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod ")) {
                break;
            }
        }
        if !line.trim_start().starts_with("//") {
            out.push(*line);
        }
    }
    out.join("\n")
}

/// Every `crates/*/src/**/*.rs`.
fn sources() -> Vec<Src> {
    let crates = crates_dir();
    let mut crate_dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .expect("read crates/")
        .map(|e| e.expect("crate entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    crate_dirs.sort();
    assert!(
        !crate_dirs.is_empty(),
        "no crates found under {}",
        crates.display()
    );
    let mut files = Vec::new();
    for c in crate_dirs {
        collect(&c.join("src"), &mut files);
    }
    files
        .iter()
        .map(|p| Src {
            rel: p
                .strip_prefix(&crates)
                .expect("under crates/")
                .to_string_lossy()
                .replace('\\', "/"),
            code: production_code(&fs::read_to_string(p).expect("read source")),
        })
        .collect()
}

const FS_RS: &str = "cainary-core/src/harness/fs.rs";
const PLATFORM_RS: &str = "cainary-core/src/harness/platform.rs";
const CLI_MAIN: &str = "cainary-cli/src/main.rs";

fn in_harness(rel: &str) -> bool {
    rel.starts_with("cainary-core/src/harness/")
}

/// Collapses whitespace runs and the space around `::`, so `std :: fs` and wrapped paths match.
fn squash(code: &str) -> String {
    code.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" ::", "::")
        .replace(":: ", "::")
}

/// The std modules a file reaches for: `std::fs`, `std::{io, fs}` and so on. Group imports
/// are checked one level deep, which is how this codebase writes them.
fn banned_std_modules(code: &str) -> Vec<String> {
    const BANNED: [&str; 4] = ["fs", "process", "net", "env"];
    let code = &squash(code);
    let mut hits = Vec::new();
    for m in BANNED {
        let needle = format!("std::{m}");
        let used = code.match_indices(&needle).any(|(i, _)| {
            let next = code[i + needle.len()..].chars().next();
            !next.is_some_and(|c| c.is_alphanumeric() || c == '_')
        });
        if used {
            hits.push(needle);
        }
    }
    let mut rest = code.as_str();
    while let Some(i) = rest.find("std::{") {
        let group = &rest[i + "std::{".len()..];
        let end = group.find('}').unwrap_or(group.len());
        for item in group[..end].split(',') {
            let head = item
                .split(|c: char| c == ':' || c.is_whitespace())
                .find(|t| !t.is_empty())
                .unwrap_or("");
            if BANNED.contains(&head) {
                hits.push(format!("std::{{{head}}}"));
            }
        }
        rest = &group[end..];
    }
    hits
}

fn check_guard1(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs {
        if in_harness(&s.rel) || s.rel == CLI_MAIN {
            continue;
        }
        for hit in banned_std_modules(&s.code) {
            bad.push(format!("{}: {hit} outside harness/", s.rel));
        }
    }
    bad
}

const WRITE_SHAPED: [&str; 10] = [
    ".write(",
    "::create(",
    ".append(true",
    ".append(false",
    ".truncate(true",
    ".truncate(false",
    "::write(",
    "::create_new(",
    "create_dir",
    "remove_",
];

fn check_guard2(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs {
        let code = squash(&s.code);
        if s.rel != FS_RS && s.code.contains("OpenOptions") {
            bad.push(format!("{}: OpenOptions outside harness/fs.rs", s.rel));
        }
        for m in WRITE_SHAPED {
            if code.contains(m) {
                bad.push(format!("{}: write-shaped call `{m}`", s.rel));
            }
        }
    }
    bad
}

fn check_guard3(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    let mut spawns = Vec::new();
    for s in srcs {
        let code = squash(&s.code);
        if code.contains("Command as") {
            bad.push(format!("{}: Command imported under an alias", s.rel));
        }
        let lines: Vec<String> = s.code.lines().map(squash).collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("Command::new") {
                // The program path may sit on the next line after rustfmt wraps the call.
                let near = lines[i..(i + 3).min(lines.len())].join(" ");
                spawns.push((s.rel.clone(), near.contains("/usr/sbin/scutil")));
            }
        }
        if s.rel != FS_RS && s.code.contains("libc::") {
            bad.push(format!("{}: libc:: outside harness/fs.rs", s.rel));
        }
    }
    match spawns.as_slice() {
        [(rel, true)] if rel == PLATFORM_RS => {}
        other => bad.push(format!(
            "Command::new must appear exactly once, for /usr/sbin/scutil in harness/platform.rs; found {other:?}"
        )),
    }
    bad
}

/// Every package `Cargo.lock` may contain: the two workspace crates and the current
/// transitive closure of `serde`, `serde_json`, `toml`, `plist` and `libc`. Adding a crate is
/// a visible, reviewed change to this list.
const ALLOWED_PACKAGES: &[&str] = &[
    "base64",
    "cainary",
    "cainary-core",
    "deranged",
    "equivalent",
    "foldhash",
    "hashbrown",
    "indexmap",
    "itoa",
    "libc",
    "memchr",
    "num-conv",
    "plist",
    "powerfmt",
    "proc-macro2",
    "quick-xml",
    "quote",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "serde_spanned",
    "syn",
    "time",
    "time-core",
    "time-macros",
    "toml",
    "toml_datetime",
    "toml_parser",
    "toml_writer",
    "unicode-ident",
    "winnow",
    "zmij",
];

fn lock_packages(lock: &str) -> Vec<String> {
    let v: toml::Value = toml::from_str(lock).expect("Cargo.lock parses as TOML");
    v.get("package")
        .and_then(|p| p.as_array())
        .expect("Cargo.lock has [[package]] entries")
        .iter()
        .map(|p| {
            p.get("name")
                .and_then(|n| n.as_str())
                .expect("package has a name")
                .to_string()
        })
        .collect()
}

fn check_guard4(lock: &str) -> Vec<String> {
    lock_packages(lock)
        .into_iter()
        .filter(|n| !ALLOWED_PACKAGES.contains(&n.as_str()))
        .map(|n| format!("Cargo.lock: package `{n}` is not in the allowlist"))
        .collect()
}

fn assert_clean(guard: &str, bad: Vec<String>) {
    assert!(bad.is_empty(), "{guard} violated:\n  {}", bad.join("\n  "));
}

#[test]
fn guard1_no_std_io_modules_outside_harness() {
    assert_clean("guard 1", check_guard1(&sources()));
}

#[test]
fn guard2_open_options_only_in_fs_and_no_writes() {
    assert_clean("guard 2", check_guard2(&sources()));
}

#[test]
fn guard3_one_subprocess_and_libc_only_in_fs() {
    assert_clean("guard 3", check_guard3(&sources()));
}

#[test]
fn guard4_cargo_lock_matches_allowlist() {
    let lock = fs::read_to_string(crates_dir().join("../Cargo.lock")).expect("read Cargo.lock");
    assert_clean("guard 4", check_guard4(&lock));
}

// `.append(`/`.truncate(` are matched with their `bool` argument so `Vec::append` and
// `String::truncate` don't trip them.
//
// The guards must actually fire. These feed violations in memory, so no source file has to be
// edited to prove it.
mod fires {
    use super::*;

    fn src(rel: &str, code: &str) -> Vec<Src> {
        vec![Src {
            rel: rel.to_string(),
            code: production_code(code),
        }]
    }

    #[test]
    fn std_fs_in_a_scanner() {
        let s = src(
            "cainary-core/src/scanners/cursor.rs",
            "fn scan() { let _ = std::fs::read(\"x\"); }",
        );
        assert_eq!(check_guard1(&s).len(), 1);
    }

    #[test]
    fn group_import_and_other_modules() {
        let s = src(
            "cainary-core/src/rules/hooks.rs",
            "use std::{io::Read, env};\nuse std::process::Command;\nuse std::net::TcpStream;",
        );
        assert_eq!(check_guard1(&s).len(), 3);
    }

    #[test]
    fn aliased_imports_and_spacing() {
        let scanner = "cainary-core/src/scanners/cursor.rs";
        for code in [
            "use std::fs as disk;\ndisk::read(\"x\");",
            "use std::{fs as disk};",
            "use std :: fs :: read;",
            "use std::\n    fs::read;",
        ] {
            assert_eq!(check_guard1(&src(scanner, code)).len(), 1, "{code}");
        }
        let w = src(FS_RS, "disk::write(\"x\", b\"y\");");
        assert_eq!(check_guard2(&w).len(), 1);
        let mut c = src(
            PLATFORM_RS,
            "use std::process::Command as C;\nC::new(\"/bin/sh\");",
        );
        c.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&c).iter().any(|b| b.contains("alias")));
    }

    #[test]
    fn allowed_places() {
        assert!(check_guard1(&src(FS_RS, "use std::fs::File;")).is_empty());
        assert!(check_guard1(&src(CLI_MAIN, "let a = std::env::args();")).is_empty());
        assert!(check_guard1(&src("cainary-cli/src/args.rs", "use std::path::Path;")).is_empty());
    }

    #[test]
    fn test_tail_and_comments_are_skipped() {
        let code = "// std::fs is banned here\nfn a() {}\n#[cfg(test)]\nmod t { use std::fs; }";
        assert!(check_guard1(&src("cainary-core/src/analysis.rs", code)).is_empty());
    }

    #[test]
    fn open_options_and_writes() {
        let s = src(
            "cainary-core/src/harness/ctx.rs",
            "let f = OpenOptions::new();",
        );
        assert_eq!(check_guard2(&s).len(), 1);
        assert!(check_guard2(&src(FS_RS, "let f = OpenOptions::new().read(true);")).is_empty());
        for m in WRITE_SHAPED {
            let s = src(FS_RS, &format!("x{m}y"));
            assert_eq!(check_guard2(&s).len(), 1, "{m}");
        }
    }

    #[test]
    fn libc_outside_fs() {
        let mut s = src("cainary-core/src/harness/ctx.rs", "let n = libc::getuid();");
        s.extend(src(
            PLATFORM_RS,
            "let c = Command::new(\"/usr/sbin/scutil\");",
        ));
        let bad = check_guard3(&s);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("libc::"));
    }

    #[test]
    fn command_new_count_and_place() {
        let ok = src(
            PLATFORM_RS,
            "let c = Command::new(\n    \"/usr/sbin/scutil\",\n);",
        );
        assert!(check_guard3(&ok).is_empty());
        let mut two = src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");");
        two.extend(src(
            "cainary-core/src/scanners/device.rs",
            "Command::new(\"ls\");",
        ));
        assert_eq!(check_guard3(&two).len(), 1);
        let wrong_prog = src(PLATFORM_RS, "Command::new(\"/bin/sh\");");
        assert_eq!(check_guard3(&wrong_prog).len(), 1);
        assert_eq!(check_guard3(&[]).len(), 1);
    }

    #[test]
    fn unknown_package() {
        let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n\
                    [[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\n";
        let bad = check_guard4(lock);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("reqwest"));
    }
}
