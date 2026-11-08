//! Source-level safety guards (architecture.md §10, guards 1–4, and N1–N4 for `cainary-net`).
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
    /// The whole file, comments and tests included.
    raw: String,
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

/// Production items that follow the first test module: `production_code` stops there, so every
/// guard would silently skip them. An item at column 0 after the cut is fine only when it is
/// itself `#[cfg(test)]`.
fn check_tests_last(srcs: &[Src]) -> Vec<String> {
    const ITEM: [&str; 18] = [
        "fn ",
        "pub fn ",
        "pub(crate) fn ",
        "impl",
        "struct ",
        "pub struct ",
        "enum ",
        "pub enum ",
        "const ",
        "pub const ",
        "static ",
        "trait ",
        "pub trait ",
        "use ",
        "pub use ",
        "type ",
        "macro_rules!",
        "extern ",
    ];
    let mut bad = Vec::new();
    for s in srcs {
        let lines: Vec<&str> = s.raw.lines().collect();
        let Some(cut) = (0..lines.len()).find(|&i| {
            lines[i].trim() == "#[cfg(test)]"
                && lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.starts_with("#["))
                    .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod "))
        }) else {
            continue;
        };
        let mut pending_test = false;
        for (n, line) in lines.iter().enumerate().skip(cut) {
            if line.starts_with("#[") {
                pending_test |= line.contains("cfg(") && line.contains("test");
                continue;
            }
            if line.starts_with("//") {
                continue;
            }
            let top_level = !line.is_empty() && !line.starts_with([' ', '\t', '}', ')', ']']);
            let is_item = top_level
                && (ITEM.iter().any(|p| line.starts_with(p))
                    || line.starts_with("mod ")
                    || line.starts_with("pub mod "));
            if is_item && !pending_test {
                bad.push(format!(
                    "{}:{}: production item after a test module: `{}`",
                    s.rel,
                    n + 1,
                    line.trim()
                ));
            }
            if !line.trim().is_empty() {
                pending_test = false;
            }
        }
    }
    bad
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
        .map(|p| {
            let raw = fs::read_to_string(p).expect("read source");
            Src {
                rel: p
                    .strip_prefix(&crates)
                    .expect("under crates/")
                    .to_string_lossy()
                    .replace('\\', "/"),
                code: production_code(&raw),
                raw,
            }
        })
        .collect()
}

const FS_RS: &str = "cainary-core/src/harness/fs.rs";
const PLATFORM_RS: &str = "cainary-core/src/harness/platform.rs";
const CLI_MAIN: &str = "cainary-cli/src/main.rs";

const NET_SRC: &str = "cainary-net/src/";
const NET_SERVER: &str = "cainary-net/src/server.rs";
const NET_LOGFILE: &str = "cainary-net/src/logfile.rs";
const NET_REDFLAG_FILE: &str = "cainary-net/src/redflag/file.rs";
const NET_TLS: &str = "cainary-net/src/tls/";
const NET_CA_FILE: &str = "cainary-net/src/tls/ca_file.rs";
const NET_TLS_MOD: &str = "cainary-net/src/tls/mod.rs";
const NET_TRUST_FILES: &str = "cainary-net/src/trust/files.rs";
const NET_PEER_PROC: &str = "cainary-net/src/peer_proc.rs";
const NET_PRIVDROP: &str = "cainary-net/src/privdrop.rs";
const NET_LISTENFD: &str = "cainary-net/src/listenfd.rs";
const NET_MAIN: &str = "cainary-net/src/main.rs";

/// Files in the net crate that may call `libc`: the log file (open flags, uid), the CA file
/// (same) and the capability drop.
fn net_libc_ok(rel: &str) -> bool {
    rel == NET_LOGFILE
        || rel == NET_CA_FILE
        || rel == NET_PRIVDROP
        || rel == NET_LISTENFD
        || rel == NET_TRUST_FILES
}

fn in_net(rel: &str) -> bool {
    rel.starts_with(NET_SRC)
}

const HELPER_SRC: &str = "cainary-bind-helper/src/";

/// The root bind helper has its own, stricter rules (`check_helper_source`).
fn in_helper(rel: &str) -> bool {
    rel.starts_with(HELPER_SRC)
}

const HOSTS_SRC: &str = "cainary-hosts-helper/src/";

/// The root hosts helper has its own rules too (`check_hosts_helper_source`); like the bind
/// helper it is exempt from guards 1 to 3.
fn in_hosts_helper(rel: &str) -> bool {
    rel.starts_with(HOSTS_SRC)
}

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
        if in_harness(&s.rel)
            || s.rel == CLI_MAIN
            || in_net(&s.rel)
            || in_helper(&s.rel)
            || in_hosts_helper(&s.rel)
        {
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
        if in_net(&s.rel) || in_helper(&s.rel) || in_hosts_helper(&s.rel) {
            continue;
        }
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
        if s.rel != FS_RS
            && !net_libc_ok(&s.rel)
            && !in_helper(&s.rel)
            && !in_hosts_helper(&s.rel)
            && s.code.contains("libc::")
        {
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

/// Calls that open or resolve an outbound connection. None may appear anywhere in the net
/// crate, `server.rs` included: it listens and never dials.
const NET_BANNED_CALLS: [&str; 11] = [
    "core::net",
    "TcpStream::connect",
    ".connect(",
    "connect_timeout",
    "UdpSocket",
    "ToSocketAddrs",
    "to_socket_addrs",
    "lookup_host",
    "UnixStream",
    "UnixDatagram",
    "os::unix::net",
];

/// Identifier tokens (`[A-Za-z0-9_]+`), so `cainary_core` isn't `core` and `max_connections`
/// isn't `connect`.
fn idents(code: &str) -> Vec<&str> {
    code.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect()
}

/// N1: `std::net` only in `server.rs`, and no outbound or resolving call anywhere in the crate.
/// Aliases can't hide a dial: the identifier `connect` (or `connect_*`) is banned outright, as
/// is renaming anything about `std`, `core`, `alloc` or `net` in a `use` or `extern crate`.
fn check_n1(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs.iter().filter(|s| in_net(&s.rel)) {
        if s.rel != NET_SERVER {
            for hit in banned_std_modules(&s.code) {
                if hit == "std::net" || hit == "std::{net}" {
                    bad.push(format!("{}: {hit} outside server.rs", s.rel));
                }
            }
        }
        let code = squash(&s.code);
        for call in NET_BANNED_CALLS {
            if code.contains(call) {
                bad.push(format!("{}: outbound or resolving call `{call}`", s.rel));
            }
        }
        if idents(&code)
            .iter()
            .any(|t| *t == "connect" || t.starts_with("connect_"))
        {
            bad.push(format!("{}: the identifier `connect` is banned", s.rel));
        }
        for stmt in code.split(';') {
            let stmt = stmt.trim_start();
            let toks = idents(stmt);
            // `use` may follow `{`, `pub` or an attribute, so look anywhere in the statement.
            let renames = toks.contains(&"use") || toks.contains(&"extern");
            if renames
                && toks.contains(&"as")
                && toks
                    .iter()
                    .any(|t| matches!(*t, "std" | "core" | "alloc" | "net"))
            {
                bad.push(format!("{}: renamed std/core/net import `{stmt}`", s.rel));
            }
        }
    }
    bad
}

/// N2: `std::fs` only in `logfile.rs` (write), `redflag/file.rs` (read) and `peer_proc.rs` (the
/// kernel's `/proc/net/tcp{,6}` and two more fixed `/proc` files, read); `OpenOptions` and
/// write-shaped calls only in `logfile.rs`; `std::env` and `std::process` only in `main.rs`.
fn check_n2(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs.iter().filter(|s| in_net(&s.rel)) {
        for hit in banned_std_modules(&s.code) {
            let allowed = match hit.trim_start_matches("std::").trim_matches(['{', '}']) {
                "fs" => {
                    s.rel == NET_LOGFILE
                        || s.rel == NET_REDFLAG_FILE
                        || s.rel == NET_CA_FILE
                        || s.rel == NET_TRUST_FILES
                        // Four fixed kernel paths, read-only: /proc/net/tcp{,6}, /proc/self/status and
                        // /proc/sys/kernel/overflowuid.
                        || s.rel == NET_PEER_PROC
                }
                "env" | "process" => s.rel == NET_MAIN,
                _ => true, // `net` is N1's
            };
            if !allowed {
                bad.push(format!("{}: {hit} outside its allowed file", s.rel));
            }
        }
        if s.rel != NET_LOGFILE && s.rel != NET_CA_FILE && s.rel != NET_TRUST_FILES {
            let code = squash(&s.code);
            if s.code.contains("OpenOptions") {
                bad.push(format!("{}: OpenOptions outside logfile.rs", s.rel));
            }
            for m in WRITE_SHAPED {
                // Sockets write too: `.write(` is the byte-stream method, and these two files
                // can't open a file (no `std::fs`, no `OpenOptions`, no `libc`).
                let socket_file = s.rel == NET_SERVER || s.rel == NET_TLS_MOD;
                if code.contains(m) && !(socket_file && m == ".write(") {
                    bad.push(format!(
                        "{}: write-shaped call `{m}` outside logfile.rs and tls/ca_file.rs",
                        s.rel
                    ));
                }
            }
        }
    }
    bad
}

/// N3: no `Command` and no `libc::` in the net crate, except `libc::` in `logfile.rs` and
/// `tls/ca_file.rs` (open flags, uid, flock), `trust/files.rs` (the same, for the Claude Code settings edit; the rest of `trust/` calls into it) and
/// `privdrop.rs` (capabilities). Guard 3's "exactly once" also counts `Command::new`.
fn check_n3(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs.iter().filter(|s| in_net(&s.rel)) {
        if s.code.contains("Command") {
            bad.push(format!("{}: `Command` in the net crate", s.rel));
        }
        if !net_libc_ok(&s.rel) && s.code.contains("libc::") {
            bad.push(format!(
                "{}: libc:: outside logfile.rs, tls/ca_file.rs and privdrop.rs",
                s.rel
            ));
        }
    }
    bad
}

/// N5: the TLS crates (`rustls`, `rcgen`, `ring`) are named only under `cainary-net/src/tls/`,
/// or on a line right after `#[cfg(feature = "tls")]`; `mod tls` is gated the same way.
fn check_tls_paths(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs
        .iter()
        .filter(|s| in_net(&s.rel) && !s.rel.starts_with(NET_TLS))
    {
        let lines: Vec<String> = s.code.lines().map(squash).collect();
        for (i, line) in lines.iter().enumerate() {
            let toks = idents(line);
            let names_tls = toks
                .iter()
                .any(|t| matches!(*t, "rustls" | "rcgen" | "ring"))
                || (toks.contains(&"mod") && toks.contains(&"tls"));
            if !names_tls {
                continue;
            }
            // The nearest non-blank line above, skipping other attributes.
            let gated = lines[..i]
                .iter()
                .rev()
                .find(|l| !l.is_empty() && !l.starts_with("#[cfg(not"))
                .is_some_and(|l| l.contains("cfg(feature = \"tls\")"));
            if !gated {
                bad.push(format!(
                    "{}: `{line}` names the TLS crates outside tls/ and not under #[cfg(feature = \"tls\")]",
                    s.rel
                ));
            }
        }
    }
    bad
}

/// Dependencies the net crate may declare, in any dependency table.
const NET_DEPS: &[&str] = &[
    "cainary-core",
    "cainary-sig",
    "flate2",
    "libc",
    "rcgen",
    "rustls",
    "time",
    "regex",
    "serde",
    "serde_json",
    "toml",
];

/// N4 (manifests): the core and CLI manifests never mention `cainary-net`; the net manifest
/// declares only `NET_DEPS` and `publish = false`.
fn check_n4(core: &str, cli: &str, net: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, text) in [("cainary-core", core), ("cainary-cli", cli)] {
        if text.contains("cainary-net") {
            bad.push(format!("{name}/Cargo.toml mentions cainary-net"));
        }
    }
    let Ok(v) = toml::from_str::<toml::Value>(net) else {
        return vec!["cainary-net/Cargo.toml does not parse".to_string()];
    };
    let mut tables: Vec<(String, &toml::Value)> = Vec::new();
    for t in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(d) = v.get(t) {
            tables.push((t.to_string(), d));
        }
    }
    if let Some(targets) = v.get("target").and_then(|t| t.as_table()) {
        for (cfg, body) in targets {
            for t in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(d) = body.get(t) {
                    tables.push((format!("target.{cfg}.{t}"), d));
                }
            }
        }
    }
    for (table, deps) in tables {
        for name in deps.as_table().into_iter().flat_map(|t| t.keys()) {
            if !NET_DEPS.contains(&name.as_str()) {
                bad.push(format!(
                    "cainary-net [{table}]: `{name}` is not an allowed dependency"
                ));
            }
        }
    }
    let publish = v.get("package").and_then(|p| p.get("publish"));
    if publish != Some(&toml::Value::Boolean(false)) {
        bad.push("cainary-net must set `publish = false`".to_string());
    }
    bad
}

/// The signature primitives crate has no build-time or runtime dependencies and cannot be
/// published independently from the workspace release.
fn check_sig_manifest(sig: &str) -> Vec<String> {
    let Ok(v) = toml::from_str::<toml::Value>(sig) else {
        return vec!["cainary-sig/Cargo.toml does not parse".to_string()];
    };
    let mut bad = Vec::new();
    let mut tables: Vec<(String, &toml::Value)> = Vec::new();
    for table in ["dependencies", "build-dependencies"] {
        if let Some(deps) = v.get(table) {
            tables.push((table.to_string(), deps));
        }
    }
    if let Some(targets) = v.get("target").and_then(|t| t.as_table()) {
        for (cfg, body) in targets {
            for table in ["dependencies", "build-dependencies"] {
                if let Some(deps) = body.get(table) {
                    tables.push((format!("target.{cfg}.{table}"), deps));
                }
            }
        }
    }
    for (table, deps) in tables {
        if deps.as_table().is_some_and(|deps| !deps.is_empty()) {
            bad.push(format!("cainary-sig [{table}] must have no dependencies"));
        }
    }
    let publish = v.get("package").and_then(|p| p.get("publish"));
    if publish != Some(&toml::Value::Boolean(false)) {
        bad.push("cainary-sig must set `publish = false`".to_string());
    }
    bad
}

/// Packages `cainary` and `cainary-core` may use: the two workspace crates and the current
/// transitive closure of `serde`, `serde_json`, `toml`, `plist` and `libc`. Adding a crate is
/// a visible, reviewed change to this list.
const CORE_ALLOWED: &[&str] = &[
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

/// Packages only `cainary-net` may use (`regex` and its closure, which includes `aho-corasick`, and
/// `flate2` for gzip request bodies with its `miniz_oxide`, `adler2`, `simd-adler32`, `crc32fast` and `cfg-if`): in the lock, but never in the
/// dependency closure of `cainary` or `cainary-core`. `memchr` is already in the core's closure
/// through `serde_json`, so it isn't here.
const NET_ONLY: &[&str] = &[
    "adler2",
    "aho-corasick",
    "cainary-net",
    "cfg-if",
    "crc32fast",
    "flate2",
    "miniz_oxide",
    "regex",
    "regex-automata",
    "regex-syntax",
    "simd-adler32",
];

/// Packages only the `tls` feature of `cainary-net` may use: rustls with the ring
/// provider, rcgen, and everything they pull in that the core doesn't already have (`syn` and
/// `time` are already `CORE_ALLOWED`). The lock lists rcgen's optional `x509-parser` too, so those
/// names are here though no build compiles them. Never `aws-lc-rs`.
const TLS_ONLY: &[&str] = &[
    "asn1-rs",
    "asn1-rs-derive",
    "asn1-rs-impl",
    "autocfg",
    "bit-vec",
    "cc",
    "data-encoding",
    "der-parser",
    "displaydoc",
    "find-msvc-tools",
    "getrandom",
    "lazy_static",
    "minimal-lexical",
    "nom",
    "num-bigint",
    "num-integer",
    "num-traits",
    "oid-registry",
    "once_cell",
    "pem",
    "rcgen",
    "ring",
    "rusticata-macros",
    "rustls",
    "rustls-pki-types",
    "rustls-webpki",
    "shlex",
    "subtle",
    "synstructure",
    "thiserror",
    "thiserror-impl",
    "untrusted",
    "wasi",
    "windows-sys",
    "windows-targets",
    "windows_aarch64_gnullvm",
    "windows_aarch64_msvc",
    "windows_i686_gnu",
    "windows_i686_gnullvm",
    "windows_i686_msvc",
    "windows_x86_64_gnu",
    "windows_x86_64_gnullvm",
    "windows_x86_64_msvc",
    "x509-parser",
    "yasna",
    "zeroize",
];

/// The pure signature primitives are available to the net collector and Linux tray, never to the
/// read-only core or CLI.
const SIG_ONLY: &[&str] = &["cainary-sig"];

/// The root bind helper: in the lock, but never in the closure of `cainary` or `cainary-core`.
const HELPER_ONLY: &[&str] = &["cainary-bind-helper", "cainary-hosts-helper"];

/// Closure rules: a named package set, and the roots whose dependency closure must not touch it.
const CLOSURE_RULES: &[(&str, &[&str], &[&str])] = &[
    ("NET_ONLY", NET_ONLY, &["cainary", "cainary-core"]),
    ("TLS_ONLY", TLS_ONLY, &["cainary", "cainary-core"]),
    ("SIG_ONLY", SIG_ONLY, &["cainary", "cainary-core"]),
    ("HELPER_ONLY", HELPER_ONLY, &["cainary", "cainary-core"]),
];

/// Every set the lock may draw from.
const ALLOWED_SETS: &[&[&str]] = &[CORE_ALLOWED, NET_ONLY, TLS_ONLY, SIG_ONLY, HELPER_ONLY];

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

/// The lock's `[[package]]` entries: name → the names it depends on.
fn lock_graph(lock: &str) -> Vec<(String, Vec<String>)> {
    let v: toml::Value = toml::from_str(lock).expect("Cargo.lock parses as TOML");
    v.get("package")
        .and_then(|p| p.as_array())
        .expect("Cargo.lock has [[package]] entries")
        .iter()
        .map(|p| {
            let name = p
                .get("name")
                .and_then(|n| n.as_str())
                .expect("package has a name");
            let deps = p
                .get("dependencies")
                .and_then(|d| d.as_array())
                .into_iter()
                .flatten()
                .filter_map(|d| d.as_str())
                // "name", "name 1.2.3" or "name 1.2.3 (registry+…)".
                .map(|d| d.split(' ').next().unwrap_or(d).to_string())
                .collect();
            (name.to_string(), deps)
        })
        .collect()
}

/// Every name reachable from `root`, `root` included.
fn closure(graph: &[(String, Vec<String>)], root: &str) -> Vec<String> {
    let mut seen = vec![root.to_string()];
    let mut stack = vec![root.to_string()];
    while let Some(n) = stack.pop() {
        for (name, deps) in graph {
            if *name == n {
                for d in deps {
                    if !seen.contains(d) {
                        seen.push(d.clone());
                        stack.push(d.clone());
                    }
                }
            }
        }
    }
    seen
}

fn check_guard4(lock: &str) -> Vec<String> {
    let mut bad: Vec<String> = lock_packages(lock)
        .into_iter()
        .filter(|n| !ALLOWED_SETS.iter().any(|set| set.contains(&n.as_str())))
        .map(|n| format!("Cargo.lock: package `{n}` is not in the allowlist"))
        .collect();
    let graph = lock_graph(lock);
    for (set, packages, roots) in CLOSURE_RULES {
        for root in *roots {
            for reached in closure(&graph, root) {
                if packages.contains(&reached.as_str()) && reached != *root {
                    bad.push(format!(
                        "Cargo.lock: `{root}` reaches `{reached}`, which is {set} only"
                    ));
                }
            }
        }
    }
    bad
}

fn assert_clean(guard: &str, bad: Vec<String>) {
    assert!(bad.is_empty(), "{guard} violated:\n  {}", bad.join("\n  "));
}

#[test]
fn test_modules_come_last() {
    assert_clean("tests-last", check_tests_last(&sources()));
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
fn n1_net_crate_never_dials_and_std_net_stays_in_server() {
    assert_clean("N1", check_n1(&sources()));
}

#[test]
fn n2_net_crate_io_stays_in_its_files() {
    assert_clean("N2", check_n2(&sources()));
}

#[test]
fn n3_net_crate_has_no_subprocess_or_libc() {
    assert_clean("N3", check_n3(&sources()));
}

#[test]
fn n5_tls_crates_stay_under_tls() {
    assert_clean("N5", check_tls_paths(&sources()));
}

#[test]
fn n4_net_manifests() {
    let crates = crates_dir();
    let read =
        |c: &str| fs::read_to_string(crates.join(c).join("Cargo.toml")).expect("read manifest");
    assert_clean(
        "N4",
        check_n4(
            &read("cainary-core"),
            &read("cainary-cli"),
            &read("cainary-net"),
        ),
    );
}

#[test]
fn guard4_cargo_lock_matches_allowlist() {
    let lock = fs::read_to_string(crates_dir().join("../Cargo.lock")).expect("read Cargo.lock");
    assert_clean("guard 4", check_guard4(&lock));
}

#[test]
fn sig_manifest_has_no_dependencies_and_is_not_publishable() {
    let manifest = fs::read_to_string(crates_dir().join("cainary-sig/Cargo.toml"))
        .expect("read cainary-sig manifest");
    assert_clean("cainary-sig manifest", check_sig_manifest(&manifest));
}

/// Identifiers the root helper may not use: no process creation, no file access, no environment
/// beyond the one `PKEXEC_UID` read, no `SO_REUSEPORT`. Anything starting with `exec` is banned too.
const HELPER_BANNED_IDENTS: &[&str] = &[
    "Command",
    "File",
    "OpenOptions",
    "fork",
    "vfork",
    "spawn",
    "system",
    "popen",
    "open",
    "openat",
    "creat",
    "read",
    "write",
    "unlink",
    "rename",
    "mkdir",
    "getenv",
    "environ",
    "setenv",
    "SO_REUSEPORT",
];

/// H1: the helper source (`cainary-bind-helper/src/`).
fn check_helper_source(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    for s in srcs.iter().filter(|s| in_helper(&s.rel)) {
        let code = squash(&s.code);
        for hit in banned_std_modules(&s.code) {
            if hit != "std::process" && hit != "std::{process}" && hit != "std::env" {
                bad.push(format!("{}: {hit} in the helper", s.rel));
            }
        }
        for t in idents(&code) {
            if HELPER_BANNED_IDENTS.contains(&t) || t.starts_with("exec") {
                bad.push(format!("{}: banned identifier `{t}` in the helper", s.rel));
            }
        }
        let vars = code.matches("env::var").count();
        let pkexec = code.matches("env::var(\"PKEXEC_UID\")").count();
        if vars != pkexec || pkexec > 1 {
            bad.push(format!(
                "{}: the helper may read only PKEXEC_UID, once (`env::var` x{vars})",
                s.rel
            ));
        }
    }
    bad
}

/// H2: the helper manifest declares only `libc` (in any dependency table) and `publish = false`.
fn check_helper_manifest(manifest: &str) -> Vec<String> {
    check_manifest_of("cainary-bind-helper", manifest)
}

fn check_manifest_of(krate: &str, manifest: &str) -> Vec<String> {
    let Ok(v) = toml::from_str::<toml::Value>(manifest) else {
        return vec![format!("{krate}/Cargo.toml does not parse")];
    };
    let mut tables: Vec<(String, &toml::Value)> = Vec::new();
    for t in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(d) = v.get(t) {
            tables.push((t.to_string(), d));
        }
    }
    if let Some(targets) = v.get("target").and_then(|t| t.as_table()) {
        for (cfg, body) in targets {
            for t in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(d) = body.get(t) {
                    tables.push((format!("target.{cfg}.{t}"), d));
                }
            }
        }
    }
    let mut bad = Vec::new();
    for (table, deps) in tables {
        for name in deps.as_table().into_iter().flat_map(|t| t.keys()) {
            if name != "libc" {
                bad.push(format!(
                    "{krate} [{table}]: `{name}` is not allowed, only libc"
                ));
            }
        }
    }
    if v.get("package").and_then(|p| p.get("publish")) != Some(&toml::Value::Boolean(false)) {
        bad.push(format!("{krate} must set `publish = false`"));
    }
    bad
}

/// H3: `cainary-bind-helper` reaches only `libc` in the lock.
fn check_helper_closure(lock: &str) -> Vec<String> {
    check_closure_of("cainary-bind-helper", lock)
}

fn check_closure_of(krate: &str, lock: &str) -> Vec<String> {
    closure(&lock_graph(lock), krate)
        .into_iter()
        .filter(|n| n != krate && n != "libc")
        .map(|n| format!("Cargo.lock: {krate} reaches `{n}`, not just libc"))
        .collect()
}

const POLICY_ID: &str = "ua.SkeLLLa.cAInary.bind-loopback-port";
const POLICY_PATH: &str = "/usr/libexec/cainary/cainary-bind-helper";
const POLICY_LOCAL_PATH: &str = "/usr/local/libexec/cainary/cainary-bind-helper";

/// The text of every `<tag …>text</tag>` in `xml`.
fn xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(gt) = after.find('>') else { break };
        let Some(end) = after.find(&close) else { break };
        if gt < end {
            out.push(after[gt + 1..end].trim().to_string());
        }
        rest = &after[end + close.len()..];
    }
    out
}

/// H4: the two polkit policies are well formed, use `no`/`no`/`auth_admin`, name the exact action
/// and `exec.path`, and differ from each other only in those two values.
fn check_policies(packaged: &str, local: &str) -> Vec<String> {
    check_policies_of(POLICY_ID, POLICY_PATH, POLICY_LOCAL_PATH, packaged, local)
}

fn check_policies_of(
    policy_id: &str,
    policy_path: &str,
    policy_local_path: &str,
    packaged: &str,
    local: &str,
) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, text, id, path) in [
        ("packaged", packaged, policy_id.to_string(), policy_path),
        (
            "local",
            local,
            format!("{policy_id}.local"),
            policy_local_path,
        ),
    ] {
        let opens = text.matches("<action ").count();
        if opens != 1 || text.matches("</action>").count() != 1 || !text.contains("<policyconfig>")
        {
            bad.push(format!(
                "{name} policy: not exactly one <action> in a <policyconfig>"
            ));
        }
        if !text.contains(&format!("<action id=\"{id}\">")) {
            bad.push(format!("{name} policy: action id must be {id}"));
        }
        let paths: Vec<String> = text
            .match_indices("<annotate key=\"org.freedesktop.policykit.exec.path\">")
            .map(|(i, m)| {
                let rest = &text[i + m.len()..];
                rest[..rest.find('<').unwrap_or(0)].to_string()
            })
            .collect();
        if paths != [path] {
            bad.push(format!(
                "{name} policy: exec.path must be {path}, found {paths:?}"
            ));
        }
        for (tag, want) in [
            ("allow_any", "no"),
            ("allow_inactive", "no"),
            ("allow_active", "auth_admin"),
        ] {
            if xml_tags(text, tag) != [want] {
                bad.push(format!("{name} policy: <{tag}> must be exactly {want}"));
            }
        }
        for tag in ["description", "message"] {
            if xml_tags(text, tag).len() != 1 {
                bad.push(format!("{name} policy: needs exactly one <{tag}>"));
            }
        }
    }
    let normalized = local
        .replace(&format!("{policy_id}.local"), policy_id)
        .replace(policy_local_path, policy_path);
    if normalized != packaged {
        bad.push("the policies differ in more than the action id and exec.path".to_string());
    }
    bad
}

// ---- The hosts helper (`cainary-hosts-helper`) ----

const HOSTS_HELPER: &str = "cainary-hosts-helper";
const HOSTS_FILE_RS: &str = "cainary-hosts-helper/src/file.rs";
const HOSTS_SEAM_RS: &str = "cainary-hosts-helper/src/seam.rs";
const HOSTS_EDIT_RS: &str = "cainary-hosts-helper/src/edit.rs";
const HOSTS_MAIN_RS: &str = "cainary-hosts-helper/src/main.rs";
const HOSTS_HELPER_RS: &str = "cainary-hosts-helper/src/helper.rs";

/// Identifiers no file of the hosts helper may use: no process creation, no std file types, no
/// path-based or working-directory-relative file call (every file call is descriptor-relative),
/// no environment beyond the one `PKEXEC_UID` read. Anything starting with `exec` is banned too.
const HOSTS_BANNED_IDENTS: &[&str] = &[
    "Command",
    "File",
    "OpenOptions",
    "DirBuilder",
    "fork",
    "vfork",
    "spawn",
    "system",
    "popen",
    "getenv",
    "environ",
    "setenv",
    "AT_FDCWD",
    "chdir",
    "fchdir",
    "chroot",
    "mkfifo",
    "mknod",
    "realpath",
    "canonicalize",
    "read_link",
    "SO_REUSEPORT",
];

/// The `libc` items the file procedure (`file.rs`) may name; everything else is a violation.
/// Path-based calls (`open`, `creat`, `unlink`, `rename`, `mkdir`, `stat`, `chmod`, `chown`,
/// `truncate`, `link`, `symlink`, `access`, …) are deliberately missing: only the `*at` forms and
/// descriptor calls are here.
const HOSTS_FILE_LIBC: &[&str] = &[
    "AT_EMPTY_PATH",
    "AT_SYMLINK_NOFOLLOW",
    "EACCES",
    "EINTR",
    "EIO",
    "ELOOP",
    "ENODATA",
    "ENOENT",
    "ENOTSUP",
    "EOPNOTSUPP",
    "EPERM",
    "ERANGE",
    "EROFS",
    "EWOULDBLOCK",
    "LOCK_EX",
    "LOCK_NB",
    "O_CLOEXEC",
    "O_CREAT",
    "O_DIRECTORY",
    "O_EXCL",
    "O_NOFOLLOW",
    "O_NONBLOCK",
    "O_PATH",
    "O_RDONLY",
    "O_RDWR",
    "O_WRONLY",
    "S_IFDIR",
    "S_IFIFO",
    "S_IFLNK",
    "S_IFMT",
    "S_IFREG",
    "STATX_CTIME",
    "STATX_GID",
    "STATX_INO",
    "STATX_MNT_ID",
    "STATX_MODE",
    "STATX_MTIME",
    "STATX_NLINK",
    "STATX_SIZE",
    "STATX_TYPE",
    "STATX_UID",
    "fchmod",
    "fchown",
    "fgetxattr",
    "flock",
    "fremovexattr",
    "fsetxattr",
    "fsync",
    "openat",
    "read",
    "renameat",
    "statx",
    "unlinkat",
    "write",
];

/// The `libc` items the other files may name (`helper.rs`): the privilege checks, SIGPIPE and the
/// node name. `edit.rs` and `seam.rs` name none.
const HOSTS_OTHER_LIBC: &[&str] = &[
    "SIGPIPE", "SIG_IGN", "getegid", "geteuid", "signal", "uname", "utsname",
];

/// The only `c"…"` literals production code may contain: the names the procedure touches.
const HOSTS_C_LITERALS: &[&str] = &[
    "",
    "/",
    "etc",
    "hosts",
    "hosts.cainary-backup",
    ".cainary-hosts.lock",
    ".hosts.cainary-new",
    ".hosts.cainary-bak-new",
    "security.selinux",
    "system.posix_acl_access",
];

/// Every `libc::name` in `code`, by name.
fn libc_names(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(i) = rest.find("libc::") {
        let after = &rest[i + "libc::".len()..];
        let n = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        out.push(after[..n].to_string());
        rest = &after[n..];
    }
    out
}

/// `code` with the inside of every string literal blanked, so a name like `c"system.posix_acl"`
/// is not read as the identifier `system`.
fn blank_strings(code: &str) -> String {
    let mut out = String::new();
    let mut in_str = false;
    let mut esc = false;
    for c in code.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
                out.push('"');
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        }
        out.push(c);
    }
    out
}

/// Every `c"…"` literal in `code`.
fn c_literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(i) = rest.find("c\"") {
        let before = rest[..i].chars().next_back();
        let after = &rest[i + 2..];
        let end = after.find('"').unwrap_or(after.len());
        // `c"` inside an identifier (`abc"`) is a string end, not a C literal.
        if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            out.push(after[..end].to_string());
        }
        rest = &after[(end + 1).min(after.len())..];
    }
    out
}

/// The text of the item that starts with `signature`: up to and including the first line that is
/// exactly `}` (or the `;` line for a `const`).
fn item_text(src: &str, signature: &str) -> Option<String> {
    let start = src.find(signature)?;
    let rest = &src[start..];
    let end = if signature.starts_with("pub const ") {
        rest.find(";\n")? + 2
    } else {
        rest.find("\n}\n")? + 3
    };
    Some(rest[..end].to_string())
}

/// H5: the hosts helper source.
fn check_hosts_helper_source(srcs: &[Src]) -> Vec<String> {
    let mut bad = Vec::new();
    let mut env_vars = 0;
    let mut apply_in_calls = 0;
    for s in srcs.iter().filter(|s| in_hosts_helper(&s.rel)) {
        let code = squash(&s.code);
        for hit in banned_std_modules(&s.code) {
            if hit != "std::process" && hit != "std::{process}" && hit != "std::env" {
                bad.push(format!("{}: {hit} in the hosts helper", s.rel));
            }
        }
        for t in idents(&blank_strings(&code)) {
            if HOSTS_BANNED_IDENTS.contains(&t) || t.starts_with("exec") {
                bad.push(format!(
                    "{}: banned identifier `{t}` in the hosts helper",
                    s.rel
                ));
            }
        }
        // Descriptor-relative or nothing: every `libc` item is on the list for its file.
        let allowed = if s.rel == HOSTS_FILE_RS {
            HOSTS_FILE_LIBC
        } else if s.rel == HOSTS_HELPER_RS || s.rel == HOSTS_SEAM_RS {
            HOSTS_OTHER_LIBC
        } else {
            &[]
        };
        for name in libc_names(&code) {
            if !allowed.contains(&name.as_str()) {
                bad.push(format!("{}: `libc::{name}` is not allowed here", s.rel));
            }
        }
        if code.contains("extern \"C\"") || code.contains("libc::syscall") {
            bad.push(format!("{}: `extern \"C\"` or `libc::syscall`", s.rel));
        }
        for lit in c_literals(&code) {
            if s.rel != HOSTS_FILE_RS || !HOSTS_C_LITERALS.contains(&lit.as_str()) {
                bad.push(format!("{}: c\"{lit}\" literal is not allowed here", s.rel));
            }
        }
        // One production/test split, and it lives in seam.rs.
        for (i, _) in code.match_indices("cfg(") {
            let tail = &code[i..];
            let ok = s.rel == HOSTS_SEAM_RS
                || (s.rel == HOSTS_MAIN_RS && tail.starts_with("cfg(target_os = \"linux\")"))
                || (s.rel == HOSTS_MAIN_RS && tail.starts_with("cfg(not(target_os = \"linux\"))"));
            if !ok {
                bad.push(format!(
                    "{}: `cfg(` outside seam.rs (and main.rs target_os)",
                    s.rel
                ));
            }
        }
        if code.contains("feature =") || code.contains("feature=") {
            bad.push(format!("{}: cargo features are not allowed", s.rel));
        }
        if s.rel == HOSTS_FILE_RS || s.rel == HOSTS_EDIT_RS {
            // The pure core and the file procedure never see the environment or process state.
            if code.contains("std::env") {
                bad.push(format!("{}: std::env outside helper.rs", s.rel));
            }
        }
        env_vars +=
            code.matches("env::var").count() - code.matches("env::var(\"PKEXEC_UID\")").count();
        if code.matches("env::var(\"PKEXEC_UID\")").count() > 1 {
            bad.push(format!("{}: PKEXEC_UID read more than once", s.rel));
        }
        if s.rel != HOSTS_SEAM_RS && code.contains("Knobs {") {
            bad.push(format!("{}: `Knobs` is built only in seam.rs", s.rel));
        }
        if s.rel == HOSTS_FILE_RS {
            apply_in_calls += code.matches("apply_in(").count();
        } else if code.contains("apply_in(") {
            bad.push(format!(
                "{}: `apply_in` is reached only from file.rs::apply",
                s.rel
            ));
        }
    }
    if env_vars > 0 {
        bad.push(format!(
            "the hosts helper may read only PKEXEC_UID (`env::var` x{env_vars} other)"
        ));
    }
    // The definition and the single call in `apply`; the descriptor-taking entry point takes a
    // test directory only from tests.
    let present = srcs.iter().any(|s| s.rel == HOSTS_FILE_RS);
    if present && apply_in_calls != 2 {
        bad.push(format!(
            "file.rs: `apply_in(` must appear exactly twice (definition and the call in `apply`), found {apply_in_calls}"
        ));
    }
    bad
}

/// H6: seam.rs is the only test seam. Its production side is fixed constants and a no-op hook,
/// and everything else in it exists only under `cfg(test)`.
fn check_hosts_seam(srcs: &[Src]) -> Vec<String> {
    let Some(s) = srcs.iter().find(|s| s.rel == HOSTS_SEAM_RS) else {
        return vec![format!("{HOSTS_SEAM_RS} is missing")];
    };
    let mut bad = Vec::new();
    let code = squash(&s.code);
    for want in [
        "#[cfg(not(test))] pub fn knobs() -> Knobs { Knobs { uid: 0, gid: 0, lock_deadline: Duration::from_secs(5), max_read: 16 * 1024 * 1024, write_chunk: usize::MAX, } }",
        "#[cfg(not(test))] pub fn hook(_step: Step, _etc: RawFd) -> Result<(), Fail> { Ok(()) }",
        "#[cfg(not(test))] pub fn crashed() -> bool { false }",
        "#[cfg(not(test))] pub fn sys(_call: Sys) -> Option<i32> { None }",
    ] {
        if !code.contains(want) {
            bad.push(format!(
                "seam.rs: production side must read exactly `{want}`"
            ));
        }
    }
    if code.matches("cfg(not(test))").count() != 4 {
        bad.push("seam.rs: exactly four `cfg(not(test))` items (knobs, hook, crashed, sys)".into());
    }
    if code.matches("cfg(").count() != code.matches("cfg(test)").count() + 4 {
        bad.push("seam.rs: every other `cfg(` must be `cfg(test)`".into());
    }
    // Everything at column 0 that is not one of the shared items must sit behind `cfg(test)`.
    let shared = ["Step", "Sys", "Knobs", "knobs", "hook", "crashed", "sys"];
    let lines: Vec<&str> = s.code.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let item = [
            "pub fn ",
            "pub enum ",
            "pub struct ",
            "fn ",
            "enum ",
            "struct ",
            "thread_local!",
            "static ",
            "const ",
        ]
        .iter()
        .find(|k| line.starts_with(**k));
        let Some(kind) = item else { continue };
        let name = line[kind.len()..]
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        if shared.contains(&name) {
            continue;
        }
        let prev = lines[..i]
            .iter()
            .rev()
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.starts_with("#[derive"));
        if prev != Some("#[cfg(test)]") {
            bad.push(format!(
                "seam.rs: `{}` is not behind `#[cfg(test)]`",
                line.trim()
            ));
        }
    }
    bad
}

/// H7: `valid_host` is byte-identical to the one in `cainary-net` (and its length cap), and
/// `parse_uid` to the bind helper's.
fn check_hosts_copies(net_host: &str, hosts_helper: &str, bind_helper: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (what, sig, a, b) in [
        ("valid_host", "pub fn valid_host(", net_host, hosts_helper),
        (
            "MAX_HOST_BYTES",
            "pub const MAX_HOST_BYTES: usize",
            net_host,
            hosts_helper,
        ),
        ("parse_uid", "pub fn parse_uid(", bind_helper, hosts_helper),
    ] {
        match (item_text(a, sig), item_text(b, sig)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(_), Some(_)) => bad.push(format!(
                "the hosts helper's `{what}` differs from its original"
            )),
            _ => bad.push(format!("`{what}` not found in both copies")),
        }
    }
    bad
}

const HOSTS_POLICY_ID: &str = "ua.SkeLLLa.cAInary.edit-hosts";
const HOSTS_POLICY_PATH: &str = "/usr/libexec/cainary/cainary-hosts-helper";
const HOSTS_POLICY_LOCAL_PATH: &str = "/usr/local/libexec/cainary/cainary-hosts-helper";
const HOSTS_POLICY_MESSAGE: &str = "Authentication is required to let cAInary change /etc/hosts. Approving lets it redirect host names to this computer for every user and program, and the change stays after cAInary quits. Requested: $(command_line)";

/// H8: the hosts policies pass the same checks as the bind ones, and their message is the
/// reviewed text, word for word.
fn check_hosts_policies(packaged: &str, local: &str) -> Vec<String> {
    let mut bad = check_policies_of(
        HOSTS_POLICY_ID,
        HOSTS_POLICY_PATH,
        HOSTS_POLICY_LOCAL_PATH,
        packaged,
        local,
    );
    for (name, text) in [("packaged", packaged), ("local", local)] {
        if xml_tags(text, "message") != [HOSTS_POLICY_MESSAGE] {
            bad.push(format!(
                "{name} hosts policy: <message> is not the reviewed text"
            ));
        }
    }
    bad
}

#[test]
fn hosts_helper_source_stays_inside_its_powers() {
    assert_clean("hosts helper source", check_hosts_helper_source(&sources()));
}

#[test]
fn hosts_helper_seam_is_test_only() {
    assert_clean("hosts helper seam", check_hosts_seam(&sources()));
}

#[test]
fn hosts_helper_manifest_is_libc_only_and_not_publishable() {
    let manifest = fs::read_to_string(crates_dir().join("cainary-hosts-helper/Cargo.toml"))
        .expect("read cainary-hosts-helper manifest");
    assert_clean(
        "hosts helper manifest",
        check_manifest_of(HOSTS_HELPER, &manifest),
    );
    let v: toml::Value = toml::from_str(&manifest).unwrap();
    assert!(v.get("features").is_none(), "no cargo features");
}

#[test]
fn hosts_helper_reaches_only_libc_in_the_lock() {
    let lock = fs::read_to_string(crates_dir().join("../Cargo.lock")).expect("read Cargo.lock");
    assert!(lock.contains(&format!("name = \"{HOSTS_HELPER}\"")));
    assert_clean(
        "hosts helper closure",
        check_closure_of(HOSTS_HELPER, &lock),
    );
}

#[test]
fn hosts_helper_copies_are_identical() {
    let read = |f: &str| fs::read_to_string(crates_dir().join(f)).expect("read source");
    assert_clean(
        "hosts helper copies",
        check_hosts_copies(
            &read("cainary-net/src/host.rs"),
            &read("cainary-hosts-helper/src/helper.rs"),
            &read("cainary-bind-helper/src/helper.rs"),
        ),
    );
}

/// The three host-name validators (`cainary-net`, the hosts helper and the tray's
/// `valid_tls_host`) compiled into one program and run over a shared corpus (the boundaries of
/// length and label size) and over every short string of a small alphabet. Any disagreement, or a
/// wrong verdict on the corpus, fails.
#[test]
fn the_three_host_validators_agree() {
    let read = |p: PathBuf| fs::read_to_string(p).expect("read source");
    let net = read(crates_dir().join("cainary-net/src/host.rs"));
    let helper = read(crates_dir().join("cainary-hosts-helper/src/helper.rs"));
    let tray = read(crates_dir().join("../linux/crates/tray-model/src/settings.rs"));
    let part =
        |src: &str, sig: &str| item_text(src, sig).unwrap_or_else(|| panic!("`{sig}` missing"));
    let program = format!(
        r#"
mod net {{ {n1} {n2} }}
mod helper {{ {h1} {h2} }}
mod tray {{ {t1} {t2} }}

fn main() {{
    let mut ok: Vec<String> = ["otel.example-corp.test", "a.b", "x1.y2.z3.example", "a-b.c-d.io", "a.b-c", "0.a", "a.0a"]
        .iter().map(|s| s.to_string()).collect();
    let l63 = "a".repeat(63);
    ok.push(format!("{{l63}}.com"));
    ok.push(format!("{{l63}}.{{l63}}.{{l63}}.{{}}", "a".repeat(61)));
    let mut bad: Vec<String> = ["", "localhost", "a..b", ".a.b", "a.b.", "a.b-", "-a.b", "A.b", "a_b.c", "a.b c", " a.b",
        "1.2.3.4", "a.1", "*.a.b", "a.b\n", "ä.example.com", "[::1]", "example.com."]
        .iter().map(|s| s.to_string()).collect();
    bad.push(format!("{{}}.com", "a".repeat(64)));
    bad.push(format!("{{l63}}.{{l63}}.{{l63}}.{{}}", "a".repeat(62)));
    let mut fails = Vec::new();
    for (list, want) in [(&ok, true), (&bad, false)] {{
        for h in list {{
            let got = (net::valid_host(h), helper::valid_host(h), tray::valid_tls_host(h));
            if got != (want, want, want) {{
                fails.push(format!("{{h:?}}: net/helper/tray = {{got:?}}, want {{want}}"));
            }}
        }}
    }}
    let alphabet = ['a', '-', '.', '1', 'A', '_'];
    let mut stack: Vec<String> = vec![String::new()];
    while let Some(s) = stack.pop() {{
        let got = (net::valid_host(&s), helper::valid_host(&s), tray::valid_tls_host(&s));
        if got.0 != got.1 || got.1 != got.2 {{
            fails.push(format!("{{s:?}}: net/helper/tray = {{got:?}}"));
        }}
        if s.len() < 5 {{
            for c in alphabet {{ stack.push(format!("{{s}}{{c}}")); }}
        }}
    }}
    if !fails.is_empty() {{
        eprintln!("{{}}", fails.join("\n"));
        std::process::exit(1);
    }}
}}
"#,
        n1 = part(&net, "pub const MAX_HOST_BYTES: usize"),
        n2 = part(&net, "pub fn valid_host("),
        h1 = part(&helper, "pub const MAX_HOST_BYTES: usize"),
        h2 = part(&helper, "pub fn valid_host("),
        t1 = part(&tray, "pub const COLLECTOR_MAX_TLS_HOST_BYTES: usize"),
        t2 = part(&tray, "pub fn valid_tls_host("),
    );
    let dir = std::env::temp_dir().join(format!("cainary-host-validators-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (src, exe) = (dir.join("v.rs"), dir.join("v"));
    fs::write(&src, program).unwrap();
    let build = std::process::Command::new("rustc")
        .args(["--edition", "2024", "-O", "-A", "warnings", "-o"])
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("rustc runs");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = std::process::Command::new(&exe)
        .output()
        .expect("validators run");
    let _ = fs::remove_dir_all(&dir);
    assert!(
        run.status.success(),
        "validators disagree:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

fn hosts_policies() -> (String, String) {
    let dir = crates_dir().join("../packaging/linux/polkit");
    let read = |f: &str| fs::read_to_string(dir.join(f)).expect("read policy");
    (
        read("ua.SkeLLLa.cAInary.hosts.policy"),
        read("ua.SkeLLLa.cAInary.hosts.local.policy"),
    )
}

#[test]
fn hosts_polkit_policies_match_and_are_strict() {
    let (p, l) = hosts_policies();
    assert_clean("hosts polkit policies", check_hosts_policies(&p, &l));
}

mod hosts_helper_fires {
    use super::*;

    fn at(rel: &str, code: &str) -> Vec<Src> {
        vec![Src {
            rel: rel.to_string(),
            code: production_code(code),
            raw: code.to_string(),
        }]
    }

    fn file(code: &str) -> Vec<Src> {
        at(HOSTS_FILE_RS, code)
    }

    #[test]
    fn source_bans_fire() {
        for (rel, code) in [
            (HOSTS_FILE_RS, "let f = File::open(p);"),
            (HOSTS_FILE_RS, "use std::fs;"),
            (HOSTS_FILE_RS, "let o = OpenOptions::new();"),
            (HOSTS_FILE_RS, "libc::open(p, 0);"),
            (HOSTS_FILE_RS, "libc::rename(a, b);"),
            (HOSTS_FILE_RS, "libc::unlink(a);"),
            (HOSTS_FILE_RS, "libc::chmod(a, 0);"),
            (HOSTS_FILE_RS, "libc::stat(a, b);"),
            (HOSTS_FILE_RS, "libc::openat(libc::AT_FDCWD, a, 0);"),
            (HOSTS_FILE_RS, "libc::mkdir(a, 0);"),
            (HOSTS_FILE_RS, "libc::syscall(1);"),
            (HOSTS_FILE_RS, "libc::execve(a, b, c);"),
            (HOSTS_FILE_RS, "let c = Command::new(\"x\");"),
            (HOSTS_FILE_RS, "libc::fork();"),
            (HOSTS_FILE_RS, "libc::getenv(p);"),
            (HOSTS_FILE_RS, "let o = libc::openat(d, c\"passwd\", 0);"),
            (
                HOSTS_FILE_RS,
                "let o = libc::openat(d, c\"etc\", 0); apply_in(a); apply_in(b); apply_in(c);",
            ),
            (HOSTS_FILE_RS, "#[cfg(unix)] fn a() {}"),
            (HOSTS_FILE_RS, "#[cfg(feature = \"x\")] fn a() {}"),
            (HOSTS_FILE_RS, "let a = std::env::var(\"HOME\");"),
            (HOSTS_HELPER_RS, "libc::openat(a, b, 0);"),
            (HOSTS_HELPER_RS, "let _ = std::env::var(\"HOME\");"),
            (HOSTS_HELPER_RS, "let _ = std::env::var_os(\"PKEXEC_UID\");"),
            (
                HOSTS_HELPER_RS,
                "let a = std::env::var(\"PKEXEC_UID\"); let b = std::env::var(\"PKEXEC_UID\");",
            ),
            (HOSTS_HELPER_RS, "let r = file::apply_in(a, b, c);"),
            (HOSTS_HELPER_RS, "let x = c\"hosts\";"),
            (HOSTS_HELPER_RS, "#[cfg(unix)] fn a() {}"),
            (HOSTS_EDIT_RS, "libc::geteuid();"),
            (HOSTS_EDIT_RS, "use std::net::TcpStream;"),
            (HOSTS_SEAM_RS, "libc::openat(a, b, 0);"),
            (HOSTS_MAIN_RS, "#[cfg(unix)] fn main() {}"),
            (HOSTS_MAIN_RS, "let _ = Knobs { uid: 1 };"),
        ] {
            let mut s = at(rel, code);
            // `apply_in` must appear twice in file.rs: give the other cases their pair.
            if rel == HOSTS_FILE_RS && !code.contains("apply_in(") {
                s[0].code
                    .push_str("\nfn apply_in() {} fn a() { apply_in(); }");
            }
            assert!(!check_hosts_helper_source(&s).is_empty(), "{rel}: {code}");
        }
    }

    #[test]
    fn source_allows_what_it_needs() {
        let mut ok = file(
            "fn apply_in() {} fn apply() { apply_in(); }\nlet o = libc::openat(d, c\"etc\", libc::O_PATH | libc::O_NOFOLLOW, 0);\nlibc::unlinkat(d, c\".hosts.cainary-new\", 0);\n// File::open is banned here\n#[cfg(test)]\nmod tests { use std::fs; fn x() { libc::open(a, 0); } }",
        );
        ok.extend(at(
            HOSTS_HELPER_RS,
            "use std::process::exit;\nlet u = std::env::var(\"PKEXEC_UID\");\nlet a = std::env::args_os();\nlibc::geteuid();\nlibc::signal(libc::SIGPIPE, libc::SIG_IGN);",
        ));
        ok.extend(at(
            HOSTS_MAIN_RS,
            "#[cfg(target_os = \"linux\")]\nmod file;\n#[cfg(not(target_os = \"linux\"))]\nfn main() { std::process::exit(2); }",
        ));
        assert_eq!(check_hosts_helper_source(&ok), Vec::<String>::new());
        // The bind helper and every other crate are none of this guard's business.
        assert!(
            check_hosts_helper_source(&at("cainary-bind-helper/src/a.rs", "libc::open(a, 0);"))
                .is_empty()
        );
        // Guards 1 to 3 leave the hosts helper to H5.
        assert!(check_guard1(&file("use std::process::exit;")).is_empty());
        assert!(check_guard2(&file("fd.write(b);")).is_empty());
        let mut s = file("libc::socket(1, 2, 0);");
        s.extend(at(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&s).is_empty());
    }

    const SEAM: &str = "pub struct Knobs { pub uid: u32 }\npub enum Step { A }\n#[cfg(not(test))]\npub fn knobs() -> Knobs {\n    Knobs {\n        uid: 0,\n        gid: 0,\n        lock_deadline: Duration::from_secs(5),\n        max_read: 16 * 1024 * 1024,\n        write_chunk: usize::MAX,\n    }\n}\n#[cfg(not(test))]\npub fn hook(_step: Step, _etc: RawFd) -> Result<(), Fail> {\n    Ok(())\n}\n#[cfg(not(test))]\npub fn crashed() -> bool {\n    false\n}\n#[cfg(not(test))]\npub fn sys(_call: Sys) -> Option<i32> {\n    None\n}\n#[cfg(test)]\npub fn plan() {}\n";

    #[test]
    fn seam_fires() {
        let seam = |code: &str| at(HOSTS_SEAM_RS, code);
        assert_eq!(check_hosts_seam(&seam(SEAM)), Vec::<String>::new());
        for bad in [
            SEAM.replace("uid: 0", "uid: 1000"),
            SEAM.replace("from_secs(5)", "from_secs(500)"),
            SEAM.replace("16 * 1024 * 1024", "1 << 40"),
            SEAM.replace("    Ok(())\n", "    Err(Fail::Busy)\n"),
            SEAM.replace("    false\n", "    true\n"),
            SEAM.replace("    None\n", "    Some(5)\n"),
            SEAM.replace("write_chunk: usize::MAX", "write_chunk: 3"),
            SEAM.replace("#[cfg(test)]\npub fn plan", "pub fn plan"),
            format!("{SEAM}#[cfg(feature = \"x\")]\nfn y() {{}}\n"),
            format!("{SEAM}#[cfg(not(test))]\npub fn extra() {{}}\n"),
        ] {
            assert!(!check_hosts_seam(&seam(&bad)).is_empty(), "{bad}");
        }
        assert!(!check_hosts_seam(&[]).is_empty());
    }

    #[test]
    fn manifest_fires() {
        let ok =
            "[package]\nname = \"h\"\npublish = false\n[dependencies]\nlibc.workspace = true\n";
        assert!(check_manifest_of(HOSTS_HELPER, ok).is_empty());
        for bad in [
            "[package]\npublish = false\n[dependencies]\nserde = \"1\"\n",
            "[package]\npublish = false\n[dev-dependencies]\ntempfile = \"3\"\n",
            "[package]\npublish = true\n",
        ] {
            assert!(!check_manifest_of(HOSTS_HELPER, bad).is_empty(), "{bad}");
        }
    }

    #[test]
    fn closure_fires() {
        let lock = "[[package]]\nname = \"cainary-hosts-helper\"\nversion = \"1\"\ndependencies = [\"libc 0.2.1\"]\n\n\
            [[package]]\nname = \"libc\"\nversion = \"0.2.1\"\n";
        assert!(check_closure_of(HOSTS_HELPER, lock).is_empty());
        let more = lock.replace("[\"libc 0.2.1\"]", "[\"libc 0.2.1\", \"serde\"]");
        assert!(!check_closure_of(HOSTS_HELPER, &more).is_empty());
        // The core and CLI never reach it.
        let core = "[[package]]\nname = \"cainary-core\"\nversion = \"1\"\ndependencies = [\"cainary-hosts-helper\"]\n\n".to_string() + lock;
        assert!(
            check_guard4(&core)
                .iter()
                .any(|b| b.contains("`cainary-core` reaches `cainary-hosts-helper`")),
            "{:?}",
            check_guard4(&core)
        );
    }

    #[test]
    fn copies_fire() {
        let read = |f: &str| fs::read_to_string(crates_dir().join(f)).unwrap();
        let (net, hosts, bind) = (
            read("cainary-net/src/host.rs"),
            read("cainary-hosts-helper/src/helper.rs"),
            read("cainary-bind-helper/src/helper.rs"),
        );
        assert!(check_hosts_copies(&net, &hosts, &bind).is_empty());
        for (a, b) in [
            ("h.len() > MAX_HOST_BYTES", "h.len() >= MAX_HOST_BYTES"),
            ("MAX_HOST_BYTES: usize = 253", "MAX_HOST_BYTES: usize = 254"),
            ("s.len() == 1 ||", "s.len() == 2 ||"),
        ] {
            assert!(hosts.contains(a), "{a}");
            assert!(
                !check_hosts_copies(&net, &hosts.replace(a, b), &bind).is_empty(),
                "{a}"
            );
        }
        assert!(!check_hosts_copies(&net, "", &bind).is_empty());
    }

    #[test]
    fn policies_fire() {
        let (p, l) = hosts_policies();
        assert!(check_hosts_policies(&p, &l).is_empty());
        for (from, to) in [
            ("<allow_active>auth_admin", "<allow_active>yes"),
            ("<allow_any>no", "<allow_any>auth_admin"),
            ("<allow_inactive>no", "<allow_inactive>auth_admin"),
            ("for every user and program", "for you"),
            (" Requested: $(command_line)", ""),
        ] {
            assert!(
                !check_hosts_policies(&p.replace(from, to), &l.replace(from, to)).is_empty(),
                "{to}"
            );
        }
        assert!(!check_hosts_policies(&p.replace(HOSTS_POLICY_PATH, "/tmp/x"), &l).is_empty());
        assert!(
            !check_hosts_policies(&p, &l.replace(HOSTS_POLICY_LOCAL_PATH, HOSTS_POLICY_PATH))
                .is_empty()
        );
        assert!(!check_hosts_policies(&p, &l.replace(".local\"", "\"")).is_empty());
        // Only the message may not drift in one file alone.
        assert!(
            !check_hosts_policies(&p, &l.replace("change /etc/hosts", "change files")).is_empty()
        );
        // The bind policies are not these.
        assert!(
            !check_policies_of(
                HOSTS_POLICY_ID,
                HOSTS_POLICY_PATH,
                HOSTS_POLICY_LOCAL_PATH,
                &fs::read_to_string(
                    crates_dir().join("../packaging/linux/polkit/ua.SkeLLLa.cAInary.policy")
                )
                .unwrap(),
                &fs::read_to_string(
                    crates_dir().join("../packaging/linux/polkit/ua.SkeLLLa.cAInary.local.policy")
                )
                .unwrap()
            )
            .is_empty()
        );
    }
}

#[test]
fn helper_source_stays_inside_its_powers() {
    assert_clean("helper source", check_helper_source(&sources()));
}

#[test]
fn helper_manifest_is_libc_only_and_not_publishable() {
    let manifest = fs::read_to_string(crates_dir().join("cainary-bind-helper/Cargo.toml"))
        .expect("read cainary-bind-helper manifest");
    assert_clean("helper manifest", check_helper_manifest(&manifest));
}

#[test]
fn helper_reaches_only_libc_in_the_lock() {
    let lock = fs::read_to_string(crates_dir().join("../Cargo.lock")).expect("read Cargo.lock");
    assert_clean("helper closure", check_helper_closure(&lock));
}

#[test]
fn polkit_policies_match_and_are_strict() {
    let dir = crates_dir().join("../packaging/linux/polkit");
    let read = |f: &str| fs::read_to_string(dir.join(f)).expect("read policy");
    assert_clean(
        "polkit policies",
        check_policies(
            &read("ua.SkeLLLa.cAInary.policy"),
            &read("ua.SkeLLLa.cAInary.local.policy"),
        ),
    );
}

mod helper_fires {
    use super::*;

    fn helper(code: &str) -> Vec<Src> {
        vec![Src {
            rel: format!("{HELPER_SRC}helper.rs"),
            code: production_code(code),
            raw: code.to_string(),
        }]
    }

    #[test]
    fn source_bans_fire() {
        for code in [
            "use std::process::Command;",
            "let f = std::fs::read(p);",
            "use std::fs as disk;",
            "let f = File::open(p);",
            "let o = OpenOptions::new();",
            "libc::execve(a, b, c);",
            "libc::open(p, 0);",
            "libc::fork();",
            "libc::getenv(p);",
            "let _ = std::env::var(\"HOME\");",
            "let _ = std::env::vars();",
            "let _ = std::env::var_os(\"PKEXEC_UID\");",
            "let a = std::env::var(\"PKEXEC_UID\"); let b = std::env::var(\"PKEXEC_UID\");",
            "libc::setsockopt(fd, 1, libc::SO_REUSEPORT, p, 4);",
            "use std::net::TcpStream;",
        ] {
            assert!(!check_helper_source(&helper(code)).is_empty(), "{code}");
        }
    }

    #[test]
    fn source_allows_what_it_needs() {
        let ok = "use std::process::exit;\nlet u = std::env::var(\"PKEXEC_UID\");\nlet a = std::env::args_os();\nlibc::sendmsg(c, m, 0);\n// File::open is banned here\n#[cfg(test)]\nmod tests { use std::fs; }";
        assert!(check_helper_source(&helper(ok)).is_empty());
        // Guards 1 to 3 leave the helper to H1; other crates are not H1's business.
        assert!(check_guard1(&helper("use std::process::exit;")).is_empty());
        let mut s = helper("libc::socket(1, 2, 0);");
        s.extend(src_at(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&s).is_empty());
        assert!(
            check_helper_source(&src_at("cainary-core/src/a.rs", "std::fs::read(p);")).is_empty()
        );
    }

    fn src_at(rel: &str, code: &str) -> Vec<Src> {
        vec![Src {
            rel: rel.to_string(),
            code: production_code(code),
            raw: code.to_string(),
        }]
    }

    #[test]
    fn manifest_fires() {
        let ok =
            "[package]\nname = \"h\"\npublish = false\n[dependencies]\nlibc.workspace = true\n";
        assert!(check_helper_manifest(ok).is_empty());
        for bad in [
            "[package]\npublish = false\n[dependencies]\nserde = \"1\"\n",
            "[package]\npublish = false\n[dev-dependencies]\ntempfile = \"3\"\n",
            "[package]\npublish = false\n[build-dependencies]\ncc = \"1\"\n",
            "[package]\npublish = false\n[target.'cfg(unix)'.dependencies]\nnix = \"0.29\"\n",
        ] {
            assert!(!check_helper_manifest(bad).is_empty(), "{bad}");
        }
        for no_publish in [
            "[package]\nname = \"h\"\n",
            "[package]\npublish = true\n",
            "[package]\npublish.workspace = true\n",
        ] {
            assert!(
                check_helper_manifest(no_publish)
                    .iter()
                    .any(|b| b.contains("publish")),
                "{no_publish}"
            );
        }
    }

    #[test]
    fn closure_fires() {
        let lock = "[[package]]\nname = \"cainary\"\nversion = \"1\"\ndependencies = [\"cainary-core\"]\n\n\
            [[package]]\nname = \"cainary-core\"\nversion = \"1\"\n\n\
            [[package]]\nname = \"cainary-bind-helper\"\nversion = \"1\"\ndependencies = [\"libc 0.2.1\"]\n\n\
            [[package]]\nname = \"libc\"\nversion = \"0.2.1\"\n";
        assert!(check_guard4(lock).is_empty());
        assert!(check_helper_closure(lock).is_empty());
        let more = lock.replace("[\"libc 0.2.1\"]", "[\"libc 0.2.1\", \"serde\"]");
        assert!(!check_helper_closure(&more).is_empty());
        let core = lock.replace(
            "name = \"cainary-core\"\nversion = \"1\"\n",
            "name = \"cainary-core\"\nversion = \"1\"\ndependencies = [\"cainary-bind-helper\"]\n",
        );
        let bad = check_guard4(&core);
        assert!(
            bad.iter()
                .any(|b| b.contains("`cainary` reaches `cainary-bind-helper`")),
            "{bad:?}"
        );
    }

    fn policies() -> (String, String) {
        let dir = crates_dir().join("../packaging/linux/polkit");
        let read = |f: &str| fs::read_to_string(dir.join(f)).expect("read policy");
        (
            read("ua.SkeLLLa.cAInary.policy"),
            read("ua.SkeLLLa.cAInary.local.policy"),
        )
    }

    #[test]
    fn policies_fire() {
        let (p, l) = policies();
        assert!(check_policies(&p, &l).is_empty());
        for (from, to) in [
            ("<allow_active>auth_admin", "<allow_active>yes"),
            ("<allow_active>auth_admin", "<allow_active>auth_admin_keep"),
            ("<allow_any>no", "<allow_any>auth_admin"),
            ("<allow_inactive>no", "<allow_inactive>auth_admin"),
        ] {
            assert!(
                !check_policies(&p.replace(from, to), &l.replace(from, to)).is_empty(),
                "{to}"
            );
        }
        // Wrong or drifting exec.path or action id, in either file.
        assert!(!check_policies(&p.replace(POLICY_PATH, "/tmp/x"), &l).is_empty());
        assert!(!check_policies(&p, &l.replace(POLICY_LOCAL_PATH, POLICY_PATH)).is_empty());
        assert!(!check_policies(&p, &l.replace(".local\"", "\"")).is_empty());
        // The two files may differ only in id and path.
        let tweaked = l.replace("Reserve", "Grab");
        assert!(!check_policies(&p, &tweaked).is_empty());
        assert!(!check_policies("<policyconfig>", &l).is_empty());
    }
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
            raw: code.to_string(),
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

    fn net(rel: &str, code: &str) -> Vec<Src> {
        src(&format!("cainary-net/src/{rel}"), code)
    }

    #[test]
    fn guards_1_to_3_leave_the_net_crate_to_its_own_rules() {
        let s = net(
            "server.rs",
            "use std::net::TcpListener;\nlet f = OpenOptions::new();",
        );
        assert!(check_guard1(&s).is_empty());
        assert!(check_guard2(&s).is_empty());
    }

    #[test]
    fn n1_std_net_outside_server() {
        for rel in ["output.rs", "args.rs", "main.rs", "redflag/mod.rs"] {
            assert_eq!(
                check_n1(&net(rel, "use std::net::IpAddr;")).len(),
                1,
                "{rel}"
            );
        }
        assert_eq!(check_n1(&net("otlp.rs", "use std::{io, net};")).len(), 1);
        assert!(check_n1(&net("server.rs", "use std::net::TcpListener;")).is_empty());
    }

    #[test]
    fn n1_no_outbound_calls_anywhere() {
        for call in [
            "let s = TcpStream::connect(a);",
            "sock.connect(addr);",
            "TcpStream :: connect_timeout(&a, d);",
            "let u = UdpSocket::bind(a);",
            "use std::net::ToSocketAddrs;",
            "let a = host.to_socket_addrs();",
            "let s = std::os::unix::net::UnixStream::connect(p);",
        ] {
            assert!(!check_n1(&net("server.rs", call)).is_empty(), "{call}");
            assert!(!check_n1(&net("otlp.rs", call)).is_empty(), "{call}");
        }
        assert!(check_n1(&net("server.rs", "let l = TcpListener::bind(addr);")).is_empty());
        assert!(
            check_n1(&net(
                "server.rs",
                "let max_connections = 1; let c = connection;"
            ))
            .is_empty()
        );
        assert!(
            check_n1(&net(
                "output.rs",
                "use cainary_core::value as v; use serde_json::Value as V;"
            ))
            .is_empty()
        );
        // Other crates are not N1's business.
        assert!(check_n1(&src("cainary-core/src/analysis.rs", "x.connect(a);")).is_empty());
    }

    #[test]
    fn n1_aliases_cannot_hide_a_dial() {
        for code in [
            "use std::net::TcpStream as S;\nlet s = S::connect(a);",
            "type S = std::net::TcpStream;\nlet s = S::connect(a);",
            "use std::net as n;\nlet s = n::TcpStream::connect(a);",
            "use std as s;\nlet x = s::net::TcpStream::connect(a);",
            "extern crate std as s;",
            "use core::net::SocketAddr;",
            "use ::std::net::TcpStream as T;",
            "let s = <TcpStream>::connect(a);",
            "let f = TcpStream::connect;",
            "let s = std::net::TcpStream::connect_timeout(&a, d);",
            "use std::net::{TcpStream as S};",
            "pub use std::net as n;",
        ] {
            assert!(!check_n1(&net("server.rs", code)).is_empty(), "{code}");
            assert!(!check_n1(&net("otlp.rs", code)).is_empty(), "{code}");
        }
    }

    #[test]
    fn n2_fs_env_process_and_writes() {
        assert_eq!(check_n2(&net("output.rs", "use std::fs;")).len(), 1);
        assert_eq!(
            check_n2(&net("server.rs", "let a = std::env::args();")).len(),
            1
        );
        assert_eq!(
            check_n2(&net("args.rs", "use std::process::exit;")).len(),
            1
        );
        assert_eq!(
            check_n2(&net("redflag/mod.rs", "use std::{fs, io};")).len(),
            1
        );
        assert!(check_n2(&net("logfile.rs", "use std::fs::File;")).is_empty());
        assert!(check_n2(&net("redflag/file.rs", "std::fs::File::open(p);")).is_empty());
        assert!(check_n2(&net("main.rs", "std::env::args(); std::process::exit(0);")).is_empty());
        // main.rs doesn't get the file system, redflag/file.rs doesn't get the environment.
        assert_eq!(check_n2(&net("main.rs", "use std::fs;")).len(), 1);
        assert_eq!(
            check_n2(&net("redflag/file.rs", "std::env::var(x);")).len(),
            1
        );
        // The file reader reads only.
        assert_eq!(
            check_n2(&net("redflag/file.rs", "let f = OpenOptions::new();")).len(),
            1
        );
        assert_eq!(
            check_n2(&net("redflag/file.rs", "std::fs::write(p, b);")).len(),
            1
        );
        assert_eq!(
            check_n2(&net("otlp.rs", "let f = OpenOptions::new();")).len(),
            1
        );
        // Socket writes are fine where there is no file access to misuse.
        assert!(check_n2(&net("server.rs", "stream.write(b)")).is_empty());
        assert!(check_n2(&net("tls/mod.rs", "inner.write(b)")).is_empty());
        assert!(!check_n2(&net("server.rs", "OpenOptions::new()")).is_empty());
        assert!(!check_n2(&net("server.rs", "std::fs::write(p, b)")).is_empty());
        assert!(!check_n2(&net("tls/mod.rs", "std::fs::remove_file(p)")).is_empty());
        for m in WRITE_SHAPED {
            assert_eq!(
                check_n2(&net("output.rs", &format!("x{m}y"))).len(),
                1,
                "{m}"
            );
            assert!(
                check_n2(&net("logfile.rs", &format!("x{m}y"))).is_empty(),
                "{m}"
            );
        }
    }

    #[test]
    fn n3_no_command_and_libc_only_in_logfile() {
        assert_eq!(
            check_n3(&net("server.rs", "let c = Command::new(\"ls\");")).len(),
            1
        );
        assert_eq!(
            check_n3(&net("main.rs", "use std::process::Command as C;")).len(),
            1
        );
        assert_eq!(
            check_n3(&net("otlp.rs", "let n = libc::getuid();")).len(),
            1
        );
        assert!(check_n3(&net("logfile.rs", "let n = libc::geteuid();")).is_empty());
        assert!(check_n3(&net("listenfd.rs", "libc::getsockopt(fd);")).is_empty());
        assert_eq!(check_n3(&net("args.rs", "libc::getsockopt(fd);")).len(), 1);
        // Guard 3 also stops libc and counts Command::new across the whole workspace.
        let mut s = net("server.rs", "libc::getuid();");
        s.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert_eq!(check_guard3(&s).len(), 1);
        let mut s = net("logfile.rs", "libc::geteuid();");
        s.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&s).is_empty());
        let mut s = net("server.rs", "Command::new(\"ls\");");
        s.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(!check_guard3(&s).is_empty());
    }

    const NET_OK: &str = "[package]\nname = \"cainary-net\"\npublish = false\n[dependencies]\nregex.workspace = true\nserde_json.workspace = true\n";

    #[test]
    fn n4_manifests() {
        let plain = "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n";
        assert!(check_n4(plain, plain, NET_OK).is_empty());
        let bad = check_n4(
            "[dependencies]\ncainary-net = { path = \"../cainary-net\" }",
            plain,
            NET_OK,
        );
        assert_eq!(bad.len(), 1);
        assert_eq!(check_n4(plain, "# uses cainary-net", NET_OK).len(), 1);
        let extra = format!("{NET_OK}reqwest = \"1\"\n");
        assert!(check_n4(plain, plain, &extra)[0].contains("reqwest"));
        let dev = format!("{NET_OK}[dev-dependencies]\nureq = \"1\"\n");
        assert!(check_n4(plain, plain, &dev)[0].contains("ureq"));
        let target = format!("{NET_OK}[target.'cfg(unix)'.dependencies]\nhyper = \"1\"\n");
        assert!(check_n4(plain, plain, &target)[0].contains("hyper"));
        let build = format!("{NET_OK}[build-dependencies]\ncc = \"1\"\n");
        assert!(check_n4(plain, plain, &build)[0].contains("cc"));
        for no_publish in [
            "[package]\nname = \"cainary-net\"\n[dependencies]\nregex = \"1\"\n",
            "[package]\nname = \"cainary-net\"\npublish = true\n",
            "[package]\nname = \"cainary-net\"\npublish.workspace = true\n",
        ] {
            assert!(
                check_n4(plain, plain, no_publish)
                    .iter()
                    .any(|b| b.contains("publish")),
                "{no_publish}"
            );
        }
    }

    #[test]
    fn sig_manifest_dependency_entries_fire() {
        for manifest in [
            "[package]\nname = \"cainary-sig\"\npublish = false\n[dependencies]\nserde = \"1\"\n",
            "[package]\nname = \"cainary-sig\"\npublish = false\n[build-dependencies]\ncc = \"1\"\n",
            "[package]\nname = \"cainary-sig\"\npublish = false\n[target.'cfg(unix)'.dependencies]\nserde = \"1\"\n",
        ] {
            assert!(
                check_sig_manifest(manifest)
                    .iter()
                    .any(|b| b.contains("no dependencies")),
                "{manifest}"
            );
        }
    }

    #[test]
    fn sig_manifest_publish_guard_fires() {
        let manifest = "[package]\nname = \"cainary-sig\"\npublish = true\n";
        assert!(
            check_sig_manifest(manifest)
                .iter()
                .any(|b| b.contains("publish = false"))
        );
    }

    const LOCK: &str = "[[package]]\nname = \"cainary\"\nversion = \"1\"\ndependencies = [\"cainary-core\", \"serde_json 1.0.0\"]\n\n\
        [[package]]\nname = \"cainary-core\"\nversion = \"1\"\ndependencies = [\"serde_json 1.0.0\"]\n\n\
        [[package]]\nname = \"serde_json\"\nversion = \"1.0.0\"\ndependencies = [\"memchr\"]\n\n\
        [[package]]\nname = \"memchr\"\nversion = \"2\"\n\n\
        [[package]]\nname = \"cainary-net\"\nversion = \"1\"\ndependencies = [\"cainary-core\", \"regex\"]\n\n\
        [[package]]\nname = \"cainary-sig\"\nversion = \"1\"\n\n\
        [[package]]\nname = \"regex\"\nversion = \"1\"\ndependencies = [\"regex-automata\", \"aho-corasick 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\"]\n\n\
        [[package]]\nname = \"regex-automata\"\nversion = \"1\"\ndependencies = [\"memchr\"]\n\n\
        [[package]]\nname = \"aho-corasick\"\nversion = \"1.0.0\"\ndependencies = [\"memchr\"]\n";

    #[test]
    fn net_only_packages_are_allowed_in_the_lock_but_not_reachable_from_the_core() {
        assert!(check_guard4(LOCK).is_empty(), "{:?}", check_guard4(LOCK));
    }

    #[test]
    fn closure_fires_when_the_core_or_cli_reaches_a_net_only_package() {
        // Directly, and through a third package.
        let direct = LOCK.replace("dependencies = [\"serde_json 1.0.0\"]\n\n[[package]]\nname = \"serde_json\"", "dependencies = [\"serde_json 1.0.0\", \"regex\"]\n\n[[package]]\nname = \"serde_json\"");
        let bad = check_guard4(&direct);
        assert!(
            bad.iter()
                .any(|b| b.contains("`cainary-core` reaches `regex`")),
            "{bad:?}"
        );
        assert!(
            bad.iter()
                .any(|b| b.contains("`cainary` reaches `regex-automata`")),
            "{bad:?}"
        );
        let indirect = LOCK.replace(
            "dependencies = [\"memchr\"]\n\n[[package]]\nname = \"memchr\"",
            "dependencies = [\"memchr\", \"aho-corasick\"]\n\n[[package]]\nname = \"memchr\"",
        );
        assert!(
            check_guard4(&indirect)
                .iter()
                .any(|b| b.contains("aho-corasick"))
        );
        let cli_only = LOCK.replace(
            "dependencies = [\"cainary-core\", \"serde_json 1.0.0\"]",
            "dependencies = [\"cainary-core\", \"regex\"]",
        );
        assert!(
            check_guard4(&cli_only)
                .iter()
                .any(|b| b.contains("`cainary` reaches `regex`"))
        );
        // Net may of course use them, and the net crate reaching core is fine.
        assert!(!check_guard4(LOCK).iter().any(|b| b.contains("cainary-net")));
    }

    #[test]
    fn sig_only_closure_fires_for_the_core_or_cli() {
        let core = LOCK.replace(
            "dependencies = [\"serde_json 1.0.0\"]\n\n[[package]]\nname = \"serde_json\"",
            "dependencies = [\"serde_json 1.0.0\", \"cainary-sig\"]\n\n[[package]]\nname = \"serde_json\"",
        );
        assert!(
            check_guard4(&core)
                .iter()
                .any(|b| b.contains("`cainary-core` reaches `cainary-sig`"))
        );

        let cli = LOCK.replace(
            "dependencies = [\"cainary-core\", \"serde_json 1.0.0\"]",
            "dependencies = [\"cainary-core\", \"serde_json 1.0.0\", \"cainary-sig\"]",
        );
        assert!(
            check_guard4(&cli)
                .iter()
                .any(|b| b.contains("`cainary` reaches `cainary-sig`"))
        );
    }

    #[test]
    fn unknown_package_still_fires_next_to_net_only_ones() {
        let lock = format!("{LOCK}\n[[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\n");
        let bad = check_guard4(&lock);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("reqwest"));
    }

    #[test]
    fn closure_rules_are_a_table() {
        // A third set is one more row: this checks the walk on a made-up one.
        let graph = lock_graph(LOCK);
        let reach = closure(&graph, "cainary-net");
        for n in [
            "cainary-core",
            "regex",
            "regex-automata",
            "aho-corasick",
            "memchr",
            "serde_json",
        ] {
            assert!(reach.iter().any(|r| r == n), "{n}");
        }
        assert!(!closure(&graph, "cainary").iter().any(|r| r == "regex"));
    }

    #[test]
    fn tls_allowances_are_exact() {
        // tls/ca_file.rs may use fs, OpenOptions, writes and libc; the rest of tls/ may not.
        let code =
            "use std::fs;\nlet f = OpenOptions::new(); std::fs::write(p, b); libc::flock(1, 2);";
        assert!(check_n2(&net("tls/ca_file.rs", code)).is_empty());
        assert!(check_n3(&net("tls/ca_file.rs", "libc::flock(1, 2);")).is_empty());
        assert!(!check_n2(&net("tls/mod.rs", "use std::fs;")).is_empty());
        assert!(!check_n2(&net("tls/leaf.rs", "let f = OpenOptions::new();")).is_empty());
        assert!(!check_n3(&net("tls/mod.rs", "libc::getuid();")).is_empty());
        assert!(check_n3(&net("privdrop.rs", "libc::prctl(1, 2);")).is_empty());
        // privdrop.rs gets libc and nothing else.
        assert!(!check_n2(&net("privdrop.rs", "use std::fs;")).is_empty());
        let mut s = net("tls/ca_file.rs", "libc::flock(1, 2);");
        s.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&s).is_empty());
        // Nobody else gets the CA writer's powers, and std::net stays in server.rs.
        assert!(!check_n2(&net("tls/ca.rs", "use std::fs::File;")).is_empty());
        assert!(!check_n1(&net("tls/mod.rs", "use std::net::TcpStream;")).is_empty());
        assert!(!check_n1(&net("tls/mod.rs", "let s = TcpStream::connect(a);")).is_empty());
    }

    #[test]
    fn n5_tls_crates_outside_tls_need_the_feature_gate() {
        let gated = "#[cfg(feature = \"tls\")]\nuse rustls::ServerConfig;\n#[cfg(feature = \"tls\")]\npub mod tls;";
        assert!(check_tls_paths(&net("lib.rs", gated)).is_empty());
        assert!(check_tls_paths(&net("tls/mod.rs", "use rustls::ServerConfig;")).is_empty());
        for bad in [
            "use rustls::ServerConfig;",
            "pub mod tls;",
            "let k = rcgen::KeyPair::generate();",
            "use ring::digest;",
            "#[cfg(feature = \"other\")]\nuse rustls::Error;",
            "#[cfg(not(feature = \"tls\"))]\nuse rustls::Error;",
        ] {
            assert!(!check_tls_paths(&net("server.rs", bad)).is_empty(), "{bad}");
        }
        // Other crates are not N5's business.
        assert!(check_tls_paths(&src("cainary-core/src/analysis.rs", "use ring::x;")).is_empty());
    }

    #[test]
    fn tls_only_closure_and_allowlist() {
        let lock = format!(
            "{LOCK}\n[[package]]\nname = \"rustls\"\nversion = \"0.23.0\"\ndependencies = [\"ring\"]\n\n\
             [[package]]\nname = \"ring\"\nversion = \"0.17.0\"\n\n\
             [[package]]\nname = \"cainary-net\"\nversion = \"1\"\ndependencies = [\"cainary-core\", \"regex\", \"rustls\"]\n"
        )
        .replace(
            "[[package]]\nname = \"cainary-net\"\nversion = \"1\"\ndependencies = [\"cainary-core\", \"regex\"]\n\n",
            "",
        );
        assert!(check_guard4(&lock).is_empty(), "{:?}", check_guard4(&lock));
        // The CLI or core reaching ring, directly or through rustls, fires.
        let direct = lock.replace(
            "name = \"cainary-core\"\nversion = \"1\"\ndependencies = [\"serde_json 1.0.0\"]",
            "name = \"cainary-core\"\nversion = \"1\"\ndependencies = [\"serde_json 1.0.0\", \"ring\"]",
        );
        let bad = check_guard4(&direct);
        assert!(
            bad.iter()
                .any(|b| b.contains("`cainary-core` reaches `ring`")),
            "{bad:?}"
        );
        assert!(
            bad.iter().any(|b| b.contains("`cainary` reaches `ring`")),
            "{bad:?}"
        );
        let via = lock.replace(
            "name = \"serde_json\"\nversion = \"1.0.0\"\ndependencies = [\"memchr\"]",
            "name = \"serde_json\"\nversion = \"1.0.0\"\ndependencies = [\"memchr\", \"rustls\"]",
        );
        assert!(
            check_guard4(&via)
                .iter()
                .any(|b| b.contains("rustls") && b.contains("TLS_ONLY"))
        );
        // aws-lc-rs is in no set.
        let aws = format!("{lock}\n[[package]]\nname = \"aws-lc-rs\"\nversion = \"1\"\n");
        assert!(check_guard4(&aws).iter().any(|b| b.contains("aws-lc-rs")));
    }

    #[test]
    fn n4_allows_the_tls_deps_only_as_named() {
        let plain = "[package]\nname = \"x\"\n";
        let ok = format!(
            "{NET_OK}rustls = {{ workspace = true, optional = true }}\nrcgen = {{ workspace = true, optional = true }}\ntime = {{ workspace = true, optional = true }}\n"
        );
        assert!(check_n4(plain, plain, &ok).is_empty());
        let aws = format!("{NET_OK}aws-lc-rs = \"1\"\n");
        assert!(check_n4(plain, plain, &aws)[0].contains("aws-lc-rs"));
        let ring = format!("{NET_OK}ring = \"0.17\"\n");
        assert!(check_n4(plain, plain, &ring)[0].contains("ring"));
    }

    #[test]
    fn production_code_after_a_test_module_is_caught() {
        let one = |code: &str| {
            vec![Src {
                rel: "cainary-net/src/x.rs".into(),
                code: production_code(code),
                raw: code.to_string(),
            }]
        };
        let ok = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n#[cfg(test)]\nmod more {\n}\n#[cfg(test)]\nfn helper() {}\n";
        assert!(check_tests_last(&one(ok)).is_empty());
        for bad in [
            "fn a() {}\n#[cfg(test)]\nmod tests {\n}\n\npub fn takeover() {}\n",
            "#[cfg(test)]\nmod tests {\n}\nimpl X {}\n",
            "#[cfg(test)]\nmod tests {\n}\n\n/// doc\nconst K: u8 = 1;\n",
            "#[cfg(test)]\nmod tests {\n}\nuse std::fs;\n",
        ] {
            assert_eq!(check_tests_last(&one(bad)).len(), 1, "{bad}");
        }
        // An attribute on a single test-only item before the module doesn't end production code.
        assert!(
            check_tests_last(&one("#[cfg(test)]\nfn only_in_tests() {}\nfn prod() {}\n"))
                .is_empty()
        );
        // And the hidden code really is invisible to the other guards: that's the point.
        let hidden = "#[cfg(test)]\nmod tests {\n}\npub fn sneaky() { std::fs::write(a, b); }\n";
        assert!(!production_code(hidden).contains("sneaky"));
        assert!(!check_tests_last(&one(hidden)).is_empty());
    }

    #[test]
    fn trust_files_rs_is_the_one_extra_writer() {
        let code = "use std::fs::File;\nlet f = OpenOptions::new(); std::fs::write(p, b); libc::openat(1, p, 2);";
        assert!(check_n2(&net("trust/files.rs", code)).is_empty());
        assert!(check_n3(&net("trust/files.rs", "libc::renameat(1, a, 1, b);")).is_empty());
        let mut s = net("trust/files.rs", "libc::unlinkat(1, a, 0);");
        s.extend(src(PLATFORM_RS, "Command::new(\"/usr/sbin/scutil\");"));
        assert!(check_guard3(&s).is_empty());
        // Nobody else gets the same powers, not even the rest of `trust/`, and trust/files.rs gets
        // no network or process access.
        for rel in [
            "setup.rs",
            "output.rs",
            "args.rs",
            "otlp.rs",
            "tls/leaf.rs",
            "trust.rs",
            "trust/mod.rs",
            "trust/claude.rs",
            "trust/codex.rs",
            "trust/state.rs",
            "trust/bundle.rs",
        ] {
            assert!(
                !check_n2(&net(rel, "use std::fs::File;")).is_empty(),
                "{rel}"
            );
            assert!(
                !check_n2(&net(rel, "let f = OpenOptions::new();")).is_empty(),
                "{rel}"
            );
            assert!(
                !check_n3(&net(rel, "libc::unlinkat(1, a, 0);")).is_empty(),
                "{rel}"
            );
        }
        assert!(!check_n2(&net("trust/files.rs", "use std::process::exit;")).is_empty());
        assert!(!check_n2(&net("trust/files.rs", "let a = std::env::args();")).is_empty());
        assert!(!check_n1(&net("trust/files.rs", "use std::net::TcpStream;")).is_empty());
        assert!(!check_n3(&net("trust/files.rs", "let c = Command::new(\"ls\");")).is_empty());
    }
}
