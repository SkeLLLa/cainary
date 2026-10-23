//! Dependency and source guards for the Linux workspace (linux-plan §8).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::Value;

const DIRECT_DEPENDENCIES: &[&str] = &[
    "async-io",
    "async-channel",
    "cc",
    "cainary-tray-dbus",
    "cainary-tray-model",
    "cxx",
    "cxx-qt",
    "cxx-qt-build",
    "cxx-qt-lib",
    "futures-lite",
    "ksni",
    "libc",
    "serde",
    "serde_json",
    "toml",
    "wayland-client",
    "zbus",
];

const DENIED_PACKAGES: &[&str] = &[
    "gtk",
    "gdk",
    "glib",
    "gio",
    "gobject",
    "pango",
    "cairo",
    "atk",
    "appindicator",
    "libappindicator",
    "ayatana",
    "rfd",
    "tray-icon",
    "muda",
    "webkit",
    "wry",
    "tokio",
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "isahc",
    "h2",
    "rustls",
    "openssl",
    "native-tls",
    "tungstenite",
    "webbrowser",
];

const WRITE_FILES: &[&str] = &[
    "crates/tray-model/src/settings.rs",
    "crates/tray-model/src/autostart.rs",
];

const WRITE_MARKERS: &[&str] = &[
    "OpenOptions::new",
    "DirBuilder::new",
    "fs::write(",
    "fs::create_dir",
    "fs::remove_file(",
    "fs::rename(",
    ".write_all(",
    ".write(",
    "File::create(",
    "File::options(",
    "OpenOptions",
    "create_new(",
    "fs::copy(",
    "fs::hard_link(",
    "fs::set_permissions(",
    "set_permissions(",
    "remove_dir(",
    "remove_dir_all(",
    "symlink(",
];

/// Names that must not be imported from `std::fs` outside the approved modules: a bare
/// `write(path, …)` or `copy(…)` after such an import would dodge the `fs::` markers.
const FS_WRITE_IMPORTS: &[&str] = &[
    "write",
    "copy",
    "rename",
    "hard_link",
    "set_permissions",
    "remove_file",
    "remove_dir",
    "remove_dir_all",
    "create_dir",
    "create_dir_all",
    "File",
    "OpenOptions",
    "*",
];

/// Process-creation and shell APIs that may not appear anywhere in production code.
const PROCESS_MARKERS: &[&str] = &[
    "libc::system",
    "libc::popen",
    "libc::fork",
    "libc::vfork",
    "libc::exec",
    "posix_spawn",
    ".exec(",
    "Command::from",
];

/// Native sources (C++ and QML) may not start processes or shells.
const NATIVE_PROCESS_CALLS: &[&str] = &[
    "QProcess",
    "system",
    "popen",
    "fork",
    "vfork",
    "execv",
    "execl",
    "posix_spawn",
];

const SCANNING_PATHS: &[&str] = &[
    ".claude/",
    "/.claude",
    "/etc/claude-code",
    "managed-settings.json",
    "claude_desktop_config.json",
];

struct Source {
    path: String,
    code: String,
}

fn linux_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cainary-tray crate is under linux/crates/")
        .to_path_buf()
}

/// The source without comments and without `#[cfg(test)] mod … { … }` bodies. Only the test
/// module is dropped, so production code after it is still scanned.
fn production_code(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut code = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.trim() == "#[cfg(test)]" {
            let next = (index + 1..lines.len()).find(|&i| {
                let trimmed = lines[i].trim();
                !trimmed.is_empty() && !trimmed.starts_with("#[")
            });
            if let Some(start) = next.filter(|&i| is_module(lines[i])) {
                index = skip_module(&lines, start);
                continue;
            }
        }
        if !line.trim_start().starts_with("//") {
            code.push(line);
        }
        index += 1;
    }
    code.join("\n")
}

fn is_module(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("mod ") || line.starts_with("pub mod ") || line.starts_with("pub(crate) mod ")
}

/// The index of the first line after the module that starts at `start` (`mod x;` is one line;
/// `mod x { … }` ends where its braces balance; braces in strings, chars and comments don't count).
fn skip_module(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i64;
    let mut opened = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    for (offset, line) in lines[start..].iter().enumerate() {
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if in_block_comment {
                if c == '*' && chars.get(i + 1) == Some(&'/') {
                    in_block_comment = false;
                    i += 1;
                }
            } else if in_string {
                if c == '\\' {
                    i += 1;
                } else if c == '"' {
                    in_string = false;
                }
            } else if c == '/' && chars.get(i + 1) == Some(&'/') {
                break;
            } else if c == '/' && chars.get(i + 1) == Some(&'*') {
                in_block_comment = true;
                i += 1;
            } else if c == '"' {
                in_string = true;
            } else if c == '\'' {
                // A char literal ('{', '\n', '\''); a lifetime has no closing quote that soon.
                let close = if chars.get(i + 1) == Some(&'\\') {
                    i + 3
                } else {
                    i + 2
                };
                if chars.get(close) == Some(&'\'') {
                    i = close;
                }
            } else if c == '{' {
                depth += 1;
                opened = true;
            } else if c == '}' {
                depth -= 1;
            }
            i += 1;
        }
        // A string left open at the end of a line continues on the next one, as Rust allows.
        if (opened && depth <= 0) || (!opened && line.trim_end().ends_with(';')) {
            return start + offset + 1;
        }
    }
    lines.len()
}

fn collect_sources(dir: &Path, root: &Path, output: &mut Vec<Source>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_sources(&path, root, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            output.push(Source {
                path: path
                    .strip_prefix(root)
                    .expect("source is under linux/")
                    .to_string_lossy()
                    .replace('\\', "/"),
                code: production_code(&source),
            });
        }
    }
}

fn sources() -> Vec<Source> {
    let root = linux_root();
    let crates = root.join("crates");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .expect("read linux/crates")
        .map(|entry| entry.expect("crate directory").path())
        .filter(|path| path.join("src").is_dir())
        .collect();
    dirs.sort();
    let mut output = Vec::new();
    for dir in dirs {
        collect_sources(&dir.join("src"), &root, &mut output);
    }
    output
}

fn dependency_tables(manifest: &Value) -> Vec<&toml::Table> {
    let mut tables = Vec::new();
    for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(table) = manifest.get(key).and_then(Value::as_table) {
            tables.push(table);
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for target in targets.values().filter_map(Value::as_table) {
            for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(table) = target.get(key).and_then(Value::as_table) {
                    tables.push(table);
                }
            }
        }
    }
    tables
}

fn manifest_dependencies(manifest: &Value) -> Vec<String> {
    dependency_tables(manifest)
        .into_iter()
        .flat_map(|table| table.keys().cloned())
        .collect()
}

fn denied(name: &str) -> bool {
    DENIED_PACKAGES.iter().any(|prefix| {
        name == *prefix || name.starts_with(&format!("{prefix}-")) || name.starts_with(prefix)
    })
}

#[test]
fn guard_l1_direct_dependencies_are_allowlisted() {
    let root = linux_root();
    let crates = root.join("crates");
    let dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .expect("read linux/crates")
        .map(|entry| entry.expect("crate directory").path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    let mut unexpected = Vec::new();
    for dir in dirs {
        let path = dir.join("Cargo.toml");
        let manifest: Value = toml::from_str(&fs::read_to_string(&path).expect("read manifest"))
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        for dependency in manifest_dependencies(&manifest) {
            if !DIRECT_DEPENDENCIES.contains(&dependency.as_str()) {
                unexpected.push(format!("{}: {dependency}", path.display()));
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "L1 direct dependency allowlist exceeded:\n  {}",
        unexpected.join("\n  ")
    );
}

#[test]
fn guard_l2_normal_build_tree_and_lock_have_no_denied_crates() {
    let root = linux_root();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--manifest-path",
            root.join("Cargo.toml").to_string_lossy().as_ref(),
            "-e",
            "normal,build",
            "--prefix",
            "none",
        ])
        .output()
        .expect("run cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8(output.stdout).expect("cargo tree output is UTF-8");
    let bad_tree: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| denied(name))
        .collect();
    assert!(
        bad_tree.is_empty(),
        "L2 denied crates in cargo tree: {bad_tree:?}"
    );

    let lock: Value = toml::from_str(
        &fs::read_to_string(root.join("Cargo.lock")).expect("read linux/Cargo.lock"),
    )
    .expect("linux/Cargo.lock parses as TOML");
    let bad_lock: Vec<String> = lock
        .get("package")
        .and_then(Value::as_array)
        .expect("Cargo.lock has [[package]] entries")
        .iter()
        .filter_map(|package| package.get("name").and_then(Value::as_str))
        .filter(|name| denied(name))
        .map(str::to_owned)
        .collect();
    assert!(
        bad_lock.is_empty(),
        "L2 denied crates in Cargo.lock: {bad_lock:?}"
    );
}

#[test]
fn guard_l3_process_network_writes_and_scanning_paths_are_confined() {
    let mut violations = Vec::new();
    let mut process_creations = Vec::new();
    for source in sources() {
        let compact = source.code.split_whitespace().collect::<Vec<_>>().join(" ");
        if compact.contains("std::net") || compact.contains("std::{net") {
            violations.push(format!("{}: std::net usage", source.path));
        }
        if compact.contains("Command as") {
            violations.push(format!("{}: Command imported under an alias", source.path));
        }
        // The one `.exec(` that is not a process call: Qt's event loop in app.rs.
        let process_view = if source.path == "crates/cainary-tray/src/app.rs" {
            compact.replace("application.pin_mut().exec()", "")
        } else {
            compact.clone()
        };
        for marker in PROCESS_MARKERS {
            if process_view.contains(marker) {
                violations.push(format!("{}: forbidden process API {marker:?}", source.path));
            }
        }
        // `process_group` needs the extension trait; nothing else may use it.
        if compact.contains("CommandExt") && source.path != "crates/tray-model/src/runner.rs" {
            violations.push(format!("{}: CommandExt outside runner.rs", source.path));
        }
        if compact.contains("Command::new") {
            process_creations.push(source.path.clone());
            if source.path != "crates/tray-model/src/runner.rs" {
                violations.push(format!(
                    "{}: process creation outside runner.rs",
                    source.path
                ));
            }
        }
        if !WRITE_FILES.iter().any(|path| *path == source.path) {
            if compact.contains("std::fs as") || imports_fs_write(&compact) {
                violations.push(format!(
                    "{}: filesystem write function imported from std::fs",
                    source.path
                ));
            }
            for marker in WRITE_MARKERS {
                if !compact.contains(marker) {
                    continue;
                }
                let allowed_child_stdin_write =
                    *marker == ".write(" && allowed_child_stdin_write(&source.path, &compact);
                if !allowed_child_stdin_write {
                    violations.push(format!(
                        "{}: filesystem write outside the approved modules",
                        source.path
                    ));
                }
            }
        }
        for literal in SCANNING_PATHS {
            if source.code.contains(literal) {
                violations.push(format!(
                    "{}: forbidden scanner path literal {literal:?}",
                    source.path
                ));
            }
        }
    }
    if process_creations != ["crates/tray-model/src/runner.rs"] {
        violations.push(format!(
            "Command::new must appear only in tray-model/src/runner.rs; found {process_creations:?}"
        ));
    }
    assert!(
        violations.is_empty(),
        "L3 source guard failed:\n  {}",
        violations.join("\n  ")
    );
}

/// Whether `code` brings a writing function (or a glob) into scope with `use std::fs::…`.
fn imports_fs_write(code: &str) -> bool {
    let mut rest = code;
    while let Some(at) = rest.find("use std::fs::") {
        let after = &rest[at + "use std::fs::".len()..];
        let statement = after.split(';').next().unwrap_or("");
        let names: Vec<&str> = statement
            .trim_matches(|c| c == '{' || c == '}' || c == ' ')
            .split(',')
            .map(|name| {
                name.trim()
                    .trim_matches(|c| c == '{' || c == '}' || c == ' ')
            })
            .collect();
        if names.iter().any(|name| {
            let name = name.split(" as ").next().unwrap_or(name).trim();
            FS_WRITE_IMPORTS.contains(&name)
        }) {
            return true;
        }
        rest = after;
    }
    false
}

fn allowed_child_stdin_write(path: &str, code: &str) -> bool {
    path == "crates/tray-model/src/runner.rs"
        && code.contains("stdin.write(self.stdin_bytes)")
        && code.matches(".write(").count() == 1
}

fn native_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, output: &mut Vec<(String, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.map(|entry| entry.expect("entry").path()).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, root, output);
            } else if path
                .extension()
                .is_some_and(|ext| ["cpp", "h", "qml"].iter().any(|want| ext == *want))
            {
                let text = fs::read_to_string(&path).expect("read native source");
                let code: Vec<&str> = text
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .collect();
                output.push((
                    path.strip_prefix(root)
                        .expect("under linux/")
                        .to_string_lossy()
                        .into_owned(),
                    code.join("\n"),
                ));
            }
        }
    }
    let root = linux_root();
    let mut output = Vec::new();
    walk(&root.join("crates/cainary-tray/cpp"), &root, &mut output);
    walk(&root.join("crates/cainary-tray/qml"), &root, &mut output);
    output
}

/// True when `name` appears as a call or type, not as part of a longer identifier.
fn mentions_call(code: &str, name: &str) -> bool {
    code.match_indices(name).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + name.len()..].chars().next();
        let ident = |c: char| c.is_alphanumeric() || c == '_';
        !before.is_some_and(ident)
            && (name == "QProcess" || after == Some('('))
            && !before.is_some_and(|c| c == '.')
    })
}

#[test]
fn guard_l3_native_sources_start_no_processes() {
    let sources = native_sources();
    assert!(!sources.is_empty(), "no C++ or QML sources found");
    let mut violations = Vec::new();
    for (path, code) in &sources {
        for call in NATIVE_PROCESS_CALLS {
            if mentions_call(code, call) {
                violations.push(format!("{path}: {call}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "L3 native source guard failed:\n  {}",
        violations.join("\n  ")
    );
}

/// C++ may not reach QML objects by name: Rust signals and `cxx_qt::Threading` do that.
#[test]
fn guard_cpp_has_no_by_name_lookups() {
    const FORBIDDEN: &[&str] = &["singletonInstance", "setProperty(", "invokeMethod("];
    let violations: Vec<String> = native_sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".cpp"))
        .flat_map(|(path, code)| {
            FORBIDDEN
                .iter()
                .filter(|call| code.contains(*call))
                .map(move |call| format!("{path}: {call}"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "C++ by-name lookup guard failed:\n  {}",
        violations.join("\n  ")
    );
}

/// Forcing every Qt window onto layer-shell breaks decorated Details/Settings/About; only the
/// popup may opt in, per window.
#[test]
fn guard_no_global_layer_shell() {
    const FORBIDDEN: &[&str] = &["useLayerShell", "QT_WAYLAND_SHELL_INTEGRATION"];
    fn walk(dir: &Path, hits: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, hits);
            } else if let Ok(text) = fs::read_to_string(&path) {
                for word in FORBIDDEN {
                    if text.contains(word) {
                        hits.push(format!("{}: {word}", path.display()));
                    }
                }
            }
        }
    }
    let crates = linux_root().join("crates");
    let mut hits = Vec::new();
    for entry in fs::read_dir(&crates).expect("read linux/crates").flatten() {
        for sub in ["cpp", "src"] {
            walk(&entry.path().join(sub), &mut hits);
        }
    }
    assert!(
        hits.is_empty(),
        "global layer-shell activation found:\n  {}",
        hits.join("\n  ")
    );
}

#[test]
fn guard_l4_linux_workspace_version_and_publish_policy_match_root() {
    let root = linux_root();
    let root_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("../Cargo.toml")).expect("read root Cargo.toml"),
    )
    .expect("root Cargo.toml parses");
    let linux_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("Cargo.toml")).expect("read linux/Cargo.toml"),
    )
    .expect("linux/Cargo.toml parses");
    let root_version = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(Value::as_str)
        .expect("root workspace package version");
    let linux_version = linux_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(Value::as_str)
        .expect("Linux workspace package version");
    assert_eq!(linux_version, root_version, "L4 workspace version mismatch");

    let crates = root.join("crates");
    for entry in fs::read_dir(crates).expect("read linux/crates") {
        let manifest_path = entry.expect("crate directory").path().join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest: Value =
            toml::from_str(&fs::read_to_string(&manifest_path).expect("read crate manifest"))
                .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));
        assert_eq!(
            manifest
                .get("package")
                .and_then(|package| package.get("publish"))
                .and_then(Value::as_bool),
            Some(false),
            "{} must use publish = false",
            manifest_path.display()
        );
    }
}

#[cfg(test)]
mod guard_helpers {
    use super::{
        allowed_child_stdin_write, denied, imports_fs_write, mentions_call, production_code,
    };

    #[test]
    fn denied_prefixes_catch_gtk_and_tokio_variants() {
        assert!(denied("gtk4-sys"));
        assert!(denied("tokio-util"));
        assert!(!denied("async-channel"));
    }

    #[test]
    fn test_module_and_comments_are_not_production_code() {
        let code = production_code(
            "// std::net comment\nfn production() {}\n#[cfg(test)]\nmod tests { std::net::TcpStream; }",
        );
        assert!(!code.contains("std::net"));
    }

    #[test]
    fn only_the_test_module_is_dropped() {
        let code = production_code(
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let s = \"}\"; let c = '{'; }\n}\nfn after() { std::fs::write(); }",
        );
        assert!(
            code.contains("fn after"),
            "production code after the test module is kept"
        );
        assert!(!code.contains("fn t"));
    }

    #[test]
    fn std_fs_write_imports_are_recognised() {
        assert!(imports_fs_write("use std::fs::write;"));
        assert!(imports_fs_write("use std::fs::{read, copy};"));
        assert!(imports_fs_write("use std::fs::*;"));
        assert!(!imports_fs_write(
            "use std::fs::{read_to_string, metadata};"
        ));
        assert!(!imports_fs_write("use std::fs;"));
    }

    #[test]
    fn native_calls_match_whole_words_only() {
        assert!(mentions_call("int r = system(cmd);", "system"));
        assert!(!mentions_call("ecosystem(x)", "system"));
        assert!(!mentions_call("obj.system(x)", "system"));
        assert!(mentions_call("QProcess p;", "QProcess"));
    }

    #[test]
    fn child_stdin_write_exception_is_limited_to_the_runner_call() {
        assert!(allowed_child_stdin_write(
            "crates/tray-model/src/runner.rs",
            "stdin.write(self.stdin_bytes)"
        ));
        assert!(!allowed_child_stdin_write(
            "crates/tray-model/src/settings.rs",
            "stdin.write(self.stdin_bytes)"
        ));
        assert!(!allowed_child_stdin_write(
            "crates/tray-model/src/runner.rs",
            "stdin.write(self.stdin_bytes); file.write(other_bytes)"
        ));
    }
}
