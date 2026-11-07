//! `hostsfile` against the shared fixtures in `tests/fixtures/hosts/` (the hosts helper's
//! `edit` must agree on every one of these).

use std::path::{Path, PathBuf};

use cainary_tray_model::hostsfile::{Analysis, BlockState, Unsupported, analyze, read_with};

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hosts")
        .join(format!("{name}.hosts"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hosts() -> Vec<String> {
    vec!["otel.example.com".into()]
}

fn run(name: &str) -> Analysis {
    analyze(&fixture(name), &hosts(), "myhost")
}

fn block(name: &str) -> BlockState {
    run(name).block
}

#[test]
fn absent_without_markers() {
    assert_eq!(block("no-block"), BlockState::Absent);
    assert_eq!(block("comments-aliases"), BlockState::Absent);
    assert_eq!(analyze(b"", &hosts(), "h").block, BlockState::Absent);
}

#[test]
fn current_in_every_line_ending_style() {
    for name in [
        "block-lf",
        "block-crlf",
        "block-eof-unterminated",
        "block-eof-crlf",
        "block-mixed-endings",
        "invalid-utf8",
        "nul-bytes",
    ] {
        assert_eq!(block(name), BlockState::Current, "{name}");
    }
}

#[test]
fn stale_when_content_differs() {
    for name in ["block-stale", "block-incomplete", "block-extra-line"] {
        assert_eq!(block(name), BlockState::Stale, "{name}");
    }
    // Names configured later or reordered.
    let more = vec!["otel.example.com".to_string(), "b.example.com".to_string()];
    assert_eq!(
        analyze(&fixture("block-lf"), &more, "h").block,
        BlockState::Stale
    );
    // No configured names: any block is stale.
    assert_eq!(
        analyze(&fixture("block-lf"), &[], "h").block,
        BlockState::Stale
    );
    let reordered = vec!["b.example.com".to_string(), "otel.example.com".to_string()];
    let bytes = analyze(&fixture("block-lf"), &reordered, "h");
    assert_eq!(bytes.block, BlockState::Stale);
}

#[test]
fn damaged_layouts_and_malformed_markers() {
    for name in [
        "damaged-begin-only",
        "damaged-end-only",
        "damaged-end-before-begin",
        "damaged-repeated-begin",
        "damaged-repeated-end",
        "damaged-two-blocks",
        "malformed-trailing-space",
        "malformed-case",
        "malformed-suffix",
        "malformed-indented-comment",
        "malformed-eof-cr",
    ] {
        assert_eq!(block(name), BlockState::Damaged, "{name}");
    }
}

#[test]
fn conflicts_are_unmanaged_non_loopback_lines() {
    let found = run("conflicts").conflicts;
    let seen: Vec<_> = found
        .iter()
        .map(|c| (c.line, c.address.as_str(), c.host.as_str()))
        .collect();
    // 0.0.0.0 counts; 127.0.0.1 and the mapped loopback don't; other names don't.
    assert_eq!(
        seen,
        [
            (3, "10.0.0.5", "otel.example.com"),
            (4, "0.0.0.0", "otel.example.com"),
        ]
    );
}

#[test]
fn lines_inside_the_block_are_not_conflicts() {
    let analysis = run("conflict-inside-block");
    assert_eq!(analysis.block, BlockState::Stale);
    assert!(analysis.conflicts.is_empty());
}

#[test]
fn conflicts_survive_comments_aliases_and_case() {
    let analysis = run("comments-aliases");
    let seen: Vec<_> = analysis
        .conflicts
        .iter()
        .map(|c| (c.line, c.address.as_str()))
        .collect();
    // Comment text, a commented-out line and a non-address first field are ignored; the CRLF
    // line with a tab-separated, upper-case alias still conflicts.
    assert_eq!(seen, [(5, "10.1.1.1")]);
}

#[test]
fn a_damaged_file_counts_every_line_as_unmanaged() {
    let analysis = run("damaged-begin-only");
    assert!(analysis.conflicts.is_empty());
    let mut bytes = fixture("damaged-begin-only");
    bytes.extend_from_slice(b"10.2.2.2 otel.example.com\n");
    let analysis = analyze(&bytes, &hosts(), "myhost");
    assert_eq!(analysis.conflicts.len(), 1);
}

#[test]
fn reserved_names() {
    let names: Vec<String> = [
        "otel.example.com",
        "x.localhost",
        "y.localdomain",
        "localhost.localdomain",
        "localhost6.localdomain6",
        "myhost.corp.example",
        "other.corp.example",
    ]
    .map(String::from)
    .into();
    let analysis = analyze(&fixture("no-block"), &names, "MyHost.Corp.Example");
    assert_eq!(
        analysis.reserved,
        [
            "x.localhost",
            "y.localdomain",
            "localhost.localdomain",
            "localhost6.localdomain6",
            "myhost.corp.example"
        ]
    );
}

#[test]
fn a_name_on_a_nodename_line_is_reserved() {
    let names: Vec<String> = ["myhost.corp.example", "otel.example.com"]
        .map(String::from)
        .into();
    let analysis = analyze(&fixture("nodename-line"), &names, "other-node");
    assert!(analysis.reserved.is_empty());
    // Alias is the nodename itself.
    let analysis = analyze(&fixture("nodename-line"), &names, "myhost");
    assert_eq!(analysis.reserved, ["myhost.corp.example"]);
    // An alias on a nodename line, for a name that doesn't start with the nodename.
    let bytes = b"127.0.1.1 mynode.lan mynode alias.example.com\n";
    let analysis = analyze(bytes, &["alias.example.com".to_string()], "mynode");
    assert_eq!(analysis.reserved, ["alias.example.com"]);
    // The managed block doesn't count.
    let analysis = analyze(&fixture("block-lf"), &hosts(), "otel.example.com");
    assert_eq!(analysis.reserved, ["otel.example.com"]);
}

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("hostsfile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Temp(dir)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn me() -> u32 {
    // SAFETY: plain syscall without arguments.
    unsafe { libc::geteuid() }
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn reads_a_protected_regular_file() {
    let temp = Temp::new("ok");
    let path = temp.0.join("hosts");
    std::fs::write(&path, fixture("block-crlf")).unwrap();
    chmod(&path, 0o644);
    let file = read_with(&path, &hosts(), "h", me());
    assert_eq!(file.unsupported, None);
    assert_eq!(file.error, None);
    assert_eq!(file.analysis.unwrap().block, BlockState::Current);
}

#[test]
fn unprotected_files_are_flagged() {
    let temp = Temp::new("unprotected");
    let path = temp.0.join("hosts");
    std::fs::write(&path, fixture("no-block")).unwrap();
    chmod(&path, 0o664);
    let file = read_with(&path, &hosts(), "h", me());
    assert_eq!(file.unsupported, Some(Unsupported::Unprotected));
    // Wrong owner.
    chmod(&path, 0o644);
    let file = read_with(&path, &hosts(), "h", me() + 1);
    assert_eq!(file.unsupported, Some(Unsupported::Unprotected));
}

#[test]
fn symlinks_are_flagged_with_their_target() {
    let temp = Temp::new("symlink");
    let target = temp.0.join("real");
    std::fs::write(&target, fixture("no-block")).unwrap();
    let path = temp.0.join("hosts");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let file = read_with(&path, &hosts(), "h", me());
    assert_eq!(
        file.unsupported,
        Some(Unsupported::Symlink {
            target: target.display().to_string()
        })
    );
}

#[test]
fn a_fifo_is_refused_without_blocking() {
    let temp = Temp::new("fifo");
    let path = temp.0.join("hosts");
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
    let file = read_with(&path, &hosts(), "h", me());
    assert_eq!(file.unsupported, Some(Unsupported::NotRegular));
    assert!(file.analysis.is_none());
    // A symlink to the FIFO too.
    let link = temp.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let file = read_with(&link, &hosts(), "h", me());
    assert_eq!(file.unsupported, Some(Unsupported::NotRegular));
}

#[test]
fn a_missing_file_is_an_error() {
    let temp = Temp::new("missing");
    let file = read_with(&temp.0.join("nope"), &hosts(), "h", me());
    assert!(file.error.is_some());
    assert!(file.analysis.is_none());
}

/// With the collector off there are no names; a well-formed block is still ours to remove.
#[test]
fn a_block_is_stale_without_names() {
    let none: Vec<String> = Vec::new();
    assert_eq!(
        analyze(&fixture("block-lf"), &none, "h").block,
        BlockState::Stale
    );
    assert_eq!(
        analyze(b"127.0.0.1 localhost\n", &none, "h").block,
        BlockState::Absent
    );
}
