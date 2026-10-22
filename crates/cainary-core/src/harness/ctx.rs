//! `ScanCtx`: recorded reads, lists and markers, and the typed outcome → `SourceState` mapping
//! (architecture.md §6.2).

use super::fs::{self, ReadError};
use super::platform::{self, CmdError, Os};
use super::{Harness, Loc};
use crate::model::{
    Finding, FindingBuilder, Origin, ScannedSource, Source, SourceKind, SourceState, Tool,
};
use crate::redact;
use crate::value::{self, Budget, Format, Value};

const NOTE_MAX_CHARS: usize = 120;

/// Everything one scanner produced.
#[derive(Debug, Default)]
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub sources: Vec<ScannedSource>,
    pub installed: bool,
    pub notes: Vec<String>,
}

/// Result of a stat-only probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Missing,
    File,
    Dir,
    Other,
    /// The stat itself failed (e.g. `EACCES` on a parent).
    Failed,
}

/// One per tool per scan. Collects findings, sources, the installed flag and notes, and records
/// every source it touches automatically.
pub struct ScanCtx<'a> {
    h: &'a Harness,
    tool: Tool,
    out: ScanOutput,
}

/// Redact, then cut to a short single-line note.
fn short(msg: &str) -> String {
    redact::text(msg).chars().take(NOTE_MAX_CHARS).collect()
}

impl<'a> ScanCtx<'a> {
    pub fn new(h: &'a Harness, tool: Tool) -> ScanCtx<'a> {
        ScanCtx {
            h,
            tool,
            out: ScanOutput {
                notes: h.notes_for(tool),
                ..ScanOutput::default()
            },
        }
    }

    /// Consume the context and return what the scanner collected.
    pub fn finish(self) -> ScanOutput {
        self.out
    }

    pub fn h(&self) -> &Harness {
        self.h
    }

    /// One row per path and kind: a second touch of the same source keeps the first outcome.
    fn record(
        &mut self,
        path: &str,
        origin: Origin,
        kind: SourceKind,
        state: SourceState,
        note: Option<String>,
    ) {
        let path = redact::display_path(path, "");
        if self
            .out
            .sources
            .iter()
            .any(|s| s.source.path == path && s.source.kind == kind)
        {
            return;
        }
        self.out.sources.push(ScannedSource {
            tool: self.tool,
            source: Source::new(path, origin, kind),
            state,
            note,
        });
    }

    /// Records Present/Absent/Error/Refused as a source.
    pub fn read(&mut self, loc: &Loc, origin: Origin, fmt: Format) -> Option<Value> {
        self.read_with_state(loc, origin, fmt).0
    }

    /// Reads a source and returns its recorded state with the parsed value.
    pub fn read_with_state(
        &mut self,
        loc: &Loc,
        origin: Origin,
        fmt: Format,
    ) -> (Option<Value>, SourceState) {
        let (state, note, value) =
            match fs::read(self.h.policy(), &loc.physical, fs::MAX_FILE_BYTES) {
                Ok(bytes) => match value::parse(&bytes, fmt, &mut Budget::new()) {
                    Ok(v) => (SourceState::Present, None, Some(v)),
                    Err(e) => (SourceState::Error, Some(short(&e)), None),
                },
                Err(ReadError::Missing) => (SourceState::Absent, None, None),
                Err(ReadError::Denied) => (
                    SourceState::Refused,
                    Some("not read: credential location".to_string()),
                    None,
                ),
                Err(ReadError::Swapped) => (
                    SourceState::Refused,
                    Some("not read: the path changed while it was opened".to_string()),
                    None,
                ),
                Err(ReadError::NotRegular) => (
                    SourceState::Error,
                    Some("not read: not a regular file".to_string()),
                    None,
                ),
                Err(ReadError::HardLinked) => (
                    SourceState::Error,
                    Some("not read: file has more than one hard link".to_string()),
                    None,
                ),
                Err(ReadError::TooLarge) => (
                    SourceState::Error,
                    Some("not read: file is larger than 1 MiB".to_string()),
                    None,
                ),
                Err(ReadError::Io(e)) => (
                    SourceState::Error,
                    Some(short(&format!("not read: {e}"))),
                    None,
                ),
            };
        self.record(&loc.shown, origin, SourceKind::File, state, note);
        (value, state)
    }

    /// Present plists, user first; top-level JSON-in-string values are decoded.
    pub fn read_mdm(&mut self, domain: &str) -> Vec<(Loc, Value)> {
        let mut found = Vec::new();
        for loc in self.h.mdm(domain) {
            let Some(mut v) = self.read(&loc, Origin::Mdm, Format::Plist) else {
                continue;
            };
            let mut budget = Budget::new();
            if let Value::Object(map) = &mut v {
                let keys: Vec<String> = map.keys().cloned().collect();
                for key in keys {
                    match value::str_or_json(&map[&key], &mut budget) {
                        Ok(inner) => {
                            map.insert(key, inner);
                        }
                        Err(e) => {
                            // An undecodable value is dropped, and the failure makes the scan
                            // incomplete rather than letting the key read as absent-and-fine.
                            map.remove(&key);
                            self.record(
                                &format!("{}#{key}", loc.shown),
                                Origin::Mdm,
                                SourceKind::File,
                                SourceState::Error,
                                Some(short(&e)),
                            );
                        }
                    }
                }
            }
            found.push((loc, v));
        }
        found
    }

    /// An embedded document (Codex base64 TOML, cloud-cache TOML), recorded as `<at>#<key>`.
    pub fn parse_inner(
        &mut self,
        at: &Loc,
        origin: Origin,
        key: &str,
        text: &[u8],
        fmt: Format,
    ) -> Option<Value> {
        let (state, note, value) = match value::parse(text, fmt, &mut Budget::new()) {
            Ok(v) => (SourceState::Present, None, Some(v)),
            Err(e) => (SourceState::Error, Some(short(&e)), None),
        };
        self.record(
            &format!("{}#{key}", at.shown),
            origin,
            SourceKind::File,
            state,
            note,
        );
        value
    }

    /// Sorted, hidden skipped, at most 256; records the directory as a source.
    pub fn list(&mut self, dir: &Loc, suffix: &str, origin: Origin) -> Vec<Loc> {
        let mut found = Vec::new();
        let (state, note) = match fs::list(self.h.policy(), &dir.physical, fs::MAX_LIST_ENTRIES) {
            Ok(listing) => {
                for entry in listing.entries {
                    let Some(name) = entry.file_name().map(|n| n.to_string_lossy().into_owned())
                    else {
                        continue;
                    };
                    if name.ends_with(suffix) {
                        found.push(Loc {
                            shown: dir.join(&name).shown,
                            physical: entry,
                        });
                    }
                }
                if listing.truncated {
                    (
                        SourceState::Capped,
                        Some(format!(
                            "only the first {} entries were checked",
                            fs::MAX_LIST_ENTRIES
                        )),
                    )
                } else {
                    (SourceState::Present, None)
                }
            }
            Err(ReadError::Missing) => (SourceState::Absent, None),
            Err(ReadError::Denied | ReadError::Swapped) => (
                SourceState::Refused,
                Some("not listed: credential location".to_string()),
            ),
            Err(ReadError::Io(e)) => (SourceState::Error, Some(short(&format!("not listed: {e}")))),
            Err(_) => (
                SourceState::Error,
                Some("not listed: not a directory".to_string()),
            ),
        };
        self.record(&dir.shown, origin, SourceKind::Dir, state, note);
        found
    }

    fn stat(loc: &Loc) -> Probe {
        match fs::stat(&loc.physical) {
            Ok(None) => Probe::Missing,
            Ok(Some(s)) if s.is_dir => Probe::Dir,
            Ok(Some(s)) if s.is_file => Probe::File,
            Ok(Some(_)) => Probe::Other,
            Err(_) => Probe::Failed,
        }
    }

    /// Stat only, not recorded: installed markers.
    pub fn probe(&self, loc: &Loc) -> Probe {
        Self::stat(loc)
    }

    /// Stat only, recorded: markers that make findings.
    pub fn marker(&mut self, loc: &Loc, origin: Origin) -> Probe {
        let p = Self::stat(loc);
        let (state, note) = match p {
            Probe::Missing => (SourceState::Absent, None),
            Probe::Failed => (
                SourceState::Error,
                Some("couldn't check whether it exists".to_string()),
            ),
            Probe::File | Probe::Dir | Probe::Other => (SourceState::Present, None),
        };
        self.record(&loc.shown, origin, SourceKind::Marker, state, note);
        p
    }

    /// uid 0 and not group/world-writable. A fixture (or `--root`) answers from its `rootOwned`
    /// list and never stats, so goldens don't depend on who runs the tests.
    pub fn root_owned(&self, loc: &Loc) -> bool {
        if !self.h.live {
            return self.h.meta.root_owned.contains(&loc.shown);
        }
        matches!(
            fs::stat(&loc.physical),
            Ok(Some(s)) if s.is_file && s.uid == 0 && s.mode & 0o022 == 0
        )
    }

    /// Root-owned, or a regular file without the owner write bit: the user can't edit it, so
    /// someone else put it there. Fixtures answer from `rootOwned`, like `root_owned`.
    pub fn locked(&self, loc: &Loc) -> bool {
        self.root_owned(loc)
            || (self.h.live
                && matches!(
                    fs::stat(&loc.physical),
                    Ok(Some(s)) if s.is_file && s.mode & 0o200 == 0
                ))
    }

    pub fn canonical(&self, loc: &Loc) -> Option<Loc> {
        let physical = fs::canonical(&loc.physical)?;
        Some(Loc {
            shown: self.h.show(&physical),
            physical,
        })
    }

    /// `env:VAR`, origin environment.
    pub fn env_source(&self, var: &str) -> Source {
        Source::new(format!("env:{var}"), Origin::Environment, SourceKind::Env)
    }

    /// Parsed `scutil --proxy` output (§6.4), recorded as a source.
    pub fn system_proxy(&mut self) -> Option<Value> {
        let text: Result<Option<String>, CmdError> = if self.h.live {
            if self.h.os == Os::Macos {
                platform::scutil_proxy().map(Some)
            } else {
                Ok(None)
            }
        } else {
            Ok(self.h.meta.scutil_proxy.clone())
        };
        let (state, note, value) = match text {
            Ok(Some(t)) => (SourceState::Present, None, Some(platform::parse_scutil(&t))),
            Ok(None) => (SourceState::Absent, None, None),
            Err(e) => {
                let why = match e {
                    CmdError::Spawn(s) => format!("couldn't run scutil: {}", short(&s)),
                    CmdError::Exit(c) => format!("scutil exited with status {c}"),
                    CmdError::TimedOut => "scutil took too long".to_string(),
                    CmdError::TooLarge => "scutil printed more than 64 KiB".to_string(),
                };
                (SourceState::Error, Some(why), None)
            }
        };
        self.record(
            "scutil --proxy",
            Origin::System,
            SourceKind::Command,
            state,
            note,
        );
        value
    }

    /// Record a `Command` source as refused: an admin helper that is never run.
    pub fn not_run(&mut self, loc: &Loc, origin: Origin, why: &str) {
        self.record(
            &loc.shown,
            origin,
            SourceKind::Command,
            SourceState::Refused,
            Some(short(why)),
        );
    }

    /// Mark the tool installed.
    pub fn installed(&mut self) {
        self.out.installed = true;
    }

    pub fn note(&mut self, s: &str) {
        let s = redact::text(s);
        if !self.out.notes.contains(&s) {
            self.out.notes.push(s);
        }
    }

    /// Build the finding for this tool (`FindingBuilder::build`) and collect it.
    pub fn emit(&mut self, f: FindingBuilder) {
        self.out.findings.push(f.build(self.tool));
    }
}

#[cfg(test)]
mod tests {
    use super::super::platform::SCUTIL_CALLS;
    use super::super::tests::Tmp;
    use super::*;
    use crate::model::Signal;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::Ordering;

    fn state_of(ctx: ScanCtx, path: &str) -> (SourceState, Option<String>) {
        let out = ctx.finish();
        let s = out
            .sources
            .iter()
            .find(|s| s.source.path == path)
            .unwrap_or_else(|| panic!("no source {path} in {:?}", out.sources));
        (s.state, s.note.clone())
    }

    /// `chmod 0` is no barrier to root, so permission tests skip there.
    fn unreadable(path: &std::path::Path) -> bool {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let blocked = if path.is_dir() {
            std::fs::read_dir(path).is_err()
        } else {
            std::fs::File::open(path).is_err()
        };
        if !blocked {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        blocked
    }

    fn restore(path: &std::path::Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn read_missing_is_absent() {
        let t = Tmp::new();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Codex);
        let loc = h.home(".codex/config.toml");
        assert!(c.read(&loc, Origin::User, Format::Toml).is_none());
        assert_eq!(
            state_of(c, "~/.codex/config.toml"),
            (SourceState::Absent, None)
        );
    }

    #[test]
    fn read_parsed_is_present() {
        let t = Tmp::new();
        t.write("home/.codex/config.toml", b"model = \"x\"\n");
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Codex);
        let v = c
            .read(&h.home(".codex/config.toml"), Origin::User, Format::Toml)
            .unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(state_of(c, "~/.codex/config.toml").0, SourceState::Present);
    }

    #[test]
    fn read_parse_error_is_error_with_redacted_short_note() {
        let t = Tmp::new();
        let long = format!("key = sk-test-EXAMPLE0123456789abcdef {}", "x".repeat(300));
        t.write("home/.codex/config.toml", long.as_bytes());
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Codex);
        assert!(
            c.read(&h.home(".codex/config.toml"), Origin::User, Format::Toml)
                .is_none()
        );
        let (state, note) = state_of(c, "~/.codex/config.toml");
        assert_eq!(state, SourceState::Error);
        let note = note.unwrap();
        assert!(note.chars().count() <= NOTE_MAX_CHARS, "{note}");
        assert!(!note.contains("sk-test-EXAMPLE0123456789abcdef"), "{note}");
    }

    #[test]
    fn read_budget_error_is_error() {
        let t = Tmp::new();
        t.write(
            "home/deep.json",
            format!("{}{}", "[".repeat(200), "]".repeat(200)).as_bytes(),
        );
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(
            c.read(&h.home("deep.json"), Origin::User, Format::Json)
                .is_none()
        );
        assert_eq!(state_of(c, "~/deep.json").0, SourceState::Error);
    }

    #[test]
    fn read_not_a_regular_file_is_error() {
        let t = Tmp::new();
        std::fs::create_dir_all(t.0.join("home/settings.json")).unwrap();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(
            c.read(&h.home("settings.json"), Origin::User, Format::Json)
                .is_none()
        );
        let (s, n) = state_of(c, "~/settings.json");
        assert_eq!(s, SourceState::Error);
        assert!(n.unwrap().contains("regular file"));
    }

    #[test]
    fn read_hard_linked_is_error() {
        let t = Tmp::new();
        t.write("home/a.json", b"{}");
        std::fs::hard_link(t.0.join("home/a.json"), t.0.join("home/b.json")).unwrap();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(
            c.read(&h.home("a.json"), Origin::User, Format::Json)
                .is_none()
        );
        assert_eq!(state_of(c, "~/a.json").0, SourceState::Error);
    }

    #[test]
    fn read_over_the_cap_is_error() {
        let t = Tmp::new();
        t.write("home/big.json", &vec![b' '; 1024 * 1024 + 1]);
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(
            c.read(&h.home("big.json"), Origin::User, Format::Json)
                .is_none()
        );
        assert_eq!(state_of(c, "~/big.json").0, SourceState::Error);
    }

    #[test]
    fn read_permission_error_is_error() {
        let t = Tmp::new();
        t.write("home/p.json", b"{}");
        let p = t.0.join("home/p.json");
        if !unreadable(&p) {
            return;
        }
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(
            c.read(&h.home("p.json"), Origin::User, Format::Json)
                .is_none()
        );
        restore(&p);
        assert_eq!(state_of(c, "~/p.json").0, SourceState::Error);
    }

    #[test]
    fn read_symlink_to_a_credential_is_refused_without_reading() {
        let t = Tmp::new();
        t.write("home/.ssh/id_rsa", b"{\"leak\": true}");
        std::fs::create_dir_all(t.0.join("home/.claude")).unwrap();
        symlink(
            t.0.join("home/.ssh/id_rsa"),
            t.0.join("home/.claude/settings.json"),
        )
        .unwrap();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::ClaudeCode);
        let loc = h
            .tool_home(super::super::ToolHome::ClaudeConfig)
            .join("settings.json");
        assert!(c.read(&loc, Origin::User, Format::Json).is_none());
        let (s, n) = state_of(c, "~/.claude/settings.json");
        assert_eq!(s, SourceState::Refused);
        assert_eq!(n.as_deref(), Some("not read: credential location"));
    }

    #[test]
    fn read_of_a_denied_path_is_refused() {
        let t = Tmp::new();
        t.write("home/.codex/auth.json", b"{}");
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Codex);
        assert!(
            c.read(&h.home(".codex/auth.json"), Origin::User, Format::Json)
                .is_none()
        );
        assert_eq!(state_of(c, "~/.codex/auth.json").0, SourceState::Refused);
    }

    #[test]
    fn second_touch_keeps_one_row() {
        let t = Tmp::new();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        let loc = h.home("x.json");
        c.read(&loc, Origin::User, Format::Json);
        c.read(&loc, Origin::User, Format::Json);
        assert_eq!(c.finish().sources.len(), 1);
    }

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>env</key><string>{"OTEL_LOG_USER_PROMPTS":"1"}</string>
<key>plain</key><string>hello</string>
<key>flag</key><true/>
</dict></plist>"#;

    #[test]
    fn read_mdm_user_first_and_decodes_json_strings() {
        let t = Tmp::new();
        t.write(
            "root/Library/Managed Preferences/com.example.app.plist",
            PLIST.as_bytes(),
        );
        t.write(
            "root/Library/Managed Preferences/alice/com.example.app.plist",
            PLIST.as_bytes(),
        );
        let h = t.fixture(r#"{ "os": "macos" }"#);
        let mut c = ScanCtx::new(&h, Tool::ClaudeCode);
        let got = c.read_mdm("com.example.app");
        let shown: Vec<&str> = got.iter().map(|(l, _)| l.shown.as_str()).collect();
        assert_eq!(
            shown,
            [
                "/Library/Managed Preferences/alice/com.example.app.plist",
                "/Library/Managed Preferences/com.example.app.plist"
            ]
        );
        assert_eq!(got[0].1["env"]["OTEL_LOG_USER_PROMPTS"], "1");
        assert_eq!(got[0].1["plain"], "hello");
        assert_eq!(got[0].1["flag"], true);
        let out = c.finish();
        assert!(out.sources.iter().all(|s| s.state == SourceState::Present));
        assert_eq!(out.sources[0].source.origin, Origin::Mdm);
    }

    #[test]
    fn read_mdm_absent_and_linux() {
        let t = Tmp::new();
        let h = t.fixture(r#"{ "os": "macos" }"#);
        let mut c = ScanCtx::new(&h, Tool::ClaudeCode);
        assert!(c.read_mdm("com.example.app").is_empty());
        assert!(
            c.finish()
                .sources
                .iter()
                .all(|s| s.state == SourceState::Absent)
        );
        let l = t.fixture(r#"{ "os": "linux" }"#);
        let mut c = ScanCtx::new(&l, Tool::ClaudeCode);
        assert!(c.read_mdm("com.example.app").is_empty());
        assert!(c.finish().sources.is_empty());
    }

    #[test]
    fn parse_inner_records_at_hash_key() {
        let h = Harness::test(super::super::platform::Os::Linux, &[]);
        let at = h.home(".codex/cache.json");
        let mut c = ScanCtx::new(&h, Tool::Codex);
        let v = c
            .parse_inner(&at, Origin::Server, "toml", b"a = 1", Format::Toml)
            .unwrap();
        assert_eq!(v["a"], 1);
        assert!(
            c.parse_inner(&at, Origin::Server, "bad", b"a = = 1", Format::Toml)
                .is_none()
        );
        let out = c.finish();
        assert_eq!(out.sources[0].source.path, "~/.codex/cache.json#toml");
        assert_eq!(out.sources[0].state, SourceState::Present);
        assert_eq!(out.sources[0].source.origin, Origin::Server);
        assert_eq!(out.sources[1].source.path, "~/.codex/cache.json#bad");
        assert_eq!(out.sources[1].state, SourceState::Error);
    }

    #[test]
    fn list_present_filters_by_suffix_and_skips_hidden() {
        let t = Tmp::new();
        t.write("root/etc/p.d/b.json", b"{}");
        t.write("root/etc/p.d/a.json", b"{}");
        t.write("root/etc/p.d/c.txt", b"x");
        t.write("root/etc/p.d/.hidden.json", b"{}");
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Copilot);
        let dir = h.sys("/etc/p.d");
        let got: Vec<String> = c
            .list(&dir, ".json", Origin::System)
            .into_iter()
            .map(|l| l.shown)
            .collect();
        assert_eq!(got, ["/etc/p.d/a.json", "/etc/p.d/b.json"]);
        let out = c.finish();
        assert_eq!(out.sources[0].state, SourceState::Present);
        assert_eq!(out.sources[0].source.kind, SourceKind::Dir);
    }

    #[test]
    fn list_missing_is_absent() {
        let t = Tmp::new();
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Copilot);
        assert!(c.list(&h.sys("/etc/none"), "", Origin::System).is_empty());
        assert_eq!(state_of(c, "/etc/none").0, SourceState::Absent);
    }

    #[test]
    fn list_over_the_cap_is_capped() {
        let t = Tmp::new();
        for i in 0..257 {
            t.write(&format!("root/etc/many/f{i:03}.json"), b"{}");
        }
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Copilot);
        let got = c.list(&h.sys("/etc/many"), ".json", Origin::System);
        assert_eq!(got.len(), 256);
        let (s, n) = state_of(c, "/etc/many");
        assert_eq!(s, SourceState::Capped);
        assert_eq!(
            n.as_deref(),
            Some("only the first 256 entries were checked")
        );
    }

    #[test]
    fn list_io_error_is_error() {
        let t = Tmp::new();
        t.write("root/etc/locked/a.json", b"{}");
        let d = t.0.join("root/etc/locked");
        if !unreadable(&d) {
            return;
        }
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Copilot);
        assert!(c.list(&h.sys("/etc/locked"), "", Origin::System).is_empty());
        restore(&d);
        assert_eq!(state_of(c, "/etc/locked").0, SourceState::Error);
    }

    #[test]
    fn list_of_a_dir_with_a_denied_child_is_refused() {
        let t = Tmp::new();
        t.write("home/.ssh/id_rsa", b"x");
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert!(c.list(&h.home(""), "", Origin::User).is_empty());
        assert_eq!(state_of(c, "~/").0, SourceState::Refused);
    }

    #[test]
    fn probe_is_not_recorded_and_marker_is() {
        let t = Tmp::new();
        t.write("home/.cursor/x", b"x");
        let h = t.fixture("{}");
        let c = ScanCtx::new(&h, Tool::Cursor);
        assert_eq!(c.probe(&h.home(".cursor")), Probe::Dir);
        assert_eq!(c.probe(&h.home(".cursor/x")), Probe::File);
        assert_eq!(c.probe(&h.home(".nope")), Probe::Missing);
        assert!(c.finish().sources.is_empty());

        let mut c = ScanCtx::new(&h, Tool::Cursor);
        assert_eq!(c.marker(&h.home(".cursor"), Origin::User), Probe::Dir);
        assert_eq!(c.marker(&h.home(".nope"), Origin::User), Probe::Missing);
        let out = c.finish();
        assert_eq!(out.sources.len(), 2);
        assert!(
            out.sources
                .iter()
                .all(|s| s.source.kind == SourceKind::Marker)
        );
        assert_eq!(out.sources[0].state, SourceState::Present);
        assert_eq!(out.sources[1].state, SourceState::Absent);
    }

    #[test]
    fn marker_failure_is_error() {
        let t = Tmp::new();
        t.write("home/locked/inner", b"x");
        let d = t.0.join("home/locked");
        if !unreadable(&d) {
            return;
        }
        let h = t.fixture("{}");
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        let p = c.marker(&h.home("locked/inner"), Origin::User);
        restore(&d);
        assert_eq!(p, Probe::Failed);
        assert_eq!(state_of(c, "~/locked/inner").0, SourceState::Error);
    }

    #[test]
    fn not_run_is_a_refused_command_source() {
        let h = Harness::test(super::super::platform::Os::Macos, &[]);
        let mut c = ScanCtx::new(&h, Tool::ClaudeCode);
        c.not_run(
            &h.sys("/opt/acme/policy-helper"),
            Origin::Mdm,
            "admin helper, never run",
        );
        let out = c.finish();
        let s = &out.sources[0];
        assert_eq!(s.state, SourceState::Refused);
        assert_eq!(s.source.kind, SourceKind::Command);
        assert_eq!(s.source.origin, Origin::Mdm);
        assert_eq!(s.note.as_deref(), Some("admin helper, never run"));
    }

    #[test]
    fn root_owned_answers_from_the_fixture_list() {
        let t = Tmp::new();
        t.write("root/opt/acme/hook", b"x");
        let h = t.fixture(r#"{ "rootOwned": ["/opt/acme/hook", "~/.claude/settings.json"] }"#);
        let c = ScanCtx::new(&h, Tool::ClaudeCode);
        assert!(c.root_owned(&h.sys("/opt/acme/hook")));
        assert!(c.root_owned(&h.home(".claude/settings.json")));
        assert!(!c.root_owned(&h.sys("/opt/acme/other")));
    }

    #[test]
    fn canonical_shows_logical_paths() {
        let t = Tmp::new();
        t.write("home/real/x.json", b"{}");
        symlink(t.0.join("home/real"), t.0.join("home/link")).unwrap();
        let h = t.fixture("{}");
        let c = ScanCtx::new(&h, Tool::Cursor);
        let got = c.canonical(&h.home("link/x.json")).unwrap();
        assert_eq!(got.shown, "~/real/x.json");
        assert!(c.canonical(&h.home("missing")).is_none());
    }

    #[test]
    fn env_source_names_the_variable() {
        let h = Harness::test(super::super::platform::Os::Linux, &[]);
        let c = ScanCtx::new(&h, Tool::Codex);
        let s = c.env_source("OTEL_LOG_USER_PROMPTS");
        assert_eq!(s.path, "env:OTEL_LOG_USER_PROMPTS");
        assert_eq!(s.origin, Origin::Environment);
        assert_eq!(s.kind, SourceKind::Env);
    }

    #[test]
    fn system_proxy_from_the_fixture() {
        let t = Tmp::new();
        let h = t.fixture(
            r#"{ "os": "macos", "scutilProxy": "<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : proxy.example-corp.com\n  HTTPSPort : 8080\n}" }"#,
        );
        let mut c = ScanCtx::new(&h, Tool::Device);
        let v = c.system_proxy().unwrap();
        assert_eq!(v["HTTPSProxy"], "proxy.example-corp.com");
        assert_eq!(v["HTTPSPort"], 8080);
        let (s, _) = state_of(c, "scutil --proxy");
        assert_eq!(s, SourceState::Present);
    }

    /// Guard 7: a fixture harness without `scutilProxy` records an `absent` source and never
    /// starts `scutil`. The platform module's own live test also bumps the counter, so a
    /// concurrent bump is retried rather than blamed on this code.
    #[test]
    fn guard7_fixture_without_scutil_proxy_runs_nothing() {
        let t = Tmp::new();
        let h = t.fixture(r#"{ "os": "macos" }"#);
        for _ in 0..5 {
            let before = SCUTIL_CALLS.load(Ordering::SeqCst);
            let mut c = ScanCtx::new(&h, Tool::Device);
            assert!(c.system_proxy().is_none());
            let (s, n) = state_of(c, "scutil --proxy");
            assert_eq!((s, n), (SourceState::Absent, None));
            if SCUTIL_CALLS.load(Ordering::SeqCst) == before {
                return;
            }
        }
        panic!("SCUTIL_CALLS kept changing: fixture mode started scutil");
    }

    #[test]
    fn system_proxy_on_a_linux_root_is_absent() {
        let t = Tmp::new();
        let h = Harness::with_roots(
            t.0.join("root"),
            t.0.join("home"),
            super::super::platform::Os::Linux,
        );
        let mut c = ScanCtx::new(&h, Tool::Device);
        assert!(c.system_proxy().is_none());
        assert_eq!(state_of(c, "scutil --proxy").0, SourceState::Absent);
    }

    #[test]
    fn notes_installed_and_relocation_notes() {
        let h = Harness::test(super::super::platform::Os::Linux, &[("CODEX_HOME", "rel")]);
        let mut c = ScanCtx::new(&h, Tool::Codex);
        c.note("one");
        c.note("one");
        c.installed();
        let out = c.finish();
        assert!(out.installed);
        assert_eq!(out.notes.len(), 2);
        assert!(out.notes[0].contains("CODEX_HOME"));
        assert_eq!(out.notes[1], "one");
    }

    #[test]
    fn emit_fills_tool_clears_signals_and_redacts() {
        let h = Harness::test(super::super::platform::Os::Linux, &[]);
        let mut c = ScanCtx::new(&h, Tool::Cursor);
        let src = Source::new("~/.cursor/hooks.json", Origin::User, SourceKind::File);
        c.emit(
            FindingBuilder::new("Hook runs")
                .signals(&[Signal::ToolDetails])
                .detail("token sk-test-EXAMPLE0123456789abcdef used")
                .source(src.clone())
                .in_effect(false),
        );
        c.emit(
            FindingBuilder::new("Hook runs")
                .signals(&[Signal::ToolDetails])
                .source(src),
        );
        let out = c.finish();
        assert_eq!(out.findings[0].tool, Tool::Cursor);
        assert!(out.findings[0].signals.is_empty());
        assert!(
            !out.findings[0]
                .detail
                .contains("sk-test-EXAMPLE0123456789abcdef")
        );
        assert_eq!(out.findings[1].signals, [Signal::ToolDetails]);
    }
}
