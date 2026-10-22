//! The harness is the only code that touches the OS (architecture.md §6).

pub mod ctx;
pub mod deny;
pub mod fs;
pub mod platform;

pub use ctx::{Probe, ScanCtx, ScanOutput};

use crate::model::Tool;
use crate::redact;
use deny::{AccessPolicy, ToolHomes};
use platform::{EnvKind, Os};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A location: `shown` is what JSON prints (`~/…`, `/Library/…`); the physical path stays private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loc {
    pub shown: String,
    physical: PathBuf,
}

impl Loc {
    /// A child of this location. `rel` is a relative path such as `settings.json`.
    pub fn join(&self, rel: &str) -> Loc {
        let rel = rel.trim_start_matches('/');
        let shown = if self.shown.ends_with('/') {
            format!("{}{rel}", self.shown)
        } else {
            format!("{}/{rel}", self.shown)
        };
        Loc {
            shown,
            physical: self.physical.join(rel),
        }
    }

    /// For hand-built `CcConfig`/`CxConfig`/`CpConfig` values in unit tests.
    #[cfg(test)]
    pub fn test(shown: &str) -> Loc {
        Loc {
            shown: shown.to_string(),
            physical: PathBuf::from(shown),
        }
    }
}

/// The three tool-home relocations (§6.1): `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`, `$COPILOT_HOME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolHome {
    ClaudeConfig,
    CodexHome,
    CopilotHome,
}

impl ToolHome {
    const ALL: [ToolHome; 3] = [
        ToolHome::ClaudeConfig,
        ToolHome::CodexHome,
        ToolHome::CopilotHome,
    ];

    fn var(self) -> &'static str {
        match self {
            ToolHome::ClaudeConfig => "CLAUDE_CONFIG_DIR",
            ToolHome::CodexHome => "CODEX_HOME",
            ToolHome::CopilotHome => "COPILOT_HOME",
        }
    }

    fn default_rel(self) -> &'static str {
        match self {
            ToolHome::ClaudeConfig => ".claude",
            ToolHome::CodexHome => ".codex",
            ToolHome::CopilotHome => ".copilot",
        }
    }

    fn tool(self) -> Tool {
        match self {
            ToolHome::ClaudeConfig => Tool::ClaudeCode,
            ToolHome::CodexHome => Tool::Codex,
            ToolHome::CopilotHome => Tool::Copilot,
        }
    }

    fn index(self) -> usize {
        match self {
            ToolHome::ClaudeConfig => 0,
            ToolHome::CodexHome => 1,
            ToolHome::CopilotHome => 2,
        }
    }
}

/// Result of a stat-only PATH lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Which {
    Found(Loc),
    NotFound,
    /// PATH has a relative or `$VAR` entry.
    Unknown,
}

/// The parsed `fixture.json`, all keys optional.
#[derive(Debug, Clone, Default)]
pub struct FixtureMeta {
    pub root_owned: Vec<String>,
    pub scutil_proxy: Option<String>,
    pub tools: Vec<Tool>,
}

/// The on-disk shape of `fixture.json`; an unknown key is an error.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
struct FixtureFile {
    os: Option<String>,
    user: Option<String>,
    env_kind: Option<String>,
    now: Option<String>,
    env: BTreeMap<String, String>,
    root_owned: Vec<String>,
    scutil_proxy: Option<String>,
    tools: Vec<String>,
}

/// Deliberately has no `Debug`: the environment snapshot must never be printed by accident.
pub struct Harness {
    pub os: Os,
    pub env_kind: EnvKind,
    /// For MDM per-user plists; fixture default `alice`.
    pub user: String,
    root: PathBuf,
    home: PathBuf,
    env: BTreeMap<String, String>,
    now: SystemTime,
    meta: FixtureMeta,
    /// False for `from_fixture` and `with_roots`: no subprocess, ever.
    live: bool,
    /// Built once in the constructor; immutable.
    policy: AccessPolicy,
    /// Resolved tool homes, indexed by `ToolHome::index`.
    homes: [Loc; 3],
    /// `$XDG_CONFIG_HOME` when usable, else `~/.config`.
    xdg: Loc,
    /// Relocation notes, per tool.
    notes: Vec<(Tool, String)>,
}

/// Everything a constructor decides; `Harness::assemble` derives the rest.
struct Parts {
    os: Os,
    env_kind: EnvKind,
    user: String,
    root: PathBuf,
    home: PathBuf,
    env: BTreeMap<String, String>,
    now: SystemTime,
    meta: FixtureMeta,
    live: bool,
}

/// `Some(rel)` when `s` is `~/rel` with no `..` component.
fn tilde_rel(s: &str) -> Option<&str> {
    let rel = s.strip_prefix("~/")?;
    no_dotdot(rel).then_some(rel)
}

fn no_dotdot(p: &str) -> bool {
    Path::new(p)
        .components()
        .all(|c| !matches!(c, Component::ParentDir))
}

impl Harness {
    fn assemble(p: Parts) -> Harness {
        let mut h = Harness {
            os: p.os,
            env_kind: p.env_kind,
            user: p.user,
            root: p.root,
            home: p.home,
            env: p.env,
            now: p.now,
            meta: p.meta,
            live: p.live,
            policy: AccessPolicy::new(
                Path::new(""),
                Path::new(""),
                &ToolHomes {
                    claude: PathBuf::new(),
                    codex: PathBuf::new(),
                    copilot: PathBuf::new(),
                },
                Path::new(""),
            ),
            homes: [Loc::empty(), Loc::empty(), Loc::empty()],
            xdg: Loc::empty(),
            notes: Vec::new(),
        };
        for which in ToolHome::ALL {
            let (loc, note) = h.resolve_home(which);
            h.homes[which.index()] = loc;
            if let Some(n) = note {
                h.notes.push((which.tool(), n));
            }
        }
        h.xdg = h.resolve_xdg();
        h.policy = AccessPolicy::new(
            &h.root,
            &h.home,
            &ToolHomes {
                claude: h.homes[0].physical.clone(),
                codex: h.homes[1].physical.clone(),
                copilot: h.homes[2].physical.clone(),
            },
            &h.xdg.physical,
        );
        h
    }

    /// The location a usable absolute or `~/` value names, or `None`.
    fn usable_dir(&self, value: &str) -> Option<Loc> {
        if let Some(rel) = tilde_rel(value) {
            return Some(Loc {
                shown: value.to_string(),
                physical: self.home.join(rel),
            });
        }
        if value.starts_with('/') && no_dotdot(value) {
            return Some(Loc {
                shown: redact::display_path(value, &self.home.to_string_lossy()),
                physical: self.root.join(value.trim_start_matches('/')),
            });
        }
        None
    }

    fn resolve_home(&self, which: ToolHome) -> (Loc, Option<String>) {
        let default_rel = which.default_rel();
        let default = || self.home(default_rel);
        match self.env(which.var()) {
            None => (default(), None),
            Some(v) => match self.usable_dir(v) {
                Some(loc) => (loc, None),
                None => (
                    default(),
                    Some(format!(
                        "`{}` is set to a value cAInary can't interpret; showing `~/{default_rel}`",
                        which.var()
                    )),
                ),
            },
        }
    }

    fn resolve_xdg(&self) -> Loc {
        self.env("XDG_CONFIG_HOME")
            .and_then(|v| self.usable_dir(v))
            .unwrap_or_else(|| self.home(".config"))
    }

    /// A display form for a physical path: `~/…` under the home, `/…` under the root.
    fn show(&self, p: &Path) -> String {
        let under = |base: &Path| p.strip_prefix(base).ok().map(Path::to_path_buf);
        let canon_home = fs::canonical(&self.home);
        let shown =
            if let Some(r) = under(&self.home).or_else(|| canon_home.as_deref().and_then(under)) {
                if r.as_os_str().is_empty() {
                    "~".to_string()
                } else {
                    format!("~/{}", r.display())
                }
            } else if let Some(r) = under(&self.root) {
                format!("/{}", r.display())
            } else {
                p.display().to_string()
            };
        redact::display_path(&shown, "")
    }

    pub fn live(env_kind: EnvKind) -> Harness {
        let env = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect::<BTreeMap<_, _>>();
        let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("/var/empty"));
        let user = ["USER", "LOGNAME"]
            .iter()
            .find_map(|k| env.get(*k).filter(|v| !v.is_empty()).cloned())
            .unwrap_or_default();
        Harness::assemble(Parts {
            os: Os::host(),
            env_kind,
            user,
            root: PathBuf::from("/"),
            home,
            env,
            now: SystemTime::now(),
            meta: FixtureMeta::default(),
            live: true,
        })
    }

    /// Hermetic: root, home, env and clock all come from the fixture directory.
    pub fn from_fixture(dir: &Path) -> Result<Harness, String> {
        match fs::stat(dir) {
            Ok(Some(s)) if s.is_dir => {}
            Ok(_) => return Err(format!("fixture not found: {}", dir.display())),
            Err(e) => return Err(format!("fixture {}: {e}", dir.display())),
        }
        let root = dir.join("root");
        let home = dir.join("home");
        // Only fixture.json is read through this policy, so the default homes are enough.
        let policy = AccessPolicy::new(
            &root,
            &home,
            &ToolHomes {
                claude: home.join(".claude"),
                codex: home.join(".codex"),
                copilot: home.join(".copilot"),
            },
            &home.join(".config"),
        );
        let file = dir.join("fixture.json");
        let parsed: FixtureFile = match fs::read(&policy, &file, fs::MAX_FILE_BYTES) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", file.display()))?
            }
            Err(fs::ReadError::Missing) => FixtureFile::default(),
            Err(e) => return Err(format!("{}: {e:?}", file.display())),
        };

        let os = match parsed.os.as_deref() {
            None => Os::host(),
            Some(s) => Os::parse(s).ok_or_else(|| format!("fixture: unknown os `{s}`"))?,
        };
        let env_kind = match parsed.env_kind.as_deref() {
            None => EnvKind::Shell,
            Some(s) => {
                EnvKind::parse(s).ok_or_else(|| format!("fixture: unknown envKind `{s}`"))?
            }
        };
        let now = match parsed.now.as_deref() {
            None => SystemTime::now(),
            Some(s) => parse_rfc3339(s).ok_or_else(|| format!("fixture: bad now `{s}`"))?,
        };
        let tools = parsed
            .tools
            .iter()
            .map(|s| Tool::from_slug(s).ok_or_else(|| format!("fixture: unknown tool `{s}`")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Harness::assemble(Parts {
            os,
            env_kind,
            user: parsed.user.unwrap_or_else(|| "alice".to_string()),
            root,
            home,
            env: parsed.env,
            now,
            meta: FixtureMeta {
                root_owned: parsed.root_owned,
                scutil_proxy: parsed.scutil_proxy,
                tools,
            },
            live: false,
        }))
    }

    /// `--root`/`--home`. The process environment is still visible; no subprocess runs.
    pub fn with_roots(root: PathBuf, home: PathBuf, os: Os) -> Harness {
        let live = Harness::live(EnvKind::Shell);
        Harness::assemble(Parts {
            os,
            env_kind: EnvKind::Shell,
            user: live.user,
            root,
            home,
            env: live.env,
            now: live.now,
            meta: FixtureMeta::default(),
            live: false,
        })
    }

    /// Hermetic and rootless: roots point at nothing. For unit tests on any host.
    #[cfg(test)]
    pub fn test(os: Os, env: &[(&str, &str)]) -> Harness {
        Harness::assemble(Parts {
            os,
            env_kind: EnvKind::Shell,
            user: "alice".to_string(),
            root: PathBuf::from("/cainary-test-nothing/root"),
            home: PathBuf::from("/cainary-test-nothing/home"),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            now: UNIX_EPOCH + Duration::from_secs(1_767_225_600), // 2026-01-01T00:00:00Z
            meta: FixtureMeta::default(),
            live: false,
        })
    }

    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// The fixture's `now`, else the system clock.
    pub fn now(&self) -> SystemTime {
        self.now
    }

    /// The fixture's `tools` filter (empty = no restriction).
    pub fn fixture_tools(&self) -> &[Tool] {
        &self.meta.tools
    }

    /// `/etc/codex/requirements.toml`
    pub fn sys(&self, abs: &str) -> Loc {
        Loc {
            shown: abs.to_string(),
            physical: self.root.join(abs.trim_start_matches('/')),
        }
    }

    /// `~/.codex/config.toml`
    pub fn home(&self, rel: &str) -> Loc {
        let rel = rel.trim_start_matches('/');
        Loc {
            shown: format!("~/{rel}"),
            physical: self.home.join(rel),
        }
    }

    /// The only place the relocation variables are interpreted: absolute or `~/`, no `..`,
    /// otherwise the default.
    pub fn tool_home(&self, which: ToolHome) -> Loc {
        self.homes[which.index()].clone()
    }

    /// Notes for a tool whose relocation variable couldn't be interpreted; `ScanCtx::new`
    /// copies them.
    pub fn notes_for(&self, tool: Tool) -> Vec<String> {
        self.notes
            .iter()
            .filter(|(t, _)| *t == tool)
            .map(|(_, n)| n.clone())
            .collect()
    }

    /// `$XDG_CONFIG_HOME` or `~/.config`.
    pub fn xdg_config(&self, rel: &str) -> Loc {
        self.xdg.join(rel)
    }

    /// macOS `~/Library/Application Support/<name>`; Linux `xdg_config(name)`.
    pub fn app_support(&self, name: &str) -> Loc {
        match self.os {
            Os::Macos => self.home(&format!("Library/Application Support/{name}")),
            Os::Linux => self.xdg_config(name),
        }
    }

    /// macOS: [user plist, device plist]; Linux: empty.
    pub fn mdm(&self, domain: &str) -> Vec<Loc> {
        platform::mdm_paths(self.os, &self.root, &self.user, domain)
            .into_iter()
            .map(|physical| Loc {
                shown: self.show(&physical),
                physical,
            })
            .collect()
    }

    /// An empty value counts as unset.
    pub fn env(&self, name: &str) -> Option<&str> {
        self.env
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// Stat-only lookup in the colon-separated `path` (default: the scan's `PATH`).
    pub fn which(&self, name: &str, path: Option<&str>) -> Which {
        if name.is_empty() || name.contains('/') {
            return Which::NotFound;
        }
        let Some(path) = path.or_else(|| self.env("PATH")) else {
            return Which::NotFound;
        };
        let entries: Vec<&str> = path.split(':').collect();
        if entries
            .iter()
            .any(|e| !e.starts_with('/') || e.contains('$') || e.contains('~'))
        {
            return Which::Unknown;
        }
        for dir in entries {
            let shown = format!("{}/{name}", dir.trim_end_matches('/'));
            let physical = self.root.join(shown.trim_start_matches('/'));
            if let Ok(Some(s)) = fs::stat(&physical)
                && s.is_file
                && s.mode & 0o111 != 0
            {
                return Which::Found(Loc {
                    shown: redact::display_path(&shown, &self.home.to_string_lossy()),
                    physical,
                });
            }
        }
        Which::NotFound
    }
}

impl Loc {
    fn empty() -> Loc {
        Loc {
            shown: String::new(),
            physical: PathBuf::new(),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC only) → `SystemTime`.
fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> {
        let t = &s[a..z];
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec;
    u64::try_from(secs)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    pub(crate) struct Tmp(pub PathBuf);
    impl Tmp {
        pub fn new() -> Tmp {
            let p = std::env::temp_dir().join(format!(
                "cainary-harness-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(p.join("home")).unwrap();
            std::fs::create_dir_all(p.join("root")).unwrap();
            Tmp(std::fs::canonicalize(&p).unwrap())
        }
        pub fn fixture(&self, json: &str) -> Harness {
            std::fs::write(self.0.join("fixture.json"), json).unwrap();
            Harness::from_fixture(&self.0).unwrap()
        }
        pub fn write(&self, rel: &str, body: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn denied(h: &Harness, p: &Path) -> bool {
        h.policy().check(p).is_err()
    }

    #[test]
    fn display_paths_use_tilde() {
        let h = Harness::test(Os::Macos, &[]);
        assert_eq!(h.home(".codex/config.toml").shown, "~/.codex/config.toml");
        assert_eq!(h.tool_home(ToolHome::CodexHome).shown, "~/.codex");
        assert_eq!(
            h.tool_home(ToolHome::ClaudeConfig)
                .join("settings.json")
                .shown,
            "~/.claude/settings.json"
        );
        assert_eq!(
            h.sys("/etc/codex/requirements.toml").shown,
            "/etc/codex/requirements.toml"
        );
        assert_eq!(h.xdg_config("gh").shown, "~/.config/gh");
        assert_eq!(
            h.app_support("Claude").shown,
            "~/Library/Application Support/Claude"
        );
        let l = Harness::test(Os::Linux, &[("XDG_CONFIG_HOME", "/data/xdg")]);
        assert_eq!(l.app_support("Claude").shown, "/data/xdg/Claude");
        assert!(h.notes_for(Tool::Codex).is_empty());
    }

    #[test]
    fn codex_home_is_used_and_policy_follows() {
        let h = Harness::test(Os::Linux, &[("CODEX_HOME", "/data/cx")]);
        let loc = h.tool_home(ToolHome::CodexHome);
        assert_eq!(loc.shown, "/data/cx");
        assert_eq!(loc.join("config.toml").shown, "/data/cx/config.toml");
        assert!(h.notes_for(Tool::Codex).is_empty());
        let root = Path::new("/cainary-test-nothing/root");
        assert!(denied(&h, &root.join("data/cx/auth.json")));
        // the default stays denied when a relocation is set
        assert!(denied(
            &h,
            Path::new("/cainary-test-nothing/home/.codex/auth.json")
        ));
        assert!(!denied(&h, &root.join("data/cx/config.toml")));
    }

    #[test]
    fn tilde_relocation_is_used() {
        let h = Harness::test(Os::Linux, &[("COPILOT_HOME", "~/cp")]);
        assert_eq!(h.tool_home(ToolHome::CopilotHome).shown, "~/cp");
        assert!(denied(
            &h,
            Path::new("/cainary-test-nothing/home/cp/config.json")
        ));
    }

    #[test]
    fn bad_relocations_fall_back_with_a_note() {
        let h = Harness::test(
            Os::Macos,
            &[
                ("CLAUDE_CONFIG_DIR", "rel/x"),
                ("CODEX_HOME", "~/../x"),
                ("COPILOT_HOME", "/a/../etc"),
            ],
        );
        assert_eq!(h.tool_home(ToolHome::ClaudeConfig).shown, "~/.claude");
        assert_eq!(h.tool_home(ToolHome::CodexHome).shown, "~/.codex");
        assert_eq!(h.tool_home(ToolHome::CopilotHome).shown, "~/.copilot");
        assert_eq!(
            h.notes_for(Tool::ClaudeCode),
            ["`CLAUDE_CONFIG_DIR` is set to a value cAInary can't interpret; showing `~/.claude`"]
        );
        assert_eq!(h.notes_for(Tool::Codex).len(), 1);
        assert_eq!(h.notes_for(Tool::Copilot).len(), 1);
        assert!(h.notes_for(Tool::Cursor).is_empty());
        // an empty value is unset, with no note
        let e = Harness::test(Os::Macos, &[("CODEX_HOME", "")]);
        assert!(e.notes_for(Tool::Codex).is_empty());
    }

    #[test]
    fn mdm_order_is_user_then_device() {
        let h = Harness::test(Os::Macos, &[]);
        let shown: Vec<String> = h
            .mdm("com.example.app")
            .into_iter()
            .map(|l| l.shown)
            .collect();
        assert_eq!(
            shown,
            [
                "/Library/Managed Preferences/alice/com.example.app.plist",
                "/Library/Managed Preferences/com.example.app.plist"
            ]
        );
        assert!(
            Harness::test(Os::Linux, &[])
                .mdm("com.example.app")
                .is_empty()
        );
    }

    #[test]
    fn env_empty_is_unset() {
        let h = Harness::test(Os::Linux, &[("A", "1"), ("B", "")]);
        assert_eq!(h.env("A"), Some("1"));
        assert_eq!(h.env("B"), None);
        assert_eq!(h.env("C"), None);
    }

    #[test]
    fn which_found_not_found_unknown() {
        let t = Tmp::new();
        t.write("root/usr/bin/acme-tool", b"#!/bin/sh\n");
        t.write("root/usr/bin/data-file", b"x");
        let bin = t.0.join("root/usr/bin");
        for (name, mode) in [("acme-tool", 0o755), ("data-file", 0o644)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        let h = t.fixture(r#"{ "env": { "PATH": "/opt/none:/usr/bin" } }"#);
        match h.which("acme-tool", None) {
            Which::Found(l) => assert_eq!(l.shown, "/usr/bin/acme-tool"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            h.which("data-file", None),
            Which::NotFound,
            "not executable"
        );
        assert_eq!(h.which("missing", None), Which::NotFound);
        assert_eq!(h.which("acme-tool", Some("/opt/none")), Which::NotFound);
        for bad in [
            "/usr/bin:rel/bin",
            "/usr/bin:",
            "$HOME/bin:/usr/bin",
            "~/bin",
        ] {
            assert_eq!(h.which("acme-tool", Some(bad)), Which::Unknown, "{bad}");
        }
        assert_eq!(h.which("a/b", None), Which::NotFound);
    }

    #[test]
    fn fixture_defaults_and_keys() {
        let t = Tmp::new();
        let h = t.fixture(
            r#"{ "os": "linux", "user": "bob", "envKind": "launchd", "now": "2026-01-01T00:00:00Z",
                 "env": {"X": "1"}, "rootOwned": ["/etc/a"], "scutilProxy": "p",
                 "tools": ["codex", "cursor"] }"#,
        );
        assert_eq!(h.os, Os::Linux);
        assert_eq!(h.user, "bob");
        assert_eq!(h.env_kind, EnvKind::Launchd);
        assert_eq!(h.env("X"), Some("1"));
        assert_eq!(h.fixture_tools(), [Tool::Codex, Tool::Cursor]);
        assert_eq!(h.now(), UNIX_EPOCH + Duration::from_secs(1_767_225_600));
        assert_eq!(h.meta.root_owned, ["/etc/a"]);
        assert_eq!(h.meta.scutil_proxy.as_deref(), Some("p"));
        assert!(!h.live);

        let d = t.fixture("{}");
        assert_eq!(d.user, "alice");
        assert_eq!(d.env_kind, EnvKind::Shell);
        assert!(d.fixture_tools().is_empty());
    }

    #[test]
    fn fixture_errors() {
        let t = Tmp::new();
        for bad in [
            r#"{ "bogus": 1 }"#,
            r#"{ "os": "windows" }"#,
            r#"{ "envKind": "tty" }"#,
            r#"{ "now": "yesterday" }"#,
            r#"{ "tools": ["vim"] }"#,
            "not json",
        ] {
            std::fs::write(t.0.join("fixture.json"), bad).unwrap();
            assert!(Harness::from_fixture(&t.0).is_err(), "{bad}");
        }
        assert!(Harness::from_fixture(&t.0.join("nope")).is_err());
    }

    #[test]
    fn missing_fixture_json_means_defaults() {
        let t = Tmp::new();
        assert!(Harness::from_fixture(&t.0).is_ok());
    }

    #[test]
    fn rfc3339_parse() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(
            parse_rfc3339("2000-03-01T12:34:56Z"),
            Some(UNIX_EPOCH + Duration::from_secs(951_914_096))
        );
        for bad in [
            "2026-13-01T00:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00",
            "",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
    }
}
