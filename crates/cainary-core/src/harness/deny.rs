//! Credential deny-list (architecture.md §6.3).
//!
//! One immutable [`AccessPolicy`] is built per scan from that scan's homes. `check` is pure:
//! it normalizes the path lexically, lower-cases it and matches it against the table. Only
//! `new` does I/O (it canonicalizes the bases through `fs::canonical`).

use super::fs;
use std::path::{Component, Path, PathBuf};

/// A path that must never be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

/// Where each tool's home resolved to (`Harness::tool_home`).
#[derive(Debug, Clone)]
pub struct ToolHomes {
    pub claude: PathBuf,
    pub codex: PathBuf,
    pub copilot: PathBuf,
}

/// The deny-list bound to one scan's homes: denied files, dirs and basenames, absolute and
/// lower-cased. Immutable once built.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    /// Exact paths; may contain `*` wildcards.
    files: Vec<String>,
    /// The directory itself and everything below it.
    dirs: Vec<String>,
    /// Patterns for the last path component; may contain `*`.
    basenames: Vec<&'static str>,
}

const BASENAMES: &[&str] = &[
    ".env",
    ".env.*",
    ".envrc",
    ".credentials*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "*.sqlite",
    "*.vscdb",
    "cookies",
];

impl AccessPolicy {
    pub fn new(root: &Path, home: &Path, homes: &ToolHomes, xdg_config: &Path) -> AccessPolicy {
        let roots = bases(&[root.to_path_buf()]);
        let tilde = bases(&[home.to_path_buf()]);
        let cfg = bases(&[homes.claude.clone(), home.join(".claude")]);
        let codex = bases(&[homes.codex.clone(), home.join(".codex")]);
        let cp = bases(&[homes.copilot.clone(), home.join(".copilot")]);
        let xdg = bases(&[xdg_config.to_path_buf(), home.join(".config")]);

        let mut files = Vec::new();
        let mut dirs = Vec::new();
        // Each entry also contributes the canonical target of its original-case path, so a
        // symlinked `.ssh` or credential file stays denied through its physical alias.
        let add = |out: &mut Vec<String>, bs: &[Base], rel: &str| {
            for b in bs {
                out.push(join(&b.lower, rel));
                if !rel.contains('*')
                    && let Some(c) = fs::canonical(&b.path.join(rel))
                {
                    out.push(normalize(&c));
                }
            }
        };

        for rel in ["auth.json", "history.jsonl"] {
            add(&mut files, &codex, rel);
        }
        for rel in ["config.json", "apps.json"] {
            add(&mut files, &cp, rel);
        }
        for rel in [
            "github-copilot/hosts.json",
            "github-copilot/apps.json",
            "gh/hosts.yml",
        ] {
            add(&mut files, &xdg, rel);
        }
        for rel in [".claude.json", "history.jsonl"] {
            add(&mut files, &cfg, rel);
        }
        for rel in [
            ".claude.json",
            ".docker/config.json",
            ".netrc",
            ".git-credentials",
            ".npmrc",
            ".pypirc",
            ".vault-token",
            ".terraform.d/credentials.tfrc.json",
            ".gemini/oauth_creds.json",
        ] {
            add(&mut files, &tilde, rel);
        }
        add(
            &mut files,
            &roots,
            "Library/Preferences/com.apple.networkextension*.plist",
        );

        for rel in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            ".password-store",
            "Library/Keychains",
            ".mozilla",
            "Library/Cookies",
            "Library/Application Support/Codex",
            "Library/HTTPStorages/com.openai.codex",
            "Library/Application Support/com.openai.chat",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Firefox",
        ] {
            add(&mut dirs, &tilde, rel);
        }
        add(&mut dirs, &roots, "Library/Keychains");
        for rel in ["gcloud", "google-chrome", "chromium"] {
            add(&mut dirs, &xdg, rel);
        }
        for rel in ["sessions", "memories", "log"] {
            add(&mut dirs, &codex, rel);
        }
        for rel in ["projects", "shell-snapshots", "todos"] {
            add(&mut dirs, &cfg, rel);
        }
        add(&mut dirs, &cp, "session-state");

        files.sort();
        files.dedup();
        dirs.sort();
        dirs.dedup();
        AccessPolicy {
            files,
            dirs,
            basenames: BASENAMES.to_vec(),
        }
    }

    /// Pure: lexical normalize, lower-case, match the §6.3 table.
    pub fn check(&self, path: &Path) -> Result<(), Denied> {
        let p = normalize(path);
        let last = p.rsplit('/').next().unwrap_or("");
        let denied = self.files.iter().any(|f| glob(f, &p))
            || self.dirs.iter().any(|d| under(d, &p))
            || self.basenames.iter().any(|b| glob(b, last));
        if denied { Err(Denied) } else { Ok(()) }
    }

    /// `check(dir)` plus "has no denied direct child".
    pub fn may_list(&self, dir: &Path) -> Result<(), Denied> {
        self.check(dir)?;
        let d = normalize(dir);
        let has_child = self
            .files
            .iter()
            .chain(self.dirs.iter())
            .any(|e| parent(e) == d);
        if has_child { Err(Denied) } else { Ok(()) }
    }
}

/// A base directory: normalized lower-case for matching, original case for I/O.
struct Base {
    lower: String,
    path: PathBuf,
}

/// Each path in logical form plus its canonical form (when it exists).
fn bases(paths: &[PathBuf]) -> Vec<Base> {
    let mut out = Vec::new();
    for p in paths {
        out.push(Base {
            lower: normalize(p),
            path: p.clone(),
        });
        if let Some(c) = fs::canonical(p) {
            out.push(Base {
                lower: normalize(&c),
                path: c,
            });
        }
    }
    out.sort_by(|a, b| a.lower.cmp(&b.lower));
    out.dedup_by(|a, b| a.lower == b.lower);
    out
}

/// `base` + `rel`, lower-cased. `base` is already normalized and lower-case.
fn join(base: &str, rel: &str) -> String {
    let rel = rel.to_ascii_lowercase();
    if base == "/" {
        format!("/{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

/// Lexical `.`/`..` removal and ASCII lower-casing. The result is `/a/b` (no trailing slash,
/// `/` for the root). `..` above the root stays at the root.
fn normalize(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().to_ascii_lowercase()),
            Component::ParentDir => {
                parts.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    format!("/{}", parts.join("/"))
}

fn parent(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => "",
    }
}

fn under(dir: &str, p: &str) -> bool {
    p == dir
        || p.strip_prefix(dir)
            .is_some_and(|rest| dir.ends_with('/') || rest.starts_with('/'))
}

/// `*` matches any run of characters (including `/`); everything else is literal.
fn glob(pat: &str, s: &str) -> bool {
    match pat.split_once('*') {
        None => pat == s,
        Some((head, rest)) => {
            let Some(s) = s.strip_prefix(head) else {
                return false;
            };
            (0..=s.len())
                .filter(|i| s.is_char_boundary(*i))
                .any(|i| glob(rest, &s[i..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AccessPolicy {
        let homes = ToolHomes {
            claude: "/home/alice/.claude".into(),
            codex: "/home/alice/.codex".into(),
            copilot: "/home/alice/.copilot".into(),
        };
        AccessPolicy::new(
            Path::new("/"),
            Path::new("/home/alice"),
            &homes,
            Path::new("/home/alice/.config"),
        )
    }

    fn denied(p: &AccessPolicy, path: &str) -> bool {
        p.check(Path::new(path)).is_err()
    }

    #[test]
    fn every_file_row_is_denied() {
        let p = policy();
        for f in [
            "/home/alice/.codex/auth.json",
            "/home/alice/.codex/history.jsonl",
            "/home/alice/.copilot/config.json",
            "/home/alice/.copilot/apps.json",
            "/home/alice/.config/github-copilot/hosts.json",
            "/home/alice/.config/github-copilot/apps.json",
            "/home/alice/.config/gh/hosts.yml",
            "/home/alice/.claude/.claude.json",
            "/home/alice/.claude/history.jsonl",
            "/home/alice/.claude.json",
            "/home/alice/.docker/config.json",
            "/home/alice/.netrc",
            "/home/alice/.git-credentials",
            "/home/alice/.npmrc",
            "/home/alice/.pypirc",
            "/home/alice/.vault-token",
            "/home/alice/.terraform.d/credentials.tfrc.json",
            "/home/alice/.gemini/oauth_creds.json",
            "/Library/Preferences/com.apple.networkextension.plist",
            "/Library/Preferences/com.apple.networkextension.necp.plist",
        ] {
            assert!(denied(&p, f), "{f}");
        }
    }

    #[test]
    fn every_dir_row_is_denied_with_children() {
        let p = policy();
        for d in [
            "/home/alice/.ssh",
            "/home/alice/.gnupg",
            "/home/alice/.aws",
            "/home/alice/.azure",
            "/home/alice/.kube",
            "/home/alice/.config/gcloud",
            "/home/alice/.password-store",
            "/home/alice/Library/Keychains",
            "/Library/Keychains",
            "/home/alice/.codex/sessions",
            "/home/alice/.codex/memories",
            "/home/alice/.codex/log",
            "/home/alice/.claude/projects",
            "/home/alice/.claude/shell-snapshots",
            "/home/alice/.claude/todos",
            "/home/alice/.copilot/session-state",
            "/home/alice/Library/Application Support/Codex",
            "/home/alice/Library/HTTPStorages/com.openai.codex",
            "/home/alice/Library/Application Support/com.openai.chat",
            "/home/alice/Library/Application Support/Google/Chrome",
            "/home/alice/Library/Application Support/Firefox",
            "/home/alice/.mozilla",
            "/home/alice/.config/google-chrome",
            "/home/alice/.config/chromium",
            "/home/alice/Library/Cookies",
        ] {
            assert!(denied(&p, d), "{d}");
            assert!(denied(&p, &format!("{d}/deep/x.txt")), "{d}/deep");
        }
    }

    #[test]
    fn basenames_are_denied_anywhere() {
        let p = policy();
        for f in [
            "/work/proj/.env",
            "/work/proj/.env.local",
            "/work/proj/.envrc",
            "/work/.credentials.json",
            "/x/server.pem",
            "/x/server.key",
            "/x/a.p12",
            "/x/a.pfx",
            "/x/id_rsa",
            "/x/id_rsa.pub",
            "/x/id_ed25519",
            "/x/id_ed25519.pub",
            "/x/a.sqlite",
            "/x/state.vscdb",
            "/x/Cookies",
        ] {
            assert!(denied(&p, f), "{f}");
        }
        assert!(!denied(&p, "/x/environment"));
        assert!(!denied(&p, "/x/keyboard.json"));
    }

    #[test]
    fn relocated_home_is_denied_and_default_stays_denied() {
        let homes = ToolHomes {
            claude: "/home/alice/.claude".into(),
            codex: "/data/cx".into(),
            copilot: "/home/alice/.copilot".into(),
        };
        let p = AccessPolicy::new(
            Path::new("/"),
            Path::new("/home/alice"),
            &homes,
            Path::new("/home/alice/.config"),
        );
        assert!(denied(&p, "/data/cx/sessions/a.jsonl"));
        assert!(denied(&p, "/data/cx/auth.json"));
        assert!(denied(&p, "/home/alice/.codex/auth.json"));
        assert!(denied(&p, "/home/alice/.codex/sessions/a.jsonl"));
        assert!(!denied(&p, "/data/cx/config.toml"));
    }

    #[test]
    fn relocated_xdg_is_denied() {
        let homes = ToolHomes {
            claude: "/home/alice/.claude".into(),
            codex: "/home/alice/.codex".into(),
            copilot: "/home/alice/.copilot".into(),
        };
        let p = AccessPolicy::new(
            Path::new("/"),
            Path::new("/home/alice"),
            &homes,
            Path::new("/cfg"),
        );
        assert!(denied(&p, "/cfg/gcloud/creds.db"));
        assert!(denied(&p, "/home/alice/.config/gcloud"));
    }

    #[test]
    fn case_and_dot_dot_do_not_bypass() {
        let p = policy();
        assert!(denied(&p, "/home/alice/.SSH/ID_RSA"));
        assert!(denied(&p, "/home/alice/.ssh/../.ssh/id_rsa"));
        assert!(denied(&p, "/home/alice/./.ssh/./x"));
        assert!(denied(&p, "/home/alice/.CODEX/Auth.JSON"));
        assert!(denied(&p, "/home/alice/x/../.netrc"));
    }

    #[test]
    fn config_files_are_allowed() {
        let p = policy();
        for f in [
            "/home/alice/.codex/config.toml",
            "/home/alice/.codex/hooks.json",
            "/home/alice/.claude/settings.json",
            "/home/alice/.copilot/settings.json",
            "/Library/Application Support/ClaudeCode/managed-settings.json",
            "/etc/codex/requirements.toml",
            "/Library/Preferences/com.apple.other.plist",
            "/home/alice/.sshx/config",
        ] {
            assert!(!denied(&p, f), "{f}");
        }
    }

    #[test]
    fn may_list_refuses_dirs_with_denied_children() {
        let p = policy();
        for d in [
            "/home/alice/.codex",
            "/home/alice/.copilot",
            "/home/alice/.claude",
            "/home/alice",
            "/home/alice/.config",
            "/home/alice/Library/Application Support",
            "/Library/Preferences",
            "/Library",
        ] {
            assert!(p.may_list(Path::new(d)).is_err(), "{d}");
        }
        assert!(p.may_list(Path::new("/home/alice/.ssh")).is_err());
        assert!(
            p.may_list(Path::new("/Library/Managed Preferences"))
                .is_ok()
        );
        assert!(
            p.may_list(Path::new("/etc/claude-code/managed-settings.d"))
                .is_ok()
        );
        assert!(p.may_list(Path::new("/home/alice/.copilot/hooks")).is_ok());
    }

    #[test]
    fn root_prefixed_entries_follow_the_root() {
        let homes = ToolHomes {
            claude: "/fx/home/.claude".into(),
            codex: "/fx/home/.codex".into(),
            copilot: "/fx/home/.copilot".into(),
        };
        let p = AccessPolicy::new(
            Path::new("/fx/root"),
            Path::new("/fx/home"),
            &homes,
            Path::new("/fx/home/.config"),
        );
        assert!(denied(&p, "/fx/root/Library/Keychains/login.keychain-db"));
        assert!(denied(
            &p,
            "/fx/root/Library/Preferences/com.apple.networkextension.plist"
        ));
        assert!(
            p.may_list(Path::new("/fx/root/Library/Preferences"))
                .is_err()
        );
        assert!(!denied(&p, "/fx/root/etc/codex/requirements.toml"));
    }

    #[test]
    fn symlinked_credential_entries_stay_denied() {
        use std::os::unix::fs::symlink;
        let tmp = std::env::temp_dir().join(format!("cainary-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let home = tmp.join("home");
        let store = tmp.join("ssh-store");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("config"), "SYNTHETIC").unwrap();
        std::fs::write(tmp.join("tok"), "SYNTHETIC").unwrap();
        symlink(&store, home.join(".ssh")).unwrap();
        symlink(store.join("config"), home.join(".claude/settings.json")).unwrap();
        symlink(tmp.join("tok"), home.join(".netrc")).unwrap();
        let homes = ToolHomes {
            claude: home.join(".claude"),
            codex: home.join(".codex"),
            copilot: home.join(".copilot"),
        };
        let p = AccessPolicy::new(Path::new("/"), &home, &homes, &home.join(".config"));
        let real = std::fs::canonicalize(&tmp).unwrap();
        assert!(p.check(&real.join("ssh-store/config")).is_err());
        assert!(p.check(&real.join("ssh-store")).is_err());
        assert!(p.check(&real.join("tok")).is_err());
        assert!(p.check(&home.join(".claude/settings.json")).is_ok());
        let r = crate::harness::fs::read(&p, &home.join(".claude/settings.json"), 1024);
        assert!(r.is_err(), "{r:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn glob_basics() {
        assert!(glob("a*c", "abbbc"));
        assert!(glob("*.pem", "x.pem"));
        assert!(!glob("*.pem", "x.pem2"));
        assert!(glob("id_rsa*", "id_rsa"));
        assert!(!glob(".env.*", ".env"));
    }
}
