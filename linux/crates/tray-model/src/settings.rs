//! The tray's settings, in `$XDG_CONFIG_HOME/cainary/tray.toml`. A missing or unreadable file
//! means the defaults; unknown keys are ignored, so an older build can read a newer file.

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::tray_icon::IconStyle;

/// How often the background scan runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refresh {
    #[serde(rename = "5m")]
    Min5,
    #[default]
    #[serde(rename = "10m")]
    Min10,
    #[serde(rename = "30m")]
    Min30,
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "daily")]
    Daily,
}

impl Refresh {
    /// In the order the Settings page lists them.
    pub const ALL: [Self; 5] = [
        Self::Min5,
        Self::Min10,
        Self::Min30,
        Self::Hour,
        Self::Daily,
    ];

    pub fn interval(self) -> Duration {
        let minutes = match self {
            Self::Min5 => 5,
            Self::Min10 => 10,
            Self::Min30 => 30,
            Self::Hour => 60,
            Self::Daily => 24 * 60,
        };
        Duration::from_secs(minutes * 60)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Min5 => "Every 5 minutes",
            Self::Min10 => "Every 10 minutes",
            Self::Min30 => "Every 30 minutes",
            Self::Hour => "Every hour",
            Self::Daily => "Daily",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(1)
    }

    pub fn from_index(i: usize) -> Self {
        Self::ALL.get(i).copied().unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub refresh: Refresh,
    /// Post a notification when something changes.
    pub notifications: bool,
    /// Mirrors the autostart file; the file is the truth, this is what the user asked for.
    pub launch_at_login: bool,
    /// Start with only the tray icon; off opens the Details window at launch.
    pub start_minimized: bool,
    /// The window's close button hides it to the tray; off quits the app.
    pub close_to_tray: bool,
    pub icon_style: IconStyle,
    /// The Details window's last size (its position can't be set on Wayland).
    pub details_width: u32,
    pub details_height: u32,
    /// Whether the popup's not-installed app rows are expanded.
    #[serde(rename = "notInstalledExpanded")]
    pub not_installed_expanded: bool,
    /// The opt-in local OTel receiver. Its child settings are versioned independently of tray UI.
    pub collector: CollectorSettings,
}

pub const COLLECTOR_PRESETS: [&str; 8] = [
    "email",
    "private-key",
    "jwt",
    "aws-access-key",
    "github-token",
    "anthropic-key",
    "openai-key",
    "slack-token",
];

pub const COLLECTOR_MAX_PATTERNS: usize = 64;
pub const COLLECTOR_MAX_PATTERN_BYTES: usize = 1024;
pub const COLLECTOR_MAX_TLS_HOSTS: usize = 32;
pub const COLLECTOR_MAX_TLS_HOST_BYTES: usize = 253;
const MAX_STORED_CUSTOM_PATTERNS: usize = 64;
const MAX_STORED_PATTERN_FIELD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorSettings {
    pub enabled: bool,
    pub port: u16,
    pub tls: bool,
    pub tls_port: u16,
    pub tls_hosts: Vec<String>,
    pub log_to_file: bool,
    pub log_path: String,
    pub presets: Vec<String>,
    pub notify: bool,
    pub patterns: Vec<CollectorPattern>,
}

impl Default for CollectorSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 4318,
            tls: false,
            tls_port: 8443,
            tls_hosts: Vec::new(),
            log_to_file: false,
            log_path: String::new(),
            presets: COLLECTOR_PRESETS
                .iter()
                .map(|name| (*name).into())
                .collect(),
            notify: true,
            patterns: Vec::new(),
        }
    }
}

impl CollectorSettings {
    /// The input is bounded enough to retain in tray.toml and pass through the settings command.
    /// Individual rows may still be invalid so the UI can explain and skip them.
    pub fn safe_to_store(&self) -> bool {
        self.patterns.len() <= MAX_STORED_CUSTOM_PATTERNS
            && self.patterns.iter().all(|pattern| {
                pattern.name.len() <= MAX_STORED_PATTERN_FIELD_BYTES
                    && pattern.pattern.len() <= MAX_STORED_PATTERN_FIELD_BYTES
            })
            && self.presets.len() <= COLLECTOR_PRESETS.len()
            && self
                .presets
                .iter()
                .all(|name| COLLECTOR_PRESETS.contains(&name.as_str()))
            && self.tls_hosts.len() <= COLLECTOR_MAX_TLS_HOSTS
            && self
                .tls_hosts
                .iter()
                .all(|host| host.len() <= COLLECTOR_MAX_TLS_HOST_BYTES)
    }

    pub fn valid(&self) -> bool {
        (1024..=u16::MAX).contains(&self.port)
            && self.safe_to_store()
            && !self.over_limit()
            && (!self.tls || self.valid_tls_config())
    }

    pub fn tls_host_problem(&self, index: usize) -> Option<&'static str> {
        let host = self.tls_hosts.get(index)?;
        if host.is_empty() {
            return None;
        }
        if !valid_tls_host(&host.to_ascii_lowercase()) {
            return Some(
                "Use a DNS name with at least two labels; wildcards and IP addresses aren't supported.",
            );
        }
        if self.tls_hosts[..index]
            .iter()
            .any(|prior| prior.eq_ignore_ascii_case(host))
        {
            return Some("This host is already listed.");
        }
        None
    }

    pub fn valid_tls_hosts(&self) -> Vec<String> {
        self.tls_hosts
            .iter()
            .enumerate()
            .filter(|(index, host)| self.tls_host_problem(*index).is_none() && !host.is_empty())
            .map(|(_, host)| host.to_ascii_lowercase())
            .collect()
    }

    pub fn valid_tls_config(&self) -> bool {
        (1..=u16::MAX).contains(&self.tls_port)
            && !self.valid_tls_hosts().is_empty()
            && self
                .tls_hosts
                .iter()
                .enumerate()
                .all(|(index, host)| host.is_empty() || self.tls_host_problem(index).is_none())
    }

    /// A row with neither field filled in is blank, not an error. Invalid rows are shown inline
    /// and omitted from the helper's config, matching the Linux collector settings contract.
    pub fn pattern_problem(&self, index: usize) -> Option<&'static str> {
        let pattern = self.patterns.get(index)?;
        if pattern.name.is_empty() && pattern.pattern.is_empty() {
            return None;
        }
        if !valid_collector_pattern_name(&pattern.name) {
            return Some(
                "Name: 1–64 characters, a–z, 0–9, - and _, starting with a letter or digit.",
            );
        }
        if COLLECTOR_PRESETS.contains(&pattern.name.as_str()) {
            return Some("That name belongs to a preset.");
        }
        if self.patterns[..index]
            .iter()
            .any(|prior| prior.name == pattern.name)
        {
            return Some("Another pattern has this name.");
        }
        if pattern.pattern.is_empty() {
            return Some("The pattern is empty.");
        }
        if pattern.pattern.len() > COLLECTOR_MAX_PATTERN_BYTES {
            return Some("The pattern is over 1024 bytes.");
        }
        None
    }

    /// The settings passed to the helper, excluding incomplete or invalid rows.
    pub fn valid_patterns(&self) -> Vec<&CollectorPattern> {
        self.patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| {
                (self.pattern_problem(index).is_none() && !pattern.pattern.is_empty())
                    .then_some(pattern)
            })
            .collect()
    }

    /// Includes selected presets in the helper's shared 64-pattern cap.
    pub fn over_limit(&self) -> bool {
        let selected_presets = self
            .presets
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
            .len();
        selected_presets + self.valid_patterns().len() > COLLECTOR_MAX_PATTERNS
    }

    /// Whether a change affects the helper process, rather than tray-only notification behavior.
    pub fn requires_restart(&self, next: &Self) -> bool {
        self.enabled != next.enabled
            || self.port != next.port
            || self.tls != next.tls
            || self.tls_port != next.tls_port
            || self.tls_hosts != next.tls_hosts
            || self.log_to_file != next.log_to_file
            || self.log_path != next.log_path
            || self.presets != next.presets
            || self.patterns != next.patterns
    }

    pub fn suggested_log_path() -> String {
        crate::state_home()
            .map(|dir| dir.join("cainary/otel-debug.jsonl").display().to_string())
            .unwrap_or_default()
    }
}

/// Mirrors `crates/cainary-net/src/host.rs`; callers lowercase before validating.
pub fn valid_tls_host(host: &str) -> bool {
    if host.is_empty() || host.len() > COLLECTOR_MAX_TLS_HOST_BYTES {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |label: &str| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    };
    labels.iter().all(|label| label_ok(label))
        && !labels[labels.len() - 1]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
}

fn valid_collector_pattern_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectorPatternKind {
    #[default]
    Text,
    Regex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorPattern {
    pub name: String,
    pub kind: CollectorPatternKind,
    pub pattern: String,
    #[serde(default)]
    pub case_sensitive: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            refresh: Refresh::default(),
            notifications: true,
            launch_at_login: false,
            start_minimized: true,
            close_to_tray: true,
            icon_style: IconStyle::default(),
            details_width: 780,
            details_height: 560,
            not_installed_expanded: false,
            collector: CollectorSettings::default(),
        }
    }
}

impl Settings {
    /// `$XDG_CONFIG_HOME/cainary/tray.toml`.
    pub fn default_path() -> Option<PathBuf> {
        crate::config_home().map(|d| d.join("cainary/tray.toml"))
    }

    pub fn load(path: &Path) -> Self {
        Self::load_checked(path).0
    }

    /// The settings and, when the file exists but can't be read or parsed, why defaults are in
    /// use. A missing file is not an error.
    pub fn load_checked(path: &Path) -> (Self, Option<String>) {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => return (Self::default(), Some(format!("{}: {e}", path.display()))),
        };
        match toml::from_str(&text) {
            Ok(settings) => (settings, None),
            Err(e) => (
                Self::default(),
                Some(format!("{}: {}", path.display(), e.message())),
            ),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = toml::to_string(self).map_err(io::Error::other)?;
        write_atomic(path, text.as_bytes(), 0o644)
    }
}

/// A hard-to-guess suffix for temporary names (no `rand` crate: `RandomState` is OS-seeded).
pub(crate) fn random_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// Writes `bytes` to a fresh temporary file next to `path` and renames it over, so a crash never
/// leaves half a file. The temporary is created exclusively (`O_EXCL`) with `O_NOFOLLOW` under a
/// random name, so a planted file or symlink makes the write fail instead of being followed.
/// Parent directories that don't exist are created private to the user (0o700).
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    if !dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", random_suffix()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
