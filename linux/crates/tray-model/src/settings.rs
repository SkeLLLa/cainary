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
