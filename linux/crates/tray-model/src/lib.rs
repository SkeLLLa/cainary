//! The tray's model: everything that doesn't need Qt or D-Bus. It runs the CLI, keeps the last
//! report, decides what changed and what to say about it, and remembers the user's settings.
//! Like the macOS app it holds no scanning logic of its own.

pub mod autostart;
pub mod baseline;
pub mod change;
pub mod fixtures;
pub mod level;
pub mod locate;
pub mod notify_plan;
pub mod report;
pub mod runner;
pub mod schedule;
pub mod settings;
pub mod store;
pub mod strings;
pub mod summary;
pub mod tray_icon;
pub mod view;

use std::path::PathBuf;

/// The reverse-DNS id shared by the desktop file, the icons, the bus name and the SNI item.
pub const APP_ID: &str = "ua.SkeLLLa.cAInary";

/// `$XDG_CONFIG_HOME`, else `~/.config`. `None` without either (no home to write to).
pub fn config_home() -> Option<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

/// `$XDG_STATE_HOME`, else `~/.local/state`.
pub fn state_home() -> Option<PathBuf> {
    xdg_dir("XDG_STATE_HOME", ".local/state")
}

fn xdg_dir(var: &str, fallback: &str) -> Option<PathBuf> {
    // The spec says relative values are invalid and must be ignored.
    if let Some(dir) = std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Some(dir);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    home.is_absolute().then(|| home.join(fallback))
}
