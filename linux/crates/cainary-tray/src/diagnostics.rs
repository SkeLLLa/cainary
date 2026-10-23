//! `--verbose` logging and the diagnostics block (About → Copy diagnostics, and stderr at startup
//! under `--verbose`). The block has no scan results.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use cainary_tray_model::autostart;
use futures_lite::future;
use zbus::Connection;

use crate::bridge::ffi::ffi;
use crate::placement;
use crate::wlprobe;

static VERBOSE: AtomicBool = AtomicBool::new(false);
static FACTS: OnceLock<Facts> = OnceLock::new();
/// The last `SniHostChanged`: 0 not reported yet, 1 a host is registered, 2 none.
pub static SNI_HOST: AtomicU8 = AtomicU8::new(0);

/// What the startup code learns once and the block repeats.
pub struct Facts {
    pub cli: Option<PathBuf>,
    pub cli_version: String,
    pub settings_path: Option<PathBuf>,
    pub settings_error: Option<String>,
    pub autostart_path: Option<PathBuf>,
}

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn set_facts(facts: Facts) {
    let _ = FACTS.set(facts);
}

/// `eprintln!` with the `cainary-tray:` prefix, only under `--verbose`.
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::diagnostics::verbose() {
            eprintln!("cainary-tray: {}", format_args!($($arg)*));
        }
    };
}
pub(crate) use vlog;

fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Which of the session bus names the diagnostics ask about have an owner.
pub struct BusNames {
    sni_watcher: bool,
    notifications: bool,
}

/// Blocks on the session bus, so never call it from the Qt thread.
pub fn bus_names() -> BusNames {
    future::block_on(async {
        let connection = Connection::session().await.ok()?;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await.ok()?;
        let owned = async |name: &'static str| {
            dbus.name_has_owner(name.try_into().unwrap())
                .await
                .unwrap_or(false)
        };
        Some(BusNames {
            sni_watcher: owned("org.kde.StatusNotifierWatcher").await,
            notifications: owned("org.freedesktop.Notifications").await,
        })
    })
    .unwrap_or(BusNames {
        sni_watcher: false,
        notifications: false,
    })
}

/// `path` with the home directory written as `~`.
fn tilde(path: &std::path::Path) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn path_or_none(path: Option<&PathBuf>) -> String {
    path.map_or_else(|| "none".into(), |path| tilde(path))
}

/// The `key: value` block, one line per key. Qt thread only (it asks Qt).
pub fn collect(bus: &BusNames) -> String {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| "unset".into());
    let mut lines = vec![
        format!("cainary-tray: {}", env!("CARGO_PKG_VERSION")),
        format!(
            "git sha: {}",
            option_env!("CAINARY_GIT_SHA").unwrap_or("unknown")
        ),
        format!(
            "build date: {}",
            option_env!("CAINARY_BUILD_DATE").unwrap_or("unknown")
        ),
        format!("qt: {}", ffi::cainary_qt_version()),
        format!("platform: {}", ffi::cainary_platform_name()),
        format!("XDG_CURRENT_DESKTOP: {}", env("XDG_CURRENT_DESKTOP")),
        format!("XDG_SESSION_TYPE: {}", env("XDG_SESSION_TYPE")),
        format!("placement: {}", placement::current().as_str()),
        format!(
            "layer-shell feature: {}",
            if cfg!(feature = "layer-shell") {
                "on"
            } else {
                "off"
            }
        ),
        format!("layer-shell protocol: {}", yes(wlprobe::has_layer_shell())),
        format!("controls style: {}", ffi::cainary_controls_style()),
        format!(
            "sni watcher: {}",
            if bus.sni_watcher { "present" } else { "absent" }
        ),
        format!(
            "sni host registered: {}",
            match SNI_HOST.load(Ordering::Relaxed) {
                1 => "yes",
                2 => "no",
                _ => "unknown",
            }
        ),
        format!("notifications: {}", yes(bus.notifications)),
    ];
    match FACTS.get() {
        Some(facts) => {
            lines.push(match &facts.cli {
                Some(path) => format!("cli: {}", tilde(path)),
                None => "cli: missing".into(),
            });
            lines.push(format!(
                "cli version: {}",
                if facts.cli_version.is_empty() {
                    "unavailable"
                } else {
                    &facts.cli_version
                }
            ));
            lines.push(match &facts.settings_error {
                Some(error) => format!(
                    "settings: {} defaults (error: {error})",
                    path_or_none(facts.settings_path.as_ref())
                ),
                None => format!(
                    "settings: {} ok",
                    path_or_none(facts.settings_path.as_ref())
                ),
            });
            let on = facts
                .autostart_path
                .as_deref()
                .is_some_and(autostart::is_enabled);
            lines.push(format!(
                "autostart: {} {}",
                path_or_none(facts.autostart_path.as_ref()),
                if on { "on" } else { "off" }
            ));
        }
        None => lines.push("startup facts: not collected".into()),
    }
    lines.push("cli env-kind arg: launchd".into());
    lines.join("\n")
}
