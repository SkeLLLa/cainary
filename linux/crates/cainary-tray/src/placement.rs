use std::sync::OnceLock;

use crate::bridge::ffi::ffi;
use crate::diagnostics::vlog;
use crate::wlprobe;

/// How the popup window is put next to the tray icon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strategy {
    /// A wlr-layer-shell surface anchored near the icon (Wayland compositors that offer it).
    LayerShell,
    /// A frameless window moved to the icon (X11; also any platform that can place windows).
    X11,
    /// An ordinary window the compositor places (GNOME Wayland, which has no layer-shell).
    Decorated,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LayerShell => "layer-shell",
            Self::X11 => "x11",
            Self::Decorated => "decorated",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::LayerShell, Self::X11, Self::Decorated]
            .into_iter()
            .find(|strategy| strategy.as_str() == value)
    }
}

static STRATEGY: OnceLock<Strategy> = OnceLock::new();

/// Decides the strategy once. Call on the Qt main thread after `QGuiApplication` exists and
/// before QML loads, so QML sees the final value when it creates the popup.
pub fn init(dev: bool) {
    STRATEGY.get_or_init(|| {
        let platform = ffi::cainary_platform_name().to_string();
        let forced = dev.then(overridden).flatten();
        let strategy = select(&platform, forced);
        vlog!(
            "placement: {} (platform {platform}{})",
            strategy.as_str(),
            if forced.is_some() { ", forced" } else { "" }
        );
        strategy
    });
}

/// The strategy chosen by [`init`]; X11 (plain placement) if it never ran.
pub fn current() -> Strategy {
    STRATEGY.get().copied().unwrap_or(Strategy::X11)
}

/// Fixes the strategy for the self-test, which runs on the offscreen platform.
pub fn init_for_self_test() {
    let _ = STRATEGY.set(Strategy::X11);
}

/// `CAINARY_PLACEMENT`, honoured under `--dev` only.
fn overridden() -> Option<Strategy> {
    let strategy = std::env::var("CAINARY_PLACEMENT")
        .ok()
        .and_then(|value| Strategy::parse(&value))?;
    if strategy == Strategy::LayerShell && !cfg!(feature = "layer-shell") {
        eprintln!("cainary-tray: CAINARY_PLACEMENT=layer-shell ignored: built without layer-shell");
        return None;
    }
    Some(strategy)
}

fn select(platform: &str, forced: Option<Strategy>) -> Strategy {
    if let Some(strategy) = forced {
        return strategy;
    }
    match platform {
        "wayland" | "wayland-egl"
            if cfg!(feature = "layer-shell") && wlprobe::has_layer_shell() =>
        {
            Strategy::LayerShell
        }
        "wayland" | "wayland-egl" => Strategy::Decorated,
        _ => Strategy::X11,
    }
}

#[cfg(test)]
mod tests {
    use super::{Strategy, select};

    #[test]
    fn xcb_and_unknown_platforms_use_x11() {
        assert_eq!(select("xcb", None), Strategy::X11);
        assert_eq!(select("offscreen", None), Strategy::X11);
    }

    #[test]
    fn a_dev_override_wins() {
        assert_eq!(
            select("xcb", Some(Strategy::Decorated)),
            Strategy::Decorated
        );
    }

    #[test]
    fn strategies_round_trip_through_their_names() {
        for strategy in [Strategy::LayerShell, Strategy::X11, Strategy::Decorated] {
            assert_eq!(Strategy::parse(strategy.as_str()), Some(strategy));
        }
        assert_eq!(Strategy::parse("other"), None);
    }
}
