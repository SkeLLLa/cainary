use crate::bridge::ffi::ffi;

/// Sets every Qt-related environment variable. Call first thing in `run()`, before any thread
/// (the D-Bus executor included) or Qt object exists: `set_var` is only sound while the process
/// is single-threaded.
pub fn before_application(self_test: bool) {
    // SAFETY: the caller runs this before spawning any thread or creating any Qt object.
    unsafe {
        if self_test {
            std::env::set_var("QT_QPA_PLATFORM", "offscreen");
            // The portal theme would D-Bus-activate xdg-desktop-portal backends that outlive
            // the self-test and keep its stdout pipe open.
            std::env::set_var("QT_QPA_PLATFORMTHEME", "generic");
            std::env::set_var("QT_NO_XDG_DESKTOP_PORTAL", "1");
            // format_time follows the locale; fixed, the snapshots don't depend on the host's.
            std::env::set_var("LC_ALL", "C.UTF-8");
            // The snapshots show the real icons, not whatever the host's theme has.
            let icons = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/icons");
            if std::env::var_os("CAINARY_ICON_THEME_PATH").is_none()
                && std::path::Path::new(icons).is_dir()
            {
                std::env::set_var("CAINARY_ICON_THEME_PATH", icons);
            }
        }
        add_private_icons_to_search_path();
        if std::env::var_os("QT_QPA_PLATFORMTHEME").is_none() && !is_kde_session() {
            // Avoid loading Qt's qgtk3 platform theme plugin when running on GNOME. Plasma is
            // left alone: Qt then loads plasma-integration, whose palette comes from the same
            // colour scheme the org.kde.desktop style reads, so the two can't disagree.
            std::env::set_var("QT_QPA_PLATFORMTHEME", "xdgdesktopportal");
        }
        if std::env::var_os("QT_QUICK_CONTROLS_STYLE").is_none() {
            std::env::set_var("QT_QUICK_CONTROLS_STYLE", controls_style(self_test));
        }
    }
}

/// A private prefix (the tarball, a dev build) keeps its icons outside the system theme. Qt
/// builds its theme search path from `XDG_DATA_DIRS`, so that prefix's `share` goes in front.
fn add_private_icons_to_search_path() {
    let icons = cainary_tray_model::locate::icon_theme_path();
    let Some(share) = std::path::Path::new(&icons)
        .parent()
        .filter(|_| !icons.is_empty())
    else {
        return;
    };
    let rest = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|dirs| !dirs.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    // SAFETY: only called from `before_application`, while the process is single-threaded.
    unsafe { std::env::set_var("XDG_DATA_DIRS", format!("{}:{rest}", share.display())) };
}

/// `org.kde.desktop` only on Plasma, and only when installed: it paints with the user's
/// Kirigami colours, which match the Qt palette only under plasma-integration. Everywhere else
/// (and in the self-test, whose snapshots must not depend on the host's theme) Fusion, which
/// paints from the palette alone.
fn controls_style(self_test: bool) -> String {
    if self_test || !is_kde_session() {
        return "Fusion".into();
    }
    ffi::cainary_controls_style().to_string()
}

/// Whether this is a KDE Plasma session.
pub fn is_kde_session() -> bool {
    ["KDE_FULL_SESSION", "KDE_SESSION_VERSION"]
        .into_iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
        || std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .split(':')
            .any(|desktop| desktop.contains("kde") || desktop.contains("plasma"))
}
