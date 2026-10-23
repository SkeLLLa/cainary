//! Settings, autostart and CLI lookup: the bits that touch the user's files.

mod common;

use std::os::unix::fs::PermissionsExt;

use cainary_tray_model::settings::{Refresh, Settings};
use cainary_tray_model::{autostart, locate};
use common::temp_dir;

#[test]
fn settings_round_trip_and_default_when_missing_or_broken() {
    let dir = temp_dir("settings");
    let path = dir.join("cainary/tray.toml");
    assert_eq!(Settings::load(&path), Settings::default());
    let s = Settings {
        refresh: Refresh::Daily,
        notifications: false,
        launch_at_login: true,
        ..Settings::default()
    };
    s.save(&path).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("refresh = \"daily\"")
    );
    assert_eq!(Settings::load(&path), s);
    std::fs::write(&path, "refresh = 7\n").unwrap();
    assert_eq!(Settings::load(&path), Settings::default());
    // Unknown keys and missing ones are fine.
    std::fs::write(&path, "future = 1\nnotifications = false\n").unwrap();
    assert!(!Settings::load(&path).notifications);
    assert_eq!(Refresh::default().interval().as_secs(), 600);
}

#[test]
fn autostart_writes_and_removes_the_entry() {
    let dir = temp_dir("autostart");
    let path = dir.join("autostart/ua.SkeLLLa.cAInary.desktop");
    assert!(!autostart::is_enabled(&path));
    autostart::set_enabled(&path, true, "/opt/my apps/cainary-tray").unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("Exec=\"/opt/my apps/cainary-tray\" --autostart\n"));
    assert!(text.contains("X-GNOME-Autostart-enabled=true"));
    assert!(autostart::is_enabled(&path));
    autostart::set_enabled(&path, false, "").unwrap();
    assert!(!path.exists());
    // Turning off twice is fine.
    autostart::set_enabled(&path, false, "").unwrap();
    assert!(autostart::entry("cainary-tray").contains("Exec=cainary-tray --autostart"));
}

#[test]
fn the_cli_is_found_next_to_the_binary_then_in_the_reserved_place() {
    let dir = temp_dir("locate");
    let exe = dir.join("cainary-tray");
    let sibling = dir.join("cainary");
    let system = dir.join("system-cainary");
    let make = |p: &std::path::Path, mode| {
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    assert_eq!(locate::cli_from(None, Some(&exe), &system), None);
    make(&system, 0o755);
    assert_eq!(
        locate::cli_from(None, Some(&exe), &system),
        Some(system.clone())
    );
    make(&sibling, 0o644);
    assert_eq!(
        locate::cli_from(None, Some(&exe), &system),
        Some(system.clone()),
        "a sibling that isn't executable is skipped"
    );
    make(&sibling, 0o755);
    assert_eq!(locate::cli_from(None, Some(&exe), &system), Some(sibling));
    let env = Some("/dev/cainary".into());
    assert_eq!(
        locate::cli_from(env, Some(&exe), &system),
        Some("/dev/cainary".into())
    );
    for relative in ["cainary", "./cainary", "bin/cainary"] {
        assert_eq!(
            locate::cli_from(Some(relative.into()), Some(&exe), &system),
            Some(sibling_or_system(&dir)),
            "a relative CAINARY_CORE ({relative}) is ignored, never resolved via PATH"
        );
    }
}

fn sibling_or_system(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("cainary")
}

#[test]
fn load_checked_reports_unreadable_files_but_not_missing_ones() {
    let dir = temp_dir("settings-checked");
    let path = dir.join("tray.toml");
    assert_eq!(Settings::load_checked(&path), (Settings::default(), None));

    let s = Settings {
        refresh: Refresh::Daily,
        ..Settings::default()
    };
    s.save(&path).unwrap();
    assert_eq!(Settings::load_checked(&path), (s, None));

    std::fs::write(&path, "\u{0}garbage = [").unwrap();
    let (loaded, error) = Settings::load_checked(&path);
    assert_eq!(loaded, Settings::default());
    assert!(error.unwrap().starts_with(&path.display().to_string()));

    // A directory can't be read as a file.
    let (loaded, error) = Settings::load_checked(&dir);
    assert_eq!(loaded, Settings::default());
    assert!(error.is_some());
}
