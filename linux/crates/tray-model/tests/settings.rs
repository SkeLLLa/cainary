//! Settings, autostart and CLI lookup: the bits that touch the user's files.

mod common;

use std::os::unix::fs::PermissionsExt;

use cainary_tray_model::settings::{CollectorPattern, CollectorPatternKind, CollectorSettings};
use cainary_tray_model::settings::{Refresh, Settings};
use cainary_tray_model::{autostart, locate};
use common::temp_dir;

#[test]
fn settings_round_trip_and_default_when_missing_or_broken() {
    let dir = temp_dir("settings");
    let path = dir.join("cainary/tray.toml");
    assert_eq!(Settings::load(&path), Settings::default());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // A pre-collector tray.toml continues to load with the opt-in feature disabled.
    std::fs::write(&path, "refresh = \"5m\"\nnotifications = false\n").unwrap();
    let old = Settings::load(&path);
    assert_eq!(old.refresh, Refresh::Min5);
    assert!(!old.notifications);
    assert!(!old.collector.enabled);
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
fn collector_settings_round_trip_with_patterns() {
    let dir = temp_dir("collector-settings");
    let path = dir.join("tray.toml");
    let mut settings = Settings::default();
    settings.collector.enabled = true;
    settings.collector.port = 4444;
    settings.collector.log_to_file = true;
    settings.collector.log_path = "/tmp/otel-debug.jsonl".into();
    settings.collector.patterns.push(CollectorPattern {
        name: "customer".into(),
        kind: CollectorPatternKind::Regex,
        pattern: "acme".into(),
        case_sensitive: true,
    });
    settings.save(&path).unwrap();
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("[collector]"));
    assert!(saved.contains("case_sensitive = true"));
    assert_eq!(Settings::load(&path), settings);
}

#[test]
fn collector_patterns_use_child_name_rules() {
    let pattern = |name: &str| CollectorPattern {
        name: name.into(),
        kind: CollectorPatternKind::Text,
        pattern: "private-pattern".into(),
        case_sensitive: false,
    };
    let mut settings = CollectorSettings::default();
    settings.patterns.push(pattern("customer-id"));
    assert!(settings.valid());

    settings.patterns[0].name = "Customer-ID".into();
    assert!(settings.valid());
    assert!(settings.pattern_problem(0).is_some());
    assert!(settings.valid_patterns().is_empty());
    settings.patterns[0].name = "email".into();
    assert_eq!(
        settings.pattern_problem(0),
        Some("That name belongs to a preset.")
    );
    settings.patterns[0].name = "customer-id".into();
    settings.patterns.push(pattern("customer-id"));
    assert_eq!(
        settings.pattern_problem(1),
        Some("Another pattern has this name.")
    );
    assert_eq!(settings.valid_patterns().len(), 1);
}

#[test]
fn collector_pattern_limits_match_the_helper() {
    let pattern = |name: String, value: String| CollectorPattern {
        name,
        kind: CollectorPatternKind::Regex,
        pattern: value,
        case_sensitive: false,
    };
    let mut settings = CollectorSettings::default();
    settings
        .patterns
        .push(pattern("p".into(), "x".repeat(1024)));
    assert_eq!(settings.pattern_problem(0), None);
    settings.patterns[0].pattern.push('x');
    assert_eq!(
        settings.pattern_problem(0),
        Some("The pattern is over 1024 bytes.")
    );
    assert!(settings.valid());
    assert!(settings.valid_patterns().is_empty());

    settings.patterns[0] = pattern("a".repeat(65), "x".into());
    assert!(settings.pattern_problem(0).is_some());
    settings.patterns[0] = pattern("a".repeat(64), "x".into());
    assert_eq!(settings.pattern_problem(0), None);

    settings.patterns[0] = pattern(String::new(), String::new());
    assert_eq!(settings.pattern_problem(0), None, "empty rows are allowed");
    assert!(settings.valid_patterns().is_empty());
    settings.patterns[0] = pattern("named".into(), String::new());
    assert_eq!(settings.pattern_problem(0), Some("The pattern is empty."));
}

#[test]
fn collector_pattern_limit_includes_selected_presets() {
    let pattern = |index| CollectorPattern {
        name: format!("custom-{index}"),
        kind: CollectorPatternKind::Text,
        pattern: format!("value-{index}"),
        case_sensitive: false,
    };
    let mut settings = CollectorSettings {
        patterns: (0..56).map(pattern).collect(),
        ..CollectorSettings::default()
    };
    assert!(!settings.over_limit());
    assert!(settings.valid());
    settings.patterns.push(pattern(56));
    assert!(settings.over_limit());
    assert!(!settings.valid());
    assert!(
        settings.safe_to_store(),
        "over-limit settings remain editable"
    );
}

#[test]
fn collector_notify_does_not_require_a_child_restart() {
    let current = CollectorSettings::default();
    let mut next = current.clone();
    next.notify = false;
    assert!(!current.requires_restart(&next));

    next = current.clone();
    next.enabled = !next.enabled;
    assert!(current.requires_restart(&next));
    next = current.clone();
    next.port += 1;
    assert!(current.requires_restart(&next));
    next = current.clone();
    next.log_to_file = !next.log_to_file;
    assert!(current.requires_restart(&next));
    next = current.clone();
    next.log_path.push_str("/next");
    assert!(current.requires_restart(&next));
    next = current.clone();
    next.presets.pop();
    assert!(current.requires_restart(&next));
    next = current.clone();
    next.patterns.push(CollectorPattern {
        name: "custom".into(),
        kind: CollectorPatternKind::Text,
        pattern: "value".into(),
        case_sensitive: false,
    });
    assert!(current.requires_restart(&next));
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
