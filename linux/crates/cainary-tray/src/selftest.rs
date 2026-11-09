use std::path::PathBuf;
use std::time::{Duration, Instant};

use cainary_tray_model::fixtures::{self, Scenario};
use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QString, QUrl};

use crate::app::{self, MAIN_QML};
use crate::bridge::ffi::ffi;
use crate::env_defaults;
use crate::placement;
use crate::ui;

const DEADLINE: Duration = Duration::from_secs(60);
/// How long each scenario's window gets to lay out and paint before it is grabbed.
const SETTLE: Duration = Duration::from_millis(400);

pub fn run() -> Result<i32, String> {
    // Before any thread exists: it mutates the process environment.
    env_defaults::before_application(true);
    // Hard stop: a missing window expose or a blocked call must fail, not hang.
    std::thread::spawn(|| {
        std::thread::sleep(DEADLINE);
        eprintln!("cainary-tray: self-test exceeded {DEADLINE:?}");
        std::process::exit(2);
    });

    let mut application = QGuiApplication::new();
    if application.is_null() {
        return Err("could not create QGuiApplication".into());
    }
    ffi::cainary_set_app_identity();
    placement::init_for_self_test();
    ffi::cainary_install_message_handler();
    ffi::cainary_clear_messages();

    let mut engine = QQmlApplicationEngine::new();
    ffi::cainary_install_icon_provider(engine.pin_mut());
    let url = QUrl::from(MAIN_QML);
    engine.pin_mut().load(&url);
    application.pin_mut().process_events();

    if !ui::ready() {
        return Err(format!(
            "QML did not create the popup, details, settings and about windows. Qt messages: {}",
            ffi::cainary_messages()
        ));
    }

    let static_json = cainary_tray_model::strings::static_json(
        env!("CARGO_PKG_VERSION"),
        option_env!("CAINARY_GIT_SHA").unwrap_or("unknown"),
        option_env!("CAINARY_BUILD_DATE").unwrap_or("unknown"),
    )
    .to_string();
    let cli_version = format!("cainary {}", env!("CARGO_PKG_VERSION"));
    ui::app(move |mut controller| {
        controller
            .as_mut()
            .set_static_json(QString::from(static_json));
        controller.set_cli_version(QString::from(cli_version));
    });

    let snapshots = snapshot_directory();
    let mut last_view = String::new();
    let size = snapshot_size();
    for scenario in fixtures::scenarios() {
        show(&scenario, &mut last_view);
        if let Some((width, height)) = size.filter(|_| scenario.window == "details") {
            ffi::cainary_resize_window(&QString::from("details"), width, height);
        }
        settle(&mut application);
        if scenario.dark {
            ffi::cainary_set_dark_palette(true);
            settle(&mut application);
        }
        // Grabbing also hides the window, which the next scenario's popup toggle relies on.
        let path = snapshots
            .as_ref()
            .map(|dir| dir.join(format!("{}.png", scenario.name)))
            .unwrap_or_default();
        let saved = ffi::cainary_grab_window(
            &QString::from(scenario.window),
            &QString::from(path.to_string_lossy().as_ref()),
        );
        if scenario.dark {
            ffi::cainary_set_dark_palette(false);
        }
        if snapshots.is_some() && !saved {
            return Err(format!("could not grab a snapshot of {}", scenario.name));
        }
    }

    if !ffi::cainary_messages().is_empty() {
        return Err(format!(
            "Qt emitted warning or error messages:\n{}",
            ffi::cainary_messages()
        ));
    }
    Ok(0)
}

/// Publishes the scenario's view and settings the way the app does, then opens its window.
fn show(scenario: &Scenario, last_view: &mut String) {
    app::publish_view_state(last_view, &scenario.state, &scenario.settings, false);
    // Native snapshots show the installed app, where Plasma has the notification and file
    // chooser portals; the self-test itself never calls them.
    let native = env_defaults::native_snapshots();
    app::sync_settings(&scenario.settings, "", native, native);
    if let Some(collector) = scenario.collector() {
        ui::collector(move |controller| controller.apply(&collector));
    }
    match scenario.window {
        "popup" => ui::app(|controller| controller.popup_requested(0, 0, &QString::default())),
        "details" => ui::show_details(scenario.selection.to_owned()),
        _ => ui::show_about(),
    }
}

fn settle(application: &mut cxx::UniquePtr<QGuiApplication>) {
    let until = Instant::now() + SETTLE;
    while Instant::now() < until {
        application.pin_mut().process_events();
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `CAINARY_UI_SNAPSHOTS_SIZE=WxH`: the Details window's size for native snapshots (the
/// README's), whose Plasma fonts need more room than the 900x600 default; ignored otherwise.
fn snapshot_size() -> Option<(i32, i32)> {
    if !env_defaults::native_snapshots() {
        return None;
    }
    let value = std::env::var("CAINARY_UI_SNAPSHOTS_SIZE").ok()?;
    let (width, height) = value.split_once('x')?;
    Some((width.parse().ok()?, height.parse().ok()?))
}

/// `CAINARY_UI_SNAPSHOTS`; without it the self-test writes nothing.
fn snapshot_directory() -> Option<PathBuf> {
    std::env::var_os("CAINARY_UI_SNAPSHOTS")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}
