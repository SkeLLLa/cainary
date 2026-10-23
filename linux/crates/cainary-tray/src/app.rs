use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use async_channel::{Receiver, Sender};
use cainary_tray_dbus::filemanager::file_uri;
use cainary_tray_dbus::{self, Notification, Options as BusOptions, Service, TrayUpdate, UiEvent};
use cainary_tray_model::notify_plan::Planned;
use cainary_tray_model::runner::Client;
use cainary_tray_model::schedule::Scheduler;
use cainary_tray_model::settings::{Refresh, Settings};
use cainary_tray_model::store::{Notifier, ScanState, Store, StoreEvent, Trigger};
use cainary_tray_model::tray_icon::IconStyle;
use cainary_tray_model::{
    autostart, baseline::BaselineStore, change::ChangeTracker, locate, strings, summary, view,
};
use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QString, QUrl};
use futures_lite::future;
use zbus::Connection;

use crate::bridge::ffi::ffi;
use crate::bridge::settings_controller::SettingsView;
use crate::controller::{self, AppCommand, AppMessage};
use crate::diagnostics::{self, Facts, vlog};
use crate::env_defaults;
use crate::placement;
use crate::tray_icons::TrayIcons;
use crate::ui;

pub(crate) const MAIN_QML: &str = "qrc:/qt/qml/ua/SkeLLLa/cAInary/qml/Main.qml";

/// How long shutdown waits for a scan in flight to be cancelled.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// The last view JSON handed to QML. Assigning an equal string would reset every repeater
/// bound to it, so unchanged views are not published again.
static LAST_VIEW_JSON: Mutex<String> = Mutex::new(String::new());

#[derive(Debug)]
enum BusSetup {
    Primary(Connection),
    Secondary(Connection),
    Unavailable,
}

pub fn run(options: &crate::Options) -> Result<i32, String> {
    env_defaults::before_application(false);

    // Claim the instance name first: a second launch forwards and exits without loading Qt.
    let (ui_sender, ui_receiver) = async_channel::unbounded();
    let bus = connect_bus(ui_sender.clone());
    if let BusSetup::Secondary(connection) = &bus {
        let request = if options.background || options.autostart {
            None
        } else if let Some(entry) = &options.details {
            Some(cainary_tray_dbus::instance::Request::ShowDetails(
                entry.clone().unwrap_or_default(),
            ))
        } else {
            Some(cainary_tray_dbus::instance::Request::Activate)
        };
        if let Some(request) = request {
            future::block_on(cainary_tray_dbus::instance::forward(connection, &request))
                .map_err(|error| format!("could not contact the running cAInary tray: {error}"))?;
        }
        return Ok(0);
    }

    let mut application = QGuiApplication::new();
    if application.is_null() {
        return Err("could not create QGuiApplication".into());
    }
    application
        .pin_mut()
        .set_application_name(&QString::from("cainary-tray"));
    application
        .pin_mut()
        .set_application_display_name(&QString::from("cAInary"));
    application
        .pin_mut()
        .set_application_version(&QString::from(env!("CARGO_PKG_VERSION")));
    ffi::cainary_set_app_identity();
    ffi::cainary_keep_running_without_windows();
    placement::init(options.dev);

    ffi::cainary_install_message_handler();
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
    #[cfg(feature = "layer-shell")]
    if placement::current() == placement::Strategy::LayerShell {
        crate::bridge::layer_shell::layer_shell::cainary_layer_shell_attach();
    }

    let settings_path = Settings::default_path();
    let (mut loaded_settings, settings_error) = settings_path
        .as_deref()
        .map(Settings::load_checked)
        .unwrap_or_default();
    if let Some(error) = &settings_error {
        eprintln!("cainary-tray: settings file unreadable, using defaults: {error}");
        let message = QString::from(error.as_str());
        ui::settings(move |controller| controller.set_load_error(message));
    }
    let autostart_path = autostart::default_path();
    if let Some(path) = autostart_path.as_deref() {
        loaded_settings.launch_at_login = autostart::is_enabled(path);
    }
    let settings = Arc::new(Mutex::new(loaded_settings));
    let initial_settings = lock(&settings).clone();
    let icons = Arc::new(TrayIcons::new());
    let initial_summary = summary::summarize(&ScanState::Scanning { last: None });
    let initial_tray = tray_update(&initial_summary, &icons, &initial_settings);

    let (message_sender, message_receiver) = async_channel::unbounded();
    controller::install(message_sender.clone());
    if let Err(error) = crate::signals::install(message_sender.clone()) {
        eprintln!("cainary-tray: SIGTERM/SIGINT will end the app abruptly: {error}");
    }
    let notifications_available = notifications_available(match &bus {
        BusSetup::Primary(connection) => Some(connection),
        BusSetup::Secondary(connection) => Some(connection),
        BusSetup::Unavailable => None,
    });
    let launch_at_login_error = Arc::new(Mutex::new(String::new()));
    sync_settings(&initial_settings, "", notifications_available);

    let mut service = None;
    let mut bus_commands = None;
    let session_connection = match bus {
        BusSetup::Primary(connection) => {
            match Service::start(
                connection.clone(),
                BusOptions {
                    icon_theme_path: icons.theme_path(),
                    tray: initial_tray,
                    with_tray: true,
                },
                ui_sender,
            ) {
                Ok(running) => {
                    bus_commands = Some(running.commands());
                    service = Some(running);
                    ui::app(|controller| controller.set_tray_available(true));
                    forward_ui_events(ui_receiver, message_sender.clone());
                    Some(connection)
                }
                Err(error) => {
                    eprintln!(
                        "cainary-tray: couldn't start the tray service: {error}; running without it"
                    );
                    None
                }
            }
        }
        BusSetup::Unavailable => {
            eprintln!("cainary-tray: no session bus; running without the tray service");
            None
        }
        BusSetup::Secondary(_) => unreachable!("secondary instance returned above"),
    };

    let cli_path = locate::cli(options.dev);
    let mut client = Client::new(cli_path);
    client.extra_args = locate::scan_args(options.dev);
    let cli_version = client.version();
    diagnostics::set_facts(Facts {
        cli: client.cli.clone(),
        cli_version: cli_version.clone(),
        settings_path: settings_path.clone(),
        settings_error,
        autostart_path: autostart_path.clone(),
    });
    if options.verbose {
        eprintln!("{}", diagnostics::collect(&diagnostics::bus_names()));
    }

    let scanner = client;
    let store_events = message_sender.clone();
    let notifier = AppNotifier {
        commands: bus_commands.clone(),
        notifications: Arc::clone(&settings),
    };
    let store = Store::new(
        scanner,
        notifier,
        BaselineStore::open(BaselineStore::default_dir()),
        ChangeTracker::default(),
        Box::new(move |event| {
            let _ = store_events.try_send(AppMessage::Store(event));
        }),
    );
    let refresh_interval = lock(&settings).refresh.interval();
    let tick_sender = message_sender.clone();
    let scheduler = Arc::new(Mutex::new(Scheduler::start(refresh_interval, move || {
        let _ = tick_sender.try_send(AppMessage::Timer);
    })));
    let worker = match spawn_controller(
        message_receiver,
        store.clone(),
        bus_commands,
        Arc::clone(&settings),
        settings_path,
        autostart_path,
        Arc::clone(&scheduler),
        Arc::clone(&icons),
        Arc::clone(&launch_at_login_error),
        notifications_available,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            lock(&scheduler).stop();
            if let Some(mut service) = service {
                service.shutdown();
            }
            store.shutdown(SHUTDOWN_GRACE);
            return Err(format!("couldn't start the controller thread: {error}"));
        }
    };

    let static_json = strings::static_json(
        env!("CARGO_PKG_VERSION"),
        option_env!("CAINARY_GIT_SHA").unwrap_or("unknown"),
        option_env!("CAINARY_BUILD_DATE").unwrap_or("unknown"),
    );
    let static_json = static_json.to_string();
    ui::app(move |mut controller| {
        controller
            .as_mut()
            .set_static_json(QString::from(static_json));
        controller.set_cli_version(QString::from(cli_version));
    });
    publish_view(&store, &settings);
    store.request(Trigger::Startup);

    let details_entry = options
        .details
        .as_ref()
        .map(|entry| entry.as_deref().unwrap_or(""));
    // Without a tray there is no other way into the app.
    let minimized = options.background || initial_settings.start_minimized;
    if let Some(entry) = details_entry {
        ui::show_details(entry.to_owned());
    } else if !minimized || service.is_none() {
        ui::show_details(String::new());
    }

    let exit_code = application.pin_mut().exec();
    // Ingress first (timer, D-Bus), then end the scan instead of abandoning it, then the
    // controller that was feeding the store.
    lock(&scheduler).stop();
    if let Some(mut service) = service {
        service.shutdown();
    }
    if !store.shutdown(SHUTDOWN_GRACE) {
        eprintln!("cainary-tray: the scan didn't stop in time");
    }
    let _ = message_sender.try_send(AppMessage::Stop);
    let _ = worker.join();
    drop(session_connection);
    Ok(exit_code)
}

fn connect_bus(ui_events: Sender<UiEvent>) -> BusSetup {
    match future::block_on(async {
        let connection = Connection::session().await?;
        cainary_tray_dbus::instance::claim(connection, ui_events).await
    }) {
        Ok(cainary_tray_dbus::instance::Claim::Primary(connection)) => {
            BusSetup::Primary(connection)
        }
        Ok(cainary_tray_dbus::instance::Claim::Secondary(connection)) => {
            BusSetup::Secondary(connection)
        }
        Err(error) => {
            eprintln!("cainary-tray: session bus unavailable: {error}");
            BusSetup::Unavailable
        }
    }
}

fn notifications_available(connection: Option<&Connection>) -> bool {
    let Some(connection) = connection else {
        return false;
    };
    future::block_on(async {
        let Ok(dbus) = zbus::fdo::DBusProxy::new(connection).await else {
            return false;
        };
        let Ok(name) = "org.freedesktop.Notifications".try_into() else {
            return false;
        };
        dbus.name_has_owner(name).await.unwrap_or(false)
    })
}

fn forward_ui_events(receiver: Receiver<UiEvent>, messages: Sender<AppMessage>) {
    let _ = std::thread::Builder::new()
        .name("cainary-ui-events".into())
        .spawn(move || {
            while let Ok(event) = future::block_on(receiver.recv()) {
                let _ = messages.try_send(AppMessage::Ui(event));
            }
        });
}

#[allow(clippy::too_many_arguments)]
fn spawn_controller(
    receiver: Receiver<AppMessage>,
    store: Store,
    bus_commands: Option<Sender<cainary_tray_dbus::Command>>,
    settings: Arc<Mutex<Settings>>,
    settings_path: Option<PathBuf>,
    autostart_path: Option<PathBuf>,
    scheduler: Arc<Mutex<Scheduler>>,
    icons: Arc<TrayIcons>,
    launch_at_login_error: Arc<Mutex<String>>,
    notifications_available: bool,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("cainary-controller".into())
        .spawn(move || {
            let mut has_seen_watcher = false;
            let mut scan_started = None;
            while let Ok(message) = future::block_on(receiver.recv()) {
                match message {
                    AppMessage::Command(command) => handle_command(
                        command,
                        &store,
                        bus_commands.as_ref(),
                        &settings,
                        settings_path.as_deref(),
                        autostart_path.as_deref(),
                        &scheduler,
                        &icons,
                        &launch_at_login_error,
                        notifications_available,
                    ),
                    AppMessage::Ui(event) => handle_ui_event(event, &store, &mut has_seen_watcher),
                    AppMessage::Store(event) => {
                        log_scan(&event, &mut scan_started);
                        publish_state(&store, bus_commands.as_ref(), &icons, &settings)
                    }
                    AppMessage::Clipboard(text) => ui::copy_text(text),
                    AppMessage::Timer => store.request(Trigger::Timer),
                    AppMessage::Stop => break,
                }
            }
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_command(
    command: AppCommand,
    store: &Store,
    bus_commands: Option<&Sender<cainary_tray_dbus::Command>>,
    settings: &Arc<Mutex<Settings>>,
    settings_path: Option<&Path>,
    autostart_path: Option<&Path>,
    scheduler: &Mutex<Scheduler>,
    icons: &TrayIcons,
    launch_at_login_error: &Arc<Mutex<String>>,
    notifications_available: bool,
) {
    match command {
        AppCommand::Refresh => store.request(Trigger::Manual),
        AppCommand::MarkAsSeen => {
            if store.mark_as_seen() {
                publish_view(store, settings);
            }
        }
        AppCommand::CopyReport => copy_report(store),
        AppCommand::Reveal(path) => {
            if let Some(commands) = bus_commands {
                let _ = commands.try_send(cainary_tray_dbus::Command::Reveal(path));
            } else {
                open_parent(&path);
            }
        }
        AppCommand::CopyFindingJson {
            entry_id,
            finding_id,
        } => copy_finding_json(store, &entry_id, &finding_id),
        AppCommand::SetNotInstalledExpanded(expanded) => {
            let mut current = lock(settings);
            if current.not_installed_expanded != expanded {
                current.not_installed_expanded = expanded;
                save_settings(&current, settings_path);
                drop(current);
                publish_view(store, settings);
            }
        }
        AppCommand::SetRefresh(value) => {
            let Some(refresh) = parse_refresh(&value) else {
                publish_settings(settings, launch_at_login_error, notifications_available);
                return;
            };
            let mut current = lock(settings);
            if current.refresh == refresh {
                return;
            }
            current.refresh = refresh;
            lock(scheduler).set_interval(refresh.interval());
            save_settings(&current, settings_path);
            drop(current);
            store.request(Trigger::Settings);
        }
        AppCommand::SetNotifications(value) => {
            let mut current = lock(settings);
            if current.notifications == value {
                return;
            }
            current.notifications = value;
            save_settings(&current, settings_path);
            drop(current);
            store.request(Trigger::Settings);
        }
        AppCommand::SetLaunchAtLogin(value) => {
            let autostart_result = if let Some(path) = autostart_path {
                autostart::set_enabled(path, value, &autostart::current_exe())
                    .map_err(|error| error.to_string())
            } else if value {
                Err("Launch at login isn't available without an XDG config directory.".into())
            } else {
                Ok(())
            };
            if let Err(error) = autostart_result {
                *lock(launch_at_login_error) = error.clone();
                eprintln!("cainary-tray: could not update autostart entry: {error}");
                publish_settings(settings, launch_at_login_error, notifications_available);
                return;
            }
            *lock(launch_at_login_error) = String::new();
            let mut current = lock(settings);
            let changed = current.launch_at_login != value;
            if changed {
                current.launch_at_login = value;
                save_settings(&current, settings_path);
            }
            drop(current);
            publish_settings(settings, launch_at_login_error, notifications_available);
            if changed {
                store.request(Trigger::Settings);
            }
        }
        AppCommand::SetStartMinimized(value) => {
            update_setting(settings, settings_path, |s| &mut s.start_minimized, value);
        }
        AppCommand::SetCloseToTray(value) => {
            update_setting(settings, settings_path, |s| &mut s.close_to_tray, value);
        }
        AppCommand::SetIconStyle(value) => {
            let Some(style) = IconStyle::from_key(&value) else {
                publish_settings(settings, launch_at_login_error, notifications_available);
                return;
            };
            if update_setting(settings, settings_path, |s| &mut s.icon_style, style) {
                publish_tray(store, bus_commands, icons, settings);
            }
        }
        AppCommand::Quit => ui::quit(),
    }
}

/// Sets one setting to `value` and saves the file; false when it already was.
fn update_setting<T: PartialEq>(
    settings: &Arc<Mutex<Settings>>,
    settings_path: Option<&Path>,
    field: impl FnOnce(&mut Settings) -> &mut T,
    value: T,
) -> bool {
    let mut current = lock(settings);
    let slot = field(&mut current);
    if *slot == value {
        return false;
    }
    *slot = value;
    save_settings(&current, settings_path);
    true
}

/// `--verbose`: one line when a scan starts and one when it ends.
fn log_scan(event: &StoreEvent, started: &mut Option<Instant>) {
    match event {
        StoreEvent::Started => {
            *started = Some(Instant::now());
            vlog!("scan: started");
        }
        StoreEvent::Updated(_) => {
            let took = started.take().map(|at| at.elapsed().as_secs_f32());
            vlog!("scan: ok in {:.1}s", took.unwrap_or_default());
        }
        StoreEvent::Failed { error, .. } => {
            *started = None;
            vlog!("scan: failed ({}): {}", error.kind(), error.reason());
        }
    }
}

fn handle_ui_event(event: UiEvent, store: &Store, has_seen_watcher: &mut bool) {
    // The popup click carries an activation token, which stays out of the log.
    match &event {
        UiEvent::TogglePopup { x, y, .. } => vlog!("ui event: TogglePopup({x}, {y})"),
        other => vlog!("ui event: {other:?}"),
    }
    match event {
        UiEvent::TogglePopup { x, y, token } => ui::toggle_popup(x, y, token),
        UiEvent::ShowDetails { entry } => ui::show_details(entry.unwrap_or_default()),
        UiEvent::Refresh => store.request(Trigger::Remote),
        UiEvent::OpenSettings => ui::show_settings(),
        UiEvent::OpenAbout => ui::show_about(),
        UiEvent::CopyReport => copy_report(store),
        UiEvent::OpenUrl { url } => {
            if is_web_url(&url) {
                ui::open_external(url);
            }
        }
        UiEvent::Quit => ui::quit(),
        UiEvent::NotificationActivated { entry } => ui::show_details(entry),
        UiEvent::SniHostChanged(online) => {
            diagnostics::SNI_HOST.store(
                if online { 1 } else { 2 },
                std::sync::atomic::Ordering::Relaxed,
            );
            if !online && !*has_seen_watcher {
                ui::show_details(String::new());
            }
            *has_seen_watcher = true;
        }
        UiEvent::Resumed => store.request(Trigger::Resume),
        UiEvent::RevealFailed { path } => open_parent(&path),
    }
}

fn publish_state(
    store: &Store,
    bus_commands: Option<&Sender<cainary_tray_dbus::Command>>,
    icons: &TrayIcons,
    settings: &Arc<Mutex<Settings>>,
) {
    publish_view(store, settings);
    publish_tray(store, bus_commands, icons, settings);
}

fn publish_tray(
    store: &Store,
    bus_commands: Option<&Sender<cainary_tray_dbus::Command>>,
    icons: &TrayIcons,
    settings: &Arc<Mutex<Settings>>,
) {
    if let Some(commands) = bus_commands {
        let display = summary::summarize(&store.state());
        let settings = lock(settings).clone();
        let _ = commands.try_send(cainary_tray_dbus::Command::Tray(tray_update(
            &display, icons, &settings,
        )));
    }
}

fn publish_view(store: &Store, settings: &Arc<Mutex<Settings>>) {
    // The lock covers reading the state through posting the view, so a publisher holding an
    // older state can't land after a newer one.
    let mut last = lock(&LAST_VIEW_JSON);
    let state = store.state();
    let settings = lock(settings).clone();
    publish_view_state(&mut last, &state, &settings, store.tracking_unavailable());
}

/// Builds the view and scan status for `state` and queues them to QML. `last` is the view
/// JSON handed over before: an equal one isn't assigned again, but the status properties are
/// always set (they only notify when they change).
pub(crate) fn publish_view_state(
    last: &mut String,
    state: &ScanState,
    settings: &Settings,
    tracking_unavailable: bool,
) {
    let format_time =
        |timestamp: &str| ffi::cainary_format_time(&QString::from(timestamp)).to_string();
    let json = view::build(
        state,
        settings,
        tracking_unavailable,
        format_time,
        resolve_reveal_path,
    );
    let status = view::status(state, format_time);
    let json = view_changed(last, &json).then_some(json);
    ui::app(move |mut controller| {
        if let Some(json) = json {
            controller.as_mut().set_view_json(QString::from(json));
        }
        controller.as_mut().set_busy(status.busy);
        controller.as_mut().set_phase(QString::from(status.phase));
        controller.set_last_checked(QString::from(status.last_checked));
    });
}

/// Records `json` as the last published view; false when it equals the previous one.
fn view_changed(last: &mut String, json: &str) -> bool {
    if last == json {
        return false;
    }
    json.clone_into(last);
    true
}

fn resolve_reveal_path(kind: &str, path: &str) -> String {
    if !matches!(kind, "file" | "dir") {
        return String::new();
    }
    let path = if path == "~" {
        std::env::var_os("HOME").map(PathBuf::from)
    } else if let Some(suffix) = path.strip_prefix("~/") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(suffix))
    } else {
        Some(PathBuf::from(path))
    };
    let Some(path) = path.filter(|path| path.is_absolute() && path.exists()) else {
        return String::new();
    };
    path.to_str().unwrap_or_default().to_owned()
}

fn tray_update(display: &summary::Summary, icons: &TrayIcons, settings: &Settings) -> TrayUpdate {
    let (icon_name, pixmaps) = icons.get(display.icon, settings.icon_style);
    TrayUpdate {
        icon_name,
        tooltip_title: "cAInary".into(),
        tooltip_body: display.tooltip_body.clone(),
        menu_rows: display.menu_rows.clone(),
        can_copy: display.can_copy,
        pixmaps,
    }
}

fn copy_report(store: &Store) {
    store.copy_report(|text| {
        if let Some(text) = text {
            controller::send(AppMessage::Clipboard(text));
        }
    });
}

fn copy_finding_json(store: &Store, entry_id: &str, finding_id: &str) {
    let state = store.state();
    let Some(snapshot) = state.last_good() else {
        return;
    };
    let report = &snapshot.report;
    let json = report
        .entry(entry_id)
        .and_then(|entry| {
            entry
                .findings
                .iter()
                .find(|finding| finding.id == finding_id)
        })
        .and_then(|finding| serde_json::to_string_pretty(finding).ok());
    if let Some(json) = json {
        ui::copy_text(json);
    }
}

fn open_parent(path: &str) {
    let selected = Path::new(path);
    let parent = selected
        .parent()
        .filter(|parent| parent.is_absolute())
        .unwrap_or(selected);
    if parent.is_absolute() {
        ui::open_external(file_uri(&parent.to_string_lossy()));
    }
}

fn save_settings(settings: &Settings, path: Option<&Path>) {
    if let Some(path) = path
        && let Err(error) = settings.save(path)
    {
        eprintln!("cainary-tray: could not save settings: {error}");
    }
}

fn publish_settings(
    settings: &Arc<Mutex<Settings>>,
    launch_at_login_error: &Arc<Mutex<String>>,
    notifications_available: bool,
) {
    let current = lock(settings);
    let launch_error = lock(launch_at_login_error).clone();
    sync_settings(&current, &launch_error, notifications_available);
}

pub(crate) fn sync_settings(
    settings: &Settings,
    launch_error: &str,
    notifications_available: bool,
) {
    let view = SettingsView {
        refresh: refresh_key(settings.refresh),
        notifications: settings.notifications,
        launch_at_login: settings.launch_at_login,
        start_minimized: settings.start_minimized,
        close_to_tray: settings.close_to_tray,
        icon_style: settings.icon_style.as_str(),
        launch_at_login_error: launch_error.to_owned(),
        notifications_available,
    };
    ui::settings(move |controller| controller.apply(&view));
}

fn refresh_key(refresh: Refresh) -> &'static str {
    match refresh {
        Refresh::Min5 => "5m",
        Refresh::Min10 => "10m",
        Refresh::Min30 => "30m",
        Refresh::Hour => "1h",
        Refresh::Daily => "daily",
    }
}

fn parse_refresh(value: &str) -> Option<Refresh> {
    match value {
        "5m" => Some(Refresh::Min5),
        "10m" => Some(Refresh::Min10),
        "30m" => Some(Refresh::Min30),
        "1h" => Some(Refresh::Hour),
        "daily" => Some(Refresh::Daily),
        _ => None,
    }
}

/// Only web links leave the app through the D-Bus menu and notifications.
fn is_web_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

struct AppNotifier {
    commands: Option<Sender<cainary_tray_dbus::Command>>,
    notifications: Arc<Mutex<Settings>>,
}

impl Notifier for AppNotifier {
    fn post(&self, planned: &[Planned], is_current: &dyn Fn() -> bool) -> HashSet<String> {
        if !lock(&self.notifications).notifications {
            return planned
                .iter()
                .flat_map(|item| item.change_ids.iter().cloned())
                .collect();
        }
        let Some(commands) = &self.commands else {
            return planned
                .iter()
                .flat_map(|item| item.change_ids.iter().cloned())
                .collect();
        };

        let mut handled = HashSet::new();
        for item in planned {
            if !is_current() {
                break;
            }
            let (reply, result) = async_channel::bounded(1);
            let notification = Notification {
                entry: item.entry.clone(),
                summary: item.summary.clone(),
                body: item.body.clone(),
            };
            if commands
                .try_send(cainary_tray_dbus::Command::Notify(
                    notification,
                    Some(reply),
                ))
                .is_ok()
                && future::block_on(result.recv()).unwrap_or(false)
            {
                handled.extend(item.change_ids.iter().cloned());
            }
        }
        handled
    }
}

#[cfg(test)]
mod tests {
    use super::view_changed;

    #[test]
    fn an_equal_view_is_not_published_twice() {
        let mut last = String::new();
        assert!(view_changed(&mut last, "{\"a\":1}"));
        assert!(!view_changed(&mut last, "{\"a\":1}"));
        assert!(view_changed(&mut last, "{\"a\":2}"));
        assert_eq!(last, "{\"a\":2}");
    }
}
