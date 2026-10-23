//! The only way other threads reach the QML controllers. Both register a [`CxxQtThread`] when
//! QML creates them; every call here is queued onto the Qt main thread, where the closure gets
//! the live object. If a controller is missing or Qt has stopped delivering (shutdown), the call
//! is dropped.

use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use cxx_qt::CxxQtThread;
use cxx_qt_lib::QString;

use crate::bridge::app_controller::qobject::AppController;
use crate::bridge::ffi::ffi;
use crate::bridge::settings_controller::qobject::SettingsController;
use crate::diagnostics::vlog;

static APP: OnceLock<CxxQtThread<AppController>> = OnceLock::new();
static SETTINGS: OnceLock<CxxQtThread<SettingsController>> = OnceLock::new();
static UI_READY: AtomicBool = AtomicBool::new(false);

pub fn register_app(thread: CxxQtThread<AppController>) {
    let _ = APP.set(thread);
}

pub fn register_settings(thread: CxxQtThread<SettingsController>) {
    let _ = SETTINGS.set(thread);
}

/// Called by `Main.qml` once its windows exist.
pub fn mark_ready() {
    UI_READY.store(true, Ordering::Release);
}

/// Both controllers exist and `Main.qml` finished creating its windows.
pub fn ready() -> bool {
    APP.get().is_some() && SETTINGS.get().is_some() && UI_READY.load(Ordering::Acquire)
}

/// Runs `f` on the Qt thread with the `AppController`.
pub fn app(f: impl FnOnce(Pin<&mut AppController>) + Send + 'static) {
    if let Some(thread) = APP.get() {
        let _ = thread.queue(f);
    }
}

/// Runs `f` on the Qt thread with the `SettingsController`.
pub fn settings(f: impl FnOnce(Pin<&mut SettingsController>) + Send + 'static) {
    if let Some(thread) = SETTINGS.get() {
        let _ = thread.queue(f);
    }
}

/// Opens the Details window on `selection` (an entry id, `:changes`, `:sources` or empty).
pub fn show_details(selection: String) {
    app(move |controller| controller.details_requested(&QString::from(selection)));
}

pub fn show_settings() {
    app(|controller| controller.settings_requested());
}

pub fn show_about() {
    app(|controller| controller.about_requested());
}

/// `token` is the tray host's xdg-activation token for this click, if it sent one.
pub fn toggle_popup(x: i32, y: i32, token: Option<String>) {
    vlog!(
        "tray click at ({x}, {y}), xdg-activation token {}",
        if token.is_some() {
            "received"
        } else {
            "absent"
        }
    );
    app(move |controller| {
        #[cfg(feature = "layer-shell")]
        if crate::placement::current() == crate::placement::Strategy::LayerShell {
            crate::bridge::layer_shell::layer_shell::cainary_layer_shell_place(x, y);
        }
        controller.popup_requested(x, y, &QString::from(token.unwrap_or_default()));
    });
}

pub fn quit() {
    app(|controller| controller.quit_requested());
}

/// Hands `url` to the desktop's opener (QML's `Qt.openUrlExternally`).
pub fn open_external(url: String) {
    app(move |controller| controller.open_external_requested(&QString::from(url)));
}

pub fn copy_text(text: String) {
    app(move |_| ffi::cainary_copy_text(&QString::from(text)));
}
