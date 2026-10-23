use std::pin::Pin;

use cxx_qt::Threading;
use cxx_qt_lib::{QRect, QString};

use crate::bridge::ffi::ffi;
use crate::controller::{self, AppCommand, AppMessage};
use crate::diagnostics;
use crate::placement;
use crate::ui;

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qrect.h");
        type QRect = cxx_qt_lib::QRect;
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qml_singleton]
        #[qproperty(QString, view_json, cxx_name = "viewJson")]
        #[qproperty(QString, static_json, cxx_name = "staticJson")]
        // Kept for the Settings window's separate CLI scanner row.
        #[qproperty(QString, cli_version, cxx_name = "cliVersion")]
        // Where the popup is placed: "layer-shell", "x11" or "decorated". Fixed at startup.
        #[qproperty(QString, placement, READ, CONSTANT)]
        // The scan's state, apart from the view: a scan starting or ending doesn't rewrite
        // viewJson, so open lists keep their scroll position and expanded rows.
        #[qproperty(bool, busy)]
        #[qproperty(QString, phase)]
        #[qproperty(QString, last_checked, cxx_name = "lastChecked")]
        // Whether the tray icon is up, so closing Details can leave the app running.
        #[qproperty(bool, tray_available, cxx_name = "trayAvailable")]
        type AppController = super::AppControllerRust;

        #[qinvokable]
        fn refresh(self: Pin<&mut AppController>);
        #[qinvokable]
        #[cxx_name = "markAsSeen"]
        fn mark_as_seen(self: Pin<&mut AppController>);
        #[qinvokable]
        #[cxx_name = "copyReport"]
        fn copy_report(self: Pin<&mut AppController>);
        #[qinvokable]
        #[cxx_name = "openDetails"]
        fn open_details(self: Pin<&mut AppController>, selection: &QString);
        #[qinvokable]
        #[cxx_name = "copyFindingJson"]
        fn copy_finding_json(
            self: Pin<&mut AppController>,
            entry_id: &QString,
            finding_id: &QString,
        );
        #[qinvokable]
        #[cxx_name = "setNotInstalledExpanded"]
        fn set_not_installed_expanded(self: Pin<&mut AppController>, expanded: bool);
        #[qinvokable]
        #[cxx_name = "showSettings"]
        fn show_settings(self: Pin<&mut AppController>);
        #[qinvokable]
        #[cxx_name = "showAbout"]
        fn show_about(self: Pin<&mut AppController>);
        #[qinvokable]
        #[cxx_name = "revealPath"]
        fn reveal_path(self: Pin<&mut AppController>, path: &QString);
        // Main.qml calls this just before it shows the popup, with the click's xdg-activation token.
        #[qinvokable]
        #[cxx_name = "setActivationToken"]
        fn set_activation_token(self: &AppController, token: &QString);
        // About's "Copy diagnostics".
        #[qinvokable]
        #[cxx_name = "copyDiagnostics"]
        fn copy_diagnostics(self: &AppController);
        #[qinvokable]
        fn quit(self: Pin<&mut AppController>);
        // The usable area of the screen holding (x, y), for placing the popup on X11.
        #[qinvokable]
        #[cxx_name = "availableArea"]
        fn available_area(self: &AppController, x: i32, y: i32) -> QRect;
        // Main.qml calls this once its windows exist.
        #[qinvokable]
        #[cxx_name = "uiReady"]
        fn ui_ready(self: Pin<&mut AppController>);

        #[qsignal]
        #[cxx_name = "popupRequested"]
        fn popup_requested(self: Pin<&mut AppController>, x: i32, y: i32, token: &QString);
        #[qsignal]
        #[cxx_name = "detailsRequested"]
        fn details_requested(self: Pin<&mut AppController>, selection: &QString);
        #[qsignal]
        #[cxx_name = "settingsRequested"]
        fn settings_requested(self: Pin<&mut AppController>);
        #[qsignal]
        #[cxx_name = "aboutRequested"]
        fn about_requested(self: Pin<&mut AppController>);
        #[qsignal]
        #[cxx_name = "openExternalRequested"]
        fn open_external_requested(self: Pin<&mut AppController>, url: &QString);
        #[qsignal]
        #[cxx_name = "quitRequested"]
        fn quit_requested(self: Pin<&mut AppController>);
    }

    impl cxx_qt::Threading for AppController {}
    impl cxx_qt::Initialize for AppController {}
}

pub struct AppControllerRust {
    view_json: QString,
    static_json: QString,
    cli_version: QString,
    placement: QString,
    busy: bool,
    phase: QString,
    last_checked: QString,
    tray_available: bool,
}

impl Default for AppControllerRust {
    fn default() -> Self {
        Self {
            view_json: QString::default(),
            static_json: QString::default(),
            cli_version: QString::default(),
            placement: QString::from(placement::current().as_str()),
            busy: false,
            phase: QString::from("scanning"),
            last_checked: QString::default(),
            tray_available: false,
        }
    }
}

impl cxx_qt::Initialize for qobject::AppController {
    fn initialize(self: Pin<&mut Self>) {
        ui::register_app(self.qt_thread());
    }
}

impl qobject::AppController {
    fn refresh(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::Refresh));
    }

    fn mark_as_seen(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::MarkAsSeen));
    }

    fn copy_report(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CopyReport));
    }

    fn open_details(mut self: Pin<&mut Self>, selection: &QString) {
        self.as_mut().details_requested(selection);
    }

    fn copy_finding_json(self: Pin<&mut Self>, entry_id: &QString, finding_id: &QString) {
        controller::send(AppMessage::Command(AppCommand::CopyFindingJson {
            entry_id: entry_id.to_string(),
            finding_id: finding_id.to_string(),
        }));
    }

    fn set_not_installed_expanded(self: Pin<&mut Self>, expanded: bool) {
        controller::send(AppMessage::Command(AppCommand::SetNotInstalledExpanded(
            expanded,
        )));
    }

    fn show_settings(mut self: Pin<&mut Self>) {
        self.as_mut().settings_requested();
    }

    fn show_about(mut self: Pin<&mut Self>) {
        self.as_mut().about_requested();
    }

    fn reveal_path(self: Pin<&mut Self>, path: &QString) {
        controller::send(AppMessage::Command(AppCommand::Reveal(path.to_string())));
    }

    fn set_activation_token(&self, token: &QString) {
        let token = token.to_string();
        // SAFETY: Rust's environment lock serialises this against `Command` spawns and
        // `std::env` reads on our other threads (Qt's `qputenv` would not take it). The only
        // other readers are Qt's, on this same thread, when the popup maps.
        unsafe {
            if token.is_empty() {
                std::env::remove_var("XDG_ACTIVATION_TOKEN");
            } else {
                std::env::set_var("XDG_ACTIVATION_TOKEN", token);
            }
        }
    }

    fn copy_diagnostics(&self) {
        // The bus calls block, so they run off the Qt thread; the text is copied back on it.
        std::thread::spawn(|| {
            let bus = diagnostics::bus_names();
            ui::app(move |_| ffi::cainary_copy_text(&QString::from(diagnostics::collect(&bus))));
        });
    }

    fn available_area(&self, x: i32, y: i32) -> QRect {
        ffi::cainary_available_area(x, y)
    }

    fn quit(self: Pin<&mut Self>) {
        self.quit_requested();
    }

    fn ui_ready(self: Pin<&mut Self>) {
        ui::mark_ready();
    }
}
