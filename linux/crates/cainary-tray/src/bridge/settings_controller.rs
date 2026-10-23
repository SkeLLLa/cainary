use std::pin::Pin;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;

use crate::controller::{self, AppCommand, AppMessage};
use crate::ui;

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qml_singleton]
        #[qproperty(
            bool,
            launch_at_login,
            cxx_name = "launchAtLogin",
            READ,
            WRITE = set_launch_at_login,
            NOTIFY = launch_at_login_changed
        )]
        #[qproperty(
            bool,
            start_minimized,
            cxx_name = "startMinimized",
            READ,
            WRITE = set_start_minimized,
            NOTIFY = start_minimized_changed
        )]
        #[qproperty(
            bool,
            close_to_tray,
            cxx_name = "closeToTray",
            READ,
            WRITE = set_close_to_tray,
            NOTIFY = close_to_tray_changed
        )]
        // "monochrome", "full-monochrome" or "color".
        #[qproperty(
            QString,
            icon_style,
            cxx_name = "iconStyle",
            READ,
            WRITE = set_icon_style,
            NOTIFY = icon_style_changed
        )]
        #[qproperty(
            QString,
            refresh,
            READ,
            WRITE = set_refresh,
            NOTIFY = refresh_changed
        )]
        #[qproperty(
            bool,
            notifications,
            READ,
            WRITE = set_notifications,
            NOTIFY = notifications_changed
        )]
        #[qproperty(QString, launch_at_login_error, cxx_name = "launchAtLoginError")]
        #[qproperty(bool, notifications_available, cxx_name = "notificationsAvailable")]
        // Why settings.toml couldn't be read (defaults are in use); empty when it could.
        #[qproperty(QString, load_error, cxx_name = "loadError")]
        type SettingsController = super::SettingsControllerRust;
    }

    unsafe extern "RustQt" {
        #[cxx_name = "setRefresh"]
        fn set_refresh(self: Pin<&mut SettingsController>, value: QString);
        #[cxx_name = "setNotifications"]
        fn set_notifications(self: Pin<&mut SettingsController>, value: bool);
        #[cxx_name = "setLaunchAtLogin"]
        fn set_launch_at_login(self: Pin<&mut SettingsController>, value: bool);
        #[cxx_name = "setStartMinimized"]
        fn set_start_minimized(self: Pin<&mut SettingsController>, value: bool);
        #[cxx_name = "setCloseToTray"]
        fn set_close_to_tray(self: Pin<&mut SettingsController>, value: bool);
        #[cxx_name = "setIconStyle"]
        fn set_icon_style(self: Pin<&mut SettingsController>, value: QString);

        #[qsignal]
        #[cxx_name = "refreshChanged"]
        fn refresh_changed(self: Pin<&mut SettingsController>);
        #[qsignal]
        #[cxx_name = "notificationsChanged"]
        fn notifications_changed(self: Pin<&mut SettingsController>);
        #[qsignal]
        #[cxx_name = "launchAtLoginChanged"]
        fn launch_at_login_changed(self: Pin<&mut SettingsController>);
        #[qsignal]
        #[cxx_name = "startMinimizedChanged"]
        fn start_minimized_changed(self: Pin<&mut SettingsController>);
        #[qsignal]
        #[cxx_name = "closeToTrayChanged"]
        fn close_to_tray_changed(self: Pin<&mut SettingsController>);
        #[qsignal]
        #[cxx_name = "iconStyleChanged"]
        fn icon_style_changed(self: Pin<&mut SettingsController>);
    }

    impl cxx_qt::Threading for SettingsController {}
    impl cxx_qt::Initialize for SettingsController {}
}

pub struct SettingsControllerRust {
    refresh: QString,
    notifications: bool,
    launch_at_login: bool,
    start_minimized: bool,
    close_to_tray: bool,
    icon_style: QString,
    launch_at_login_error: QString,
    notifications_available: bool,
    load_error: QString,
}

impl Default for SettingsControllerRust {
    fn default() -> Self {
        Self {
            refresh: QString::from("10m"),
            notifications: true,
            launch_at_login: false,
            start_minimized: true,
            close_to_tray: true,
            icon_style: QString::from("monochrome"),
            launch_at_login_error: QString::default(),
            notifications_available: false,
            load_error: QString::default(),
        }
    }
}

/// What the controller shows, as the controller thread knows it.
pub struct SettingsView {
    pub refresh: &'static str,
    pub notifications: bool,
    pub launch_at_login: bool,
    pub start_minimized: bool,
    pub close_to_tray: bool,
    pub icon_style: &'static str,
    pub launch_at_login_error: String,
    pub notifications_available: bool,
}

impl cxx_qt::Initialize for qobject::SettingsController {
    fn initialize(self: Pin<&mut Self>) {
        ui::register_settings(self.qt_thread());
    }
}

impl qobject::SettingsController {
    /// Takes the controller thread's settings. Writes the fields and emits the change signals
    /// itself, never through the WRITE setters, which would send the values back as commands.
    pub fn apply(mut self: Pin<&mut Self>, view: &SettingsView) {
        let refresh = QString::from(view.refresh);
        if self.refresh != refresh {
            self.as_mut().rust_mut().refresh = refresh;
            self.as_mut().refresh_changed();
        }
        if self.notifications != view.notifications {
            self.as_mut().rust_mut().notifications = view.notifications;
            self.as_mut().notifications_changed();
        }
        if self.launch_at_login != view.launch_at_login {
            self.as_mut().rust_mut().launch_at_login = view.launch_at_login;
            self.as_mut().launch_at_login_changed();
        }
        if self.start_minimized != view.start_minimized {
            self.as_mut().rust_mut().start_minimized = view.start_minimized;
            self.as_mut().start_minimized_changed();
        }
        if self.close_to_tray != view.close_to_tray {
            self.as_mut().rust_mut().close_to_tray = view.close_to_tray;
            self.as_mut().close_to_tray_changed();
        }
        let icon_style = QString::from(view.icon_style);
        if self.icon_style != icon_style {
            self.as_mut().rust_mut().icon_style = icon_style;
            self.as_mut().icon_style_changed();
        }
        self.as_mut()
            .set_launch_at_login_error(QString::from(view.launch_at_login_error.as_str()));
        self.set_notifications_available(view.notifications_available);
    }

    fn set_refresh(mut self: Pin<&mut Self>, value: QString) {
        if self.refresh == value {
            return;
        }
        self.as_mut().rust_mut().refresh = value.clone();
        self.as_mut().refresh_changed();
        controller::send(AppMessage::Command(AppCommand::SetRefresh(
            value.to_string(),
        )));
    }

    fn set_notifications(mut self: Pin<&mut Self>, value: bool) {
        if self.notifications == value {
            return;
        }
        self.as_mut().rust_mut().notifications = value;
        self.as_mut().notifications_changed();
        controller::send(AppMessage::Command(AppCommand::SetNotifications(value)));
    }

    fn set_launch_at_login(mut self: Pin<&mut Self>, value: bool) {
        if self.launch_at_login == value {
            return;
        }
        self.as_mut().rust_mut().launch_at_login = value;
        self.as_mut().launch_at_login_changed();
        controller::send(AppMessage::Command(AppCommand::SetLaunchAtLogin(value)));
    }

    fn set_start_minimized(mut self: Pin<&mut Self>, value: bool) {
        if self.start_minimized == value {
            return;
        }
        self.as_mut().rust_mut().start_minimized = value;
        self.as_mut().start_minimized_changed();
        controller::send(AppMessage::Command(AppCommand::SetStartMinimized(value)));
    }

    fn set_close_to_tray(mut self: Pin<&mut Self>, value: bool) {
        if self.close_to_tray == value {
            return;
        }
        self.as_mut().rust_mut().close_to_tray = value;
        self.as_mut().close_to_tray_changed();
        controller::send(AppMessage::Command(AppCommand::SetCloseToTray(value)));
    }

    fn set_icon_style(mut self: Pin<&mut Self>, value: QString) {
        if self.icon_style == value {
            return;
        }
        self.as_mut().rust_mut().icon_style = value.clone();
        self.as_mut().icon_style_changed();
        controller::send(AppMessage::Command(AppCommand::SetIconStyle(
            value.to_string(),
        )));
    }
}
