use std::sync::OnceLock;

use async_channel::Sender;
use cainary_tray_dbus::UiEvent;
use cainary_tray_model::store::StoreEvent;

static APP_MESSAGES: OnceLock<Sender<AppMessage>> = OnceLock::new();

#[derive(Debug)]
pub enum AppCommand {
    Refresh,
    MarkAsSeen,
    CopyReport,
    Reveal(String),
    CopyFindingJson {
        entry_id: String,
        finding_id: String,
    },
    SetNotInstalledExpanded(bool),
    SetRefresh(String),
    SetNotifications(bool),
    SetLaunchAtLogin(bool),
    SetStartMinimized(bool),
    SetCloseToTray(bool),
    SetIconStyle(String),
    Quit,
}

pub enum AppMessage {
    Command(AppCommand),
    Ui(UiEvent),
    Store(StoreEvent),
    Clipboard(String),
    Timer,
    Stop,
}

pub fn install(sender: Sender<AppMessage>) {
    let _ = APP_MESSAGES.set(sender);
}

pub fn send(message: AppMessage) {
    if let Some(sender) = APP_MESSAGES.get() {
        let _ = sender.try_send(message);
    }
}
