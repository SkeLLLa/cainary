//! What crosses between the D-Bus thread and the controller (plan I5). The controller sends
//! [`Command`]s in; everything the desktop asks for comes back as a [`UiEvent`].

/// Something the desktop asked the app to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEvent {
    /// The tray icon was clicked at (x, y) in screen coordinates (0, 0 when unknown).
    TogglePopup {
        x: i32,
        y: i32,
        /// The tray host's xdg-activation token for the click, when it sent one.
        token: Option<String>,
    },
    ShowDetails {
        entry: Option<String>,
    },
    Refresh,
    OpenSettings,
    OpenAbout,
    CopyReport,
    OpenUrl {
        url: String,
    },
    Quit,
    /// The user clicked a notification about `entry`.
    NotificationActivated {
        entry: String,
    },
    /// A StatusNotifierWatcher appeared (true) or went away (false).
    SniHostChanged(bool),
    /// The machine woke from sleep.
    Resumed,
    /// `FileManager1.ShowItems` failed; the caller opens the parent directory instead.
    RevealFailed {
        path: String,
    },
}

/// An ARGB32 image in network byte order, as `IconPixmap` wants it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pixmap {
    pub width: i32,
    pub height: i32,
    pub argb: Vec<u8>,
}

/// Everything the tray item shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrayUpdate {
    /// The icon's name in the icon theme path, `ua.SkeLLLa.cAInary.tray-…`.
    pub icon_name: String,
    pub tooltip_title: String,
    pub tooltip_body: String,
    /// Disabled rows at the top of the menu, one per tool.
    pub menu_rows: Vec<String>,
    /// Whether the current scan can be copied as a text report.
    pub can_copy: bool,
    /// Fallback pixels for hosts that ignore the icon theme path, at a few sizes.
    pub pixmaps: Vec<Pixmap>,
}

/// One desktop notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The entry it is about: activating it opens Details there, and a newer notification
    /// for the same entry replaces it.
    pub entry: String,
    pub summary: String,
    pub body: String,
}

/// What the controller asks the D-Bus thread to do.
#[derive(Debug)]
pub enum Command {
    Tray(TrayUpdate),
    /// Posts `Notification`; the reply, if asked for, says whether the server took it.
    Notify(Notification, Option<async_channel::Sender<bool>>),
    /// Shows a file in the file manager (falls back via [`UiEvent::RevealFailed`]).
    Reveal(String),
    Shutdown,
}
