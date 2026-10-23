//! Is there a tray to show the icon in? Stock GNOME has no StatusNotifierWatcher until the
//! AppIndicator extension is on; then the app opens Details at launch and shows a banner.

use futures_lite::StreamExt;

use crate::events::UiEvent;

pub const WATCHER: &str = "org.kde.StatusNotifierWatcher";

/// Whether a watcher owns its name right now.
pub async fn present(conn: &zbus::Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else {
        return false;
    };
    let Ok(name) = WATCHER.try_into() else {
        return false;
    };
    dbus.name_has_owner(name).await.unwrap_or(false)
}

/// Sends the current state, then [`UiEvent::SniHostChanged`] whenever the watcher comes or goes.
pub async fn watch(
    conn: &zbus::Connection,
    events: async_channel::Sender<UiEvent>,
) -> zbus::Result<()> {
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    let mut changes = dbus
        .receive_name_owner_changed_with_args(&[(0, WATCHER)])
        .await?;
    let _ = events
        .send(UiEvent::SniHostChanged(present(conn).await))
        .await;
    while let Some(signal) = changes.next().await {
        let Ok(args) = signal.args() else { continue };
        let online = args.new_owner().is_some();
        if events.send(UiEvent::SniHostChanged(online)).await.is_err() {
            break;
        }
    }
    Ok(())
}
