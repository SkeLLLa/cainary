//! Resume from sleep: logind's `PrepareForSleep(false)` on the system bus means the machine just
//! woke, and the store rescans.

use futures_lite::StreamExt;

use crate::events::UiEvent;

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

/// Sends [`UiEvent::Resumed`] after every wake. Returns when the signal stream ends; without a
/// system bus or logind it returns an error and the timer alone keeps scanning.
pub async fn watch(events: async_channel::Sender<UiEvent>) -> zbus::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = ManagerProxy::new(&conn).await?;
    let mut stream = proxy.receive_prepare_for_sleep().await?;
    while let Some(signal) = stream.next().await {
        if signal.args().is_ok_and(|a| !a.start) && events.send(UiEvent::Resumed).await.is_err() {
            break;
        }
    }
    Ok(())
}
