//! Single instance (plan I6): the first `cainary-tray` owns `ua.SkeLLLa.cAInary` on the session
//! bus and serves `ua.SkeLLLa.cAInary1`; a later one forwards its request there and exits.

use crate::events::UiEvent;

pub const OBJECT_PATH: &str = "/ua/SkeLLLa/cAInary";
pub const INTERFACE: &str = "ua.SkeLLLa.cAInary1";

/// What a second launch asks the running instance for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Activate,
    ShowDetails(String),
    Refresh,
    Quit,
}

/// The result of trying to become the instance.
pub enum Claim {
    /// We own the name and serve the interface on this connection.
    Primary(zbus::Connection),
    /// Someone else does; forward to it with [`forward`].
    Secondary(zbus::Connection),
}

struct Instance {
    events: async_channel::Sender<UiEvent>,
}

#[zbus::interface(name = "ua.SkeLLLa.cAInary1")]
impl Instance {
    /// A plain second launch: show the Details window.
    async fn activate(&self) {
        let _ = self.events.send(UiEvent::ShowDetails { entry: None }).await;
    }

    /// `cainary-tray --details [entry]`; an empty entry means none in particular.
    async fn show_details(&self, entry: String) {
        let entry = (!entry.is_empty()).then_some(entry);
        let _ = self.events.send(UiEvent::ShowDetails { entry }).await;
    }

    async fn refresh(&self) {
        let _ = self.events.send(UiEvent::Refresh).await;
    }

    async fn quit(&self) {
        let _ = self.events.send(UiEvent::Quit).await;
    }
}

/// Connects to the session bus, serves the interface and asks for the name without queueing.
/// The object is in place before the name is, so a forwarded call can't arrive too early.
pub async fn claim(
    conn: zbus::Connection,
    events: async_channel::Sender<UiEvent>,
) -> zbus::Result<Claim> {
    conn.object_server()
        .at(OBJECT_PATH, Instance { events })
        .await?;
    let flags = zbus::fdo::RequestNameFlags::DoNotQueue.into();
    match conn.request_name_with_flags(crate::APP_ID, flags).await {
        Ok(
            zbus::fdo::RequestNameReply::PrimaryOwner | zbus::fdo::RequestNameReply::AlreadyOwner,
        ) => Ok(Claim::Primary(conn)),
        Ok(_) | Err(zbus::Error::NameTaken) => {
            conn.object_server()
                .remove::<Instance, _>(OBJECT_PATH)
                .await?;
            Ok(Claim::Secondary(conn))
        }
        Err(e) => Err(e),
    }
}

/// Calls the running instance.
pub async fn forward(conn: &zbus::Connection, request: &Request) -> zbus::Result<()> {
    let proxy = zbus::Proxy::new(conn, crate::APP_ID, OBJECT_PATH, INTERFACE).await?;
    match request {
        Request::Activate => proxy.call::<_, _, ()>("Activate", &()).await,
        Request::ShowDetails(entry) => proxy.call("ShowDetails", &(entry.as_str(),)).await,
        Request::Refresh => proxy.call("Refresh", &()).await,
        Request::Quit => proxy.call("Quit", &()).await,
    }
}
