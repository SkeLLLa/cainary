//! Desktop notifications through `org.freedesktop.Notifications`. Each entry has at most one
//! notification on screen: a newer one replaces it. Clicking one (the `default` action) opens
//! Details at that entry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_lite::StreamExt;
use zbus::zvariant::Value;

use crate::events::{Notification, UiEvent};

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
pub trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// Posts notifications and remembers which id belongs to which entry.
#[derive(Clone)]
pub struct Notifier {
    proxy: NotificationsProxy<'static>,
    /// Notification id → entry, and entry → its latest id (for `replaces_id`).
    ids: Arc<Mutex<Ids>>,
}

#[derive(Default)]
struct Ids {
    entry_of: HashMap<u32, String>,
    latest: HashMap<String, u32>,
}

impl Notifier {
    pub async fn new(conn: &zbus::Connection) -> zbus::Result<Self> {
        Ok(Self {
            proxy: NotificationsProxy::new(conn).await?,
            ids: Arc::default(),
        })
    }

    pub async fn post(&self, n: &Notification) -> zbus::Result<u32> {
        let replaces = self.lock().latest.get(&n.entry).copied().unwrap_or(0);
        let mut hints = HashMap::new();
        hints.insert("desktop-entry", Value::from(crate::APP_ID));
        // Normal urgency: these are changes worth a look, not emergencies.
        hints.insert("urgency", Value::U8(1));
        let id = self
            .proxy
            .notify(
                "cAInary",
                replaces,
                crate::APP_ID,
                &n.summary,
                &n.body,
                &["default", "Open details"],
                hints,
                -1,
            )
            .await?;
        let mut ids = self.lock();
        ids.entry_of.insert(id, n.entry.clone());
        ids.latest.insert(n.entry.clone(), id);
        Ok(id)
    }

    /// Turns clicks on our notifications into [`UiEvent::NotificationActivated`] until the
    /// connection goes away.
    pub async fn listen(&self, events: async_channel::Sender<UiEvent>) -> zbus::Result<()> {
        let mut invoked = self.proxy.receive_action_invoked().await?;
        let mut closed = self.proxy.receive_notification_closed().await?;
        loop {
            let next = futures_lite::future::or(
                async { invoked.next().await.map(Signal::Invoked) },
                async { closed.next().await.map(Signal::Closed) },
            )
            .await;
            match next {
                Some(Signal::Invoked(sig)) => {
                    let Ok(args) = sig.args() else { continue };
                    if args.action_key != "default" {
                        continue;
                    }
                    let entry = self.lock().entry_of.get(&args.id).cloned();
                    if let Some(entry) = entry {
                        let _ = events.send(UiEvent::NotificationActivated { entry }).await;
                    }
                }
                Some(Signal::Closed(sig)) => {
                    if let Ok(args) = sig.args() {
                        let mut ids = self.lock();
                        if let Some(entry) = ids.entry_of.remove(&args.id) {
                            ids.latest.remove(&entry);
                        }
                    }
                }
                None => return Ok(()),
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ids> {
        self.ids.lock().unwrap_or_else(|e| e.into_inner())
    }
}

enum Signal {
    Invoked(ActionInvoked),
    Closed(NotificationClosed),
}
