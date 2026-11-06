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
        let summary = escape_plain_text(&n.summary);
        let body = escape_plain_text(&n.body);
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
                &summary,
                &body,
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

/// Freedesktop notification bodies allow a small markup subset. These values are plain text, so
/// escape markup and control characters before they reach the desktop shell.
pub fn escape_plain_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code <= 0x1f
            || (0x7f..=0x9f).contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
            || matches!(code, 0x200e | 0x200f | 0x061c)
        {
            escaped.push_str(&format!("\\u{{{code:04X}}}"));
        } else {
            match ch {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                _ => escaped.push(ch),
            }
        }
    }
    escaped
}

enum Signal {
    Invoked(ActionInvoked),
    Closed(NotificationClosed),
}

#[cfg(test)]
mod tests {
    use super::escape_plain_text;

    #[test]
    fn notification_text_cannot_add_markup_or_lines() {
        assert_eq!(
            escape_plain_text("<b>bad & text</b>\nsecond\u{202e}"),
            "&lt;b&gt;bad &amp; text&lt;/b&gt;\\u{000A}second\\u{202E}"
        );
    }
}
