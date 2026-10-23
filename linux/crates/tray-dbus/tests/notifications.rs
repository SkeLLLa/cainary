//! Notifications against a fake `org.freedesktop.Notifications` server.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cainary_tray_dbus::{Command, Notification, Options, Service, UiEvent};
use common::{async_io_sleep, block_on, next_matching, own, session};
use zbus::zvariant::OwnedValue;

#[derive(Debug, Clone)]
struct Posted {
    app_name: String,
    replaces_id: u32,
    summary: String,
    body: String,
    actions: Vec<String>,
    desktop_entry: String,
}

#[derive(Clone, Default)]
struct FakeServer {
    posted: Arc<Mutex<Vec<Posted>>>,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl FakeServer {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: String,
        replaces_id: u32,
        _app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        let desktop_entry = hints
            .get("desktop-entry")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        let mut posted = self.posted.lock().unwrap();
        posted.push(Posted {
            app_name,
            replaces_id,
            summary,
            body,
            actions,
            desktop_entry,
        });
        // Ids start at 41 so a zero `replaces_id` can't pass by accident.
        40 + posted.len() as u32
    }
}

async fn notify(service: &Service, entry: &str, body: &str) -> bool {
    let (tx, rx) = async_channel::bounded(1);
    let n = Notification {
        entry: entry.into(),
        summary: "Claude · MEDIUM".into(),
        body: body.into(),
    };
    service.send(Command::Notify(n, Some(tx)));
    rx.recv().await.unwrap()
}

#[test]
fn posts_replace_per_entry_and_clicks_open_details() {
    block_on(async {
        let Some(server) = session().await else {
            return;
        };
        let fake = FakeServer::default();
        server
            .object_server()
            .at("/org/freedesktop/Notifications", fake.clone())
            .await
            .unwrap();
        if !own(&server, "org.freedesktop.Notifications").await {
            return;
        }
        let client = session().await.unwrap();
        let (tx, rx) = async_channel::unbounded();
        let options = Options {
            icon_theme_path: String::new(),
            tray: Default::default(),
            with_tray: false,
        };
        let mut service = Service::start(client, options, tx).expect("start the service");

        assert!(notify(&service, "claude", "Bedrock routing was turned on").await);
        assert!(notify(&service, "claude", "Telemetry export was turned on").await);
        let posted = fake.posted.lock().unwrap().clone();
        assert_eq!(posted.len(), 2);
        assert_eq!(posted[0].app_name, "cAInary");
        assert_eq!(posted[0].desktop_entry, "ua.SkeLLLa.cAInary");
        assert_eq!(posted[0].actions, ["default", "Open details"]);
        assert_eq!(posted[0].replaces_id, 0);
        assert_eq!(
            posted[1].replaces_id, 41,
            "a newer one replaces the entry's last"
        );
        assert_eq!(posted[1].summary, "Claude · MEDIUM");
        assert_eq!(posted[1].body, "Telemetry export was turned on");

        // The listener subscribes concurrently with the first post; keep clicking until it
        // has seen one.
        let clicker = async {
            loop {
                server
                    .emit_signal(
                        None::<&str>,
                        "/org/freedesktop/Notifications",
                        "org.freedesktop.Notifications",
                        "ActionInvoked",
                        &(42u32, "default"),
                    )
                    .await
                    .unwrap();
                async_io_sleep(std::time::Duration::from_millis(100)).await;
            }
        };
        let clicked = futures_lite::future::or(
            next_matching(&rx, |e| matches!(e, UiEvent::NotificationActivated { .. })),
            clicker,
        )
        .await;
        assert_eq!(
            clicked,
            UiEvent::NotificationActivated {
                entry: "claude".into()
            }
        );
        service.shutdown();
    });
}
