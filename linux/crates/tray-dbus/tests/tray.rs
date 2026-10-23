//! The StatusNotifierItem against a fake StatusNotifierWatcher: it registers, shows the state
//! it was given, follows updates, and turns clicks and menu items into events.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cainary_tray_dbus::{Command, Options, Service, TrayUpdate, UiEvent};
use common::{async_io_sleep, block_on, next_matching, own, session};
use zbus::zvariant::{OwnedValue, Value};

#[derive(Clone, Default)]
struct FakeWatcher {
    items: Arc<Mutex<Vec<String>>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl FakeWatcher {
    fn register_status_notifier_item(&self, service: String) {
        self.items.lock().unwrap().push(service);
    }

    fn register_status_notifier_host(&self, _service: String) {}

    #[zbus(property)]
    fn registered_status_notifier_items(&self) -> Vec<String> {
        self.items.lock().unwrap().clone()
    }

    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn protocol_version(&self) -> i32 {
        0
    }
}

fn update(icon: &str) -> TrayUpdate {
    TrayUpdate {
        icon_name: icon.into(),
        tooltip_title: "cAInary".into(),
        tooltip_body: "MEDIUM · Claude Code runs through Amazon Bedrock (1 tool to review)".into(),
        menu_rows: vec!["Claude: MEDIUM".into(), "my_tool: OK".into()],
        can_copy: true,
        pixmaps: Vec::new(),
    }
}

type Layout = (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);

/// Labels and enabled flags of the top-level menu, in order (separators have no label).
fn labels(layout: &Layout) -> Vec<(String, bool, i32)> {
    layout
        .2
        .iter()
        .map(|child| {
            let v = Value::try_from(child).unwrap();
            let inner = match v {
                Value::Value(b) => *b,
                v => v,
            };
            let (id, props, _): Layout = inner.try_into().unwrap();
            let label = props
                .get("label")
                .and_then(|v| String::try_from(v.clone()).ok())
                .unwrap_or_default();
            let enabled = props
                .get("enabled")
                .and_then(|v| bool::try_from(v.clone()).ok())
                .unwrap_or(true);
            (label, enabled, id)
        })
        .collect()
}

#[test]
fn registers_shows_state_and_sends_clicks() {
    block_on(async {
        let Some(host) = session().await else { return };
        let fake = FakeWatcher::default();
        host.object_server()
            .at("/StatusNotifierWatcher", fake.clone())
            .await
            .unwrap();
        if !own(&host, "org.kde.StatusNotifierWatcher").await {
            return;
        }
        let conn = session().await.unwrap();
        let (tx, rx) = async_channel::unbounded();
        let options = Options {
            icon_theme_path: "/opt/cainary/share/icons".into(),
            tray: update("ua.SkeLLLa.cAInary.tray-plain-symbolic"),
            with_tray: true,
        };
        let mut service = Service::start(conn, options, tx).expect("start the service");
        assert_eq!(
            next_matching(&rx, |e| matches!(e, UiEvent::SniHostChanged(_))).await,
            UiEvent::SniHostChanged(true)
        );
        let name = loop {
            if let Some(n) = fake.items.lock().unwrap().first().cloned() {
                break n;
            }
            async_io_sleep(std::time::Duration::from_millis(50)).await;
        };

        // SNI announces changes with its own signals, not PropertiesChanged: don't cache.
        let item: zbus::Proxy = zbus::proxy::Builder::new(&host)
            .destination(name.clone())
            .unwrap()
            .path("/StatusNotifierItem")
            .unwrap()
            .interface("org.kde.StatusNotifierItem")
            .unwrap()
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .unwrap();
        let prop = |p: &'static str| {
            let item = item.clone();
            async move { item.get_property::<String>(p).await.unwrap() }
        };
        assert_eq!(prop("Id").await, "ua.SkeLLLa.cAInary");
        assert_eq!(prop("Category").await, "ApplicationStatus");
        assert_eq!(
            prop("IconName").await,
            "ua.SkeLLLa.cAInary.tray-plain-symbolic"
        );
        assert_eq!(prop("IconThemePath").await, "/opt/cainary/share/icons");
        assert_eq!(prop("Status").await, "Active");

        service.send(Command::Tray(update(
            "ua.SkeLLLa.cAInary.tray-plain-red2-symbolic",
        )));
        // The update is applied on the D-Bus thread; poll until it lands.
        let mut tries = 0;
        while prop("IconName").await != "ua.SkeLLLa.cAInary.tray-plain-red2-symbolic" {
            tries += 1;
            assert!(tries < 100, "the update never arrived");
            async_io_sleep(std::time::Duration::from_millis(50)).await;
        }
        // Plasma animates NeedsAttention; a high level only changes the picture.
        assert_eq!(prop("Status").await, "Active");

        item.call::<_, _, ()>("Activate", &(120i32, 5i32))
            .await
            .unwrap();
        assert_eq!(
            next_matching(&rx, |e| matches!(e, UiEvent::TogglePopup { .. })).await,
            UiEvent::TogglePopup {
                x: 120,
                y: 5,
                token: None
            }
        );
        item.call::<_, _, ()>("SecondaryActivate", &(0i32, 0i32))
            .await
            .unwrap();
        assert_eq!(
            next_matching(&rx, |e| *e == UiEvent::Refresh).await,
            UiEvent::Refresh
        );

        let menu = zbus::Proxy::new(&host, name, "/MenuBar", "com.canonical.dbusmenu")
            .await
            .unwrap();
        let (_rev, layout): (u32, Layout) = menu
            .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
            .await
            .unwrap();
        let items = labels(&layout);
        let texts: Vec<&str> = items.iter().map(|(l, _, _)| l.as_str()).collect();
        assert_eq!(
            texts,
            [
                "Claude: MEDIUM",
                "my__tool: OK",
                "",
                "Open _details",
                "_Refresh now",
                "_Copy report",
                "",
                "_Settings…",
                "_About cAInary",
                "Support _Ukraine",
                "",
                "_Quit cAInary"
            ]
        );
        assert!(!items[0].1, "summary rows are disabled");
        assert!(
            items[5].1,
            "Copy report should be enabled when a report is available"
        );
        let quit = items.last().unwrap().2;
        menu.call::<_, _, ()>("Event", &(quit, "clicked", Value::from(0i32), 0u32))
            .await
            .unwrap();
        assert_eq!(
            next_matching(&rx, |e| *e == UiEvent::Quit).await,
            UiEvent::Quit
        );

        service.shutdown();
    });
}
