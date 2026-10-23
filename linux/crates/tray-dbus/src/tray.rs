//! The StatusNotifierItem (ksni): icon, tooltip and menu. Clicks become [`UiEvent`]s; the
//! controller owns all state and pushes it back as a [`TrayUpdate`].

use async_channel::Sender;
use ksni::menu::{MenuItem, StandardItem, SubMenu};
use ksni::{Category, Icon, Status, ToolTip};

use crate::events::{TrayUpdate, UiEvent};

pub struct CainaryTray {
    pub state: TrayUpdate,
    /// Extra icon theme directory for private installs; empty for the system theme.
    pub icon_theme_path: String,
    pub events: Sender<UiEvent>,
}

impl CainaryTray {
    fn send(&self, event: UiEvent) {
        // Unbounded: never blocks the D-Bus thread. A closed channel means we are exiting.
        let _ = self.events.try_send(event);
    }

    fn item(label: &str, event: UiEvent) -> MenuItem<Self> {
        StandardItem {
            label: label.into(),
            activate: Box::new(move |t: &mut Self| t.send(event.clone())),
            ..Default::default()
        }
        .into()
    }
}

impl ksni::Tray for CainaryTray {
    fn id(&self) -> String {
        crate::APP_ID.into()
    }

    fn title(&self) -> String {
        "cAInary".into()
    }

    fn category(&self) -> Category {
        Category::ApplicationStatus
    }

    // Never `NeedsAttention`: Plasma animates it, and the badge already says what needs a look.
    fn status(&self) -> Status {
        Status::Active
    }

    fn icon_theme_path(&self) -> String {
        self.icon_theme_path.clone()
    }

    fn icon_name(&self) -> String {
        self.state.icon_name.clone()
    }

    fn attention_icon_name(&self) -> String {
        self.state.icon_name.clone()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.state
            .pixmaps
            .iter()
            .map(|p| Icon {
                width: p.width,
                height: p.height,
                data: p.argb.clone(),
            })
            .collect()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: self.state.icon_name.clone(),
            icon_pixmap: Vec::new(),
            title: self.state.tooltip_title.clone(),
            description: self.state.tooltip_body.clone(),
        }
    }

    fn activate(&mut self, x: i32, y: i32) {
        // The host's xdg-activation token, if any, lets a layer-shell popup take focus.
        let token = ksni::current_xdg_activation_token().or_else(|| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ksni::current_xdg_activation_token()
        });
        self.send(UiEvent::TogglePopup { x, y, token });
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        self.send(UiEvent::Refresh);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = self
            .state
            .menu_rows
            .iter()
            .map(|row| {
                StandardItem {
                    // Underscores are mnemonics in dbusmenu; a tool name may contain one.
                    label: row.replace('_', "__"),
                    enabled: false,
                    ..Default::default()
                }
                .into()
            })
            .collect();
        items.push(MenuItem::Separator);
        items.extend([
            Self::item("Open _details", UiEvent::ShowDetails { entry: None }),
            Self::item("_Refresh now", UiEvent::Refresh),
        ]);
        let mut copy = StandardItem {
            label: "_Copy report".into(),
            enabled: self.state.can_copy,
            ..Default::default()
        };
        copy.activate = Box::new(|t: &mut Self| t.send(UiEvent::CopyReport));
        items.push(copy.into());
        items.extend([
            MenuItem::Separator,
            Self::item("_Settings…", UiEvent::OpenSettings),
            Self::item("_About cAInary", UiEvent::OpenAbout),
            SubMenu {
                label: "Support _Ukraine".into(),
                submenu: vec![
                    Self::item(
                        "Come Back Alive",
                        UiEvent::OpenUrl {
                            url: "https://savelife.in.ua/en/donate-en/".into(),
                        },
                    ),
                    Self::item(
                        "Sternenko Fund",
                        UiEvent::OpenUrl {
                            url: "https://www.sternenkofund.org/en/donate".into(),
                        },
                    ),
                    Self::item(
                        "Prytula Foundation",
                        UiEvent::OpenUrl {
                            url: "https://prytulafoundation.org/en/donation".into(),
                        },
                    ),
                ],
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            Self::item("_Quit cAInary", UiEvent::Quit),
        ]);
        items
    }

    // Watcher changes reach the controller through `watcher.rs`, which also knows the state at
    // startup.
    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        // Keep the item: it registers again when a watcher comes back.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksni::Tray;

    fn label(item: &MenuItem<CainaryTray>) -> &str {
        match item {
            MenuItem::Standard(item) => &item.label,
            MenuItem::Separator => "─",
            MenuItem::SubMenu(item) => &item.label,
            _ => "<other>",
        }
    }

    #[test]
    fn menu_has_the_linux_parity_order_and_support_submenu() {
        let (events, _rx) = async_channel::unbounded();
        let tray = CainaryTray {
            state: TrayUpdate {
                menu_rows: vec!["Claude: MEDIUM".into()],
                can_copy: false,
                ..Default::default()
            },
            icon_theme_path: String::new(),
            events,
        };
        let items = tray.menu();
        let labels = items.iter().map(label).collect::<Vec<_>>();
        assert_eq!(
            labels,
            [
                "Claude: MEDIUM",
                "─",
                "Open _details",
                "_Refresh now",
                "_Copy report",
                "─",
                "_Settings…",
                "_About cAInary",
                "Support _Ukraine",
                "─",
                "_Quit cAInary",
            ]
        );
        let MenuItem::Standard(copy) = &items[4] else {
            panic!("Copy report must be a standard menu item")
        };
        assert!(!copy.enabled);
        let MenuItem::SubMenu(support) = &items[8] else {
            panic!("Support Ukraine must be a submenu")
        };
        assert_eq!(
            support.submenu.iter().map(label).collect::<Vec<_>>(),
            ["Come Back Alive", "Sternenko Fund", "Prytula Foundation"]
        );
    }
}
