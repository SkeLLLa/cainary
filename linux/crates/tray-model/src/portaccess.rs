//! What the collector page says and offers about a port below 1024, and how long the tray keeps
//! the reserved sockets. Pure: `privport` finds out what is installed, `runner::bind_privileged`
//! asks for the sockets, the tray app glues them to this table.

use std::time::Duration;

use serde::Serialize;

use crate::privport::{HelperError, PrivState};
use crate::runner::BindError;
use crate::settings::CollectorSettings;

/// How long reserved sockets are kept while the collector is stopped without having been switched
/// off or failed to start (it crashed, or was stopped). Past this the port is released.
pub const STOPPED_HOLD: Duration = Duration::from_secs(10 * 60);

/// The port the collector listens on: the takeover port while HTTPS is on, else the receiver's.
pub fn effective_port(settings: &CollectorSettings) -> u16 {
    if settings.tls {
        settings.tls_port
    } else {
        settings.port
    }
}

/// What the tray knows about reaching the port, without the sockets (those are `Hold`'s).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// An ordinary port: the collector binds it itself.
    NotNeeded,
    /// Looking for the helper.
    Checking,
    NoHelper(String),
    Ready,
    /// A trusted helper of another build; the text says which.
    Mismatch(String),
}

impl Access {
    /// The helper-free part of a [`PrivState`].
    pub fn of(state: &PrivState) -> Self {
        match state {
            PrivState::NotNeeded => Self::NotNeeded,
            PrivState::NoHelper(why) => Self::NoHelper(why.clone()),
            PrivState::Ready { .. } => Self::Ready,
            PrivState::Mismatch { warn, .. } => Self::Mismatch(warn.clone()),
            // Held is the sockets' business; what the helper would say is unknown and unneeded.
            PrivState::Held(_) => Self::Ready,
        }
    }
}

/// Everything the page's wording depends on.
#[derive(Clone, Debug)]
pub struct Inputs<'a> {
    pub port: u16,
    pub access: &'a Access,
    /// The tray holds the reserved sockets for `port`.
    pub held: bool,
    /// The collector process is starting or listening.
    pub running: bool,
    /// The user has the collector switched on.
    pub enabled: bool,
    /// An authentication prompt is open.
    pub opening: bool,
    /// A development checkout, which installs the helper by hand.
    pub dev: bool,
    /// Why the last attempt to open the port failed.
    pub error: Option<&'a str>,
    /// Said while the port is held (only IPv4 could be reserved).
    pub notice: Option<&'a str>,
}

/// The `privilege` object of the collector view JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeView {
    /// `none`, `checking`, `no-helper`, `ready`, `mismatch`, `opening`, `held` or `held-stopped`.
    pub state: &'static str,
    pub port: u16,
    pub heading: String,
    pub detail: String,
    pub warning: String,
    pub error: String,
    /// Lines to copy and run as an administrator; the tray never runs them.
    pub instructions: Vec<String>,
    /// Whether the "Open port N" button is offered.
    pub can_open: bool,
    pub busy: bool,
}

pub fn view(inputs: &Inputs) -> PrivilegeView {
    let port = inputs.port;
    let mut view = PrivilegeView {
        state: "none",
        port,
        error: inputs.error.unwrap_or_default().to_owned(),
        ..PrivilegeView::default()
    };
    if matches!(inputs.access, Access::NotNeeded) && !inputs.held {
        view.error.clear();
        return view;
    }
    let needs = format!("Port {port} needs administrator permission");
    if inputs.held {
        view.warning = inputs.notice.unwrap_or_default().to_owned();
        if inputs.running {
            view.state = "held";
            view.heading = format!("Port {port} is open for the collector");
        } else {
            view.state = "held-stopped";
            view.heading = format!("Port {port} reserved; collector stopped");
            view.detail = "Retry starts it on the same port without asking again. Switching the \
                           collector off, or changing the port, gives the port back."
                .into();
        }
        return view;
    }
    if inputs.opening {
        view.state = "opening";
        view.heading = needs;
        view.detail = "Waiting for you to authenticate…".into();
        view.can_open = true;
        view.busy = true;
        return view;
    }
    match inputs.access {
        Access::NotNeeded => {}
        Access::Checking => {
            view.state = "checking";
            view.heading = format!("Checking the port helper for port {port}…");
        }
        Access::NoHelper(why) => {
            view.state = "no-helper";
            view.heading = needs;
            let why = sentence(why);
            if inputs.dev {
                view.detail = format!(
                    "{why} Build the helper, then run the commands it prints as an \
                     administrator. Or use a port of 1024 or above."
                );
                view.instructions = vec!["mise run linux:helper".into()];
            } else {
                view.detail = format!(
                    "{why} Install or upgrade the cainary package to get it. Or use a port of \
                     1024 or above."
                );
            }
        }
        Access::Ready | Access::Mismatch(_) => {
            view.state = if matches!(inputs.access, Access::Mismatch(_)) {
                "mismatch"
            } else {
                "ready"
            };
            view.heading = needs;
            if let Access::Mismatch(warn) = inputs.access {
                view.warning = format!("Port helper out of date: {warn}. It is still used.");
            }
            if inputs.enabled {
                view.detail = "cAInary asks once, with the system's authentication dialog, \
                               then keeps the port until the collector is switched off."
                    .into();
                view.can_open = true;
            } else {
                view.detail =
                    "Switch the collector on to open it; you are asked once, in the system's \
                     authentication dialog."
                        .into();
            }
        }
    }
    view
}

/// `reason` as a sentence: capitalised, with a full stop.
fn sentence(reason: &str) -> String {
    let reason = reason.trim().trim_end_matches('.');
    let mut chars = reason.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// What starting the collector does about its port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    /// Switched off.
    Disabled,
    /// The port needs root and isn't held: nothing starts until the user clicks "Open port N".
    /// Starting the tray, saving settings and Retry never ask for the privilege.
    NeedsOpen,
    /// Start the collector; with `inherit` it gets the held sockets as `--listen-fd`.
    Run { inherit: bool },
}

pub fn launch_plan(enabled: bool, needs_privilege: bool, held: bool) -> Launch {
    match (enabled, needs_privilege, held) {
        (false, _, _) => Launch::Disabled,
        (true, true, false) => Launch::NeedsOpen,
        (true, true, true) => Launch::Run { inherit: true },
        (true, false, _) => Launch::Run { inherit: false },
    }
}

/// The model's message for a collector that can't start until the port is opened.
pub fn needs_message(port: u16) -> String {
    format!("Port {port} needs administrator permission")
}

/// What the user is told when opening the port failed: a short line, and for the unexpected
/// failures the longer reason, for the log.
pub fn bind_failure(error: &BindError, port: u16) -> (String, Option<String>) {
    match error {
        BindError::Dismissed => ("Cancelled".into(), None),
        BindError::NotAuthorized => ("Not authorized".into(), None),
        BindError::TimedOut => ("Timed out waiting for authentication".into(), None),
        BindError::Helper(HelperError::PortInUse) => {
            (format!("Port {port} is already in use"), None)
        }
        BindError::ProtocolMismatch(_) => (
            "The port helper is out of date; update it".into(),
            Some(error.reason()),
        ),
        _ => (format!("Couldn't open port {port}"), Some(error.reason())),
    }
}

/// A place for the sockets reserved for one port. Generic so the lifecycle can be tested without
/// sockets; the tray stores [`crate::runner::Reserved`].
#[derive(Debug)]
pub struct Hold<T> {
    held: Option<(u16, T)>,
}

impl<T> Default for Hold<T> {
    fn default() -> Self {
        Self { held: None }
    }
}

/// What ends a reservation (requirement 7 of the security review).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// The collector was switched off, or the page has no collector to run.
    Off,
    /// Another port is wanted.
    PortChanged,
    /// The collector exited before it reported `hello` (a startup failure, not a crash).
    StartupFailed,
    /// The tray quits.
    Quit,
    /// A stopped collector held the port for too long.
    Expired,
}

impl<T> Hold<T> {
    pub fn port(&self) -> Option<u16> {
        self.held.as_ref().map(|(port, _)| *port)
    }

    pub fn holds(&self, port: u16) -> bool {
        self.port() == Some(port)
    }

    pub fn get(&self, port: u16) -> Option<&T> {
        self.held
            .as_ref()
            .filter(|(held, _)| *held == port)
            .map(|(_, reservation)| reservation)
    }

    /// Keeps `reservation` for `port`; whatever was held before is dropped (closed).
    pub fn keep(&mut self, port: u16, reservation: T) {
        self.held = Some((port, reservation));
    }

    /// Drops the reservation (closing the tray's copy of the sockets) and says which port it was.
    pub fn release(&mut self, _why: Release) -> Option<u16> {
        self.held.take().map(|(port, _)| port)
    }

    /// Releases the reservation unless it is for `wanted`.
    pub fn keep_only(&mut self, wanted: Option<u16>) -> Option<u16> {
        match (self.port(), wanted) {
            (Some(held), Some(wanted)) if held == wanted => None,
            (Some(_), Some(_)) => self.release(Release::PortChanged),
            (Some(_), None) => self.release(Release::Off),
            (None, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(access: &'a Access) -> Inputs<'a> {
        Inputs {
            port: 443,
            access,
            held: false,
            running: false,
            enabled: true,
            opening: false,
            dev: false,
            error: None,
            notice: None,
        }
    }

    #[test]
    fn an_ordinary_port_says_nothing() {
        let v = view(&inputs(&Access::NotNeeded));
        assert_eq!(v.state, "none");
        assert!(!v.can_open);
    }

    #[test]
    fn no_helper_explains_and_has_no_button() {
        let access = Access::NoHelper("the port helper isn't installed".into());
        let v = view(&inputs(&access));
        assert_eq!(v.state, "no-helper");
        assert_eq!(v.heading, "Port 443 needs administrator permission");
        assert!(
            v.detail
                .starts_with("The port helper isn't installed. Install or upgrade")
        );
        assert!(v.instructions.is_empty());
        assert!(!v.can_open);

        let v = view(&Inputs {
            dev: true,
            ..inputs(&access)
        });
        assert_eq!(v.instructions, vec!["mise run linux:helper".to_string()]);
        assert!(!v.can_open);
    }

    #[test]
    fn ready_and_mismatch_offer_the_button_only_while_the_collector_is_on() {
        let v = view(&inputs(&Access::Ready));
        assert_eq!((v.state, v.can_open, v.busy), ("ready", true, false));
        assert!(v.warning.is_empty());

        let access = Access::Mismatch("the helper is version 0.0.1, this app is 0.2.0".into());
        let v = view(&inputs(&access));
        assert_eq!((v.state, v.can_open), ("mismatch", true));
        assert!(v.warning.contains("version 0.0.1"));

        let off = view(&Inputs {
            enabled: false,
            ..inputs(&Access::Ready)
        });
        assert_eq!((off.state, off.can_open), ("ready", false));
    }

    #[test]
    fn the_prompt_open_disables_the_button() {
        let v = view(&Inputs {
            opening: true,
            ..inputs(&Access::Ready)
        });
        assert_eq!((v.state, v.can_open, v.busy), ("opening", true, true));
    }

    #[test]
    fn held_ports_say_open_or_reserved() {
        let running = view(&Inputs {
            held: true,
            running: true,
            ..inputs(&Access::Ready)
        });
        assert_eq!(running.state, "held");
        assert!(!running.can_open);
        let stopped = view(&Inputs {
            held: true,
            ..inputs(&Access::Ready)
        });
        assert_eq!(stopped.state, "held-stopped");
        assert_eq!(stopped.heading, "Port 443 reserved; collector stopped");
        assert!(!stopped.can_open);
    }

    #[test]
    fn checking_and_errors() {
        let v = view(&inputs(&Access::Checking));
        assert_eq!(v.state, "checking");
        let v = view(&Inputs {
            error: Some("Cancelled"),
            ..inputs(&Access::Ready)
        });
        assert_eq!(v.error, "Cancelled");
        // An ordinary port drops a stale error.
        let v = view(&Inputs {
            error: Some("Cancelled"),
            ..inputs(&Access::NotNeeded)
        });
        assert_eq!(v.error, "");
    }

    #[test]
    fn bind_errors_have_short_messages() {
        let message = |e: BindError| bind_failure(&e, 443);
        assert_eq!(message(BindError::Dismissed), ("Cancelled".into(), None));
        assert_eq!(
            message(BindError::NotAuthorized),
            ("Not authorized".into(), None)
        );
        assert_eq!(
            message(BindError::Helper(HelperError::PortInUse)),
            ("Port 443 is already in use".into(), None)
        );
        let (short, detail) = message(BindError::Rejected("wrong port".into()));
        assert_eq!(short, "Couldn't open port 443");
        assert!(detail.unwrap().contains("wrong port"));
    }

    #[test]
    fn nothing_asks_for_the_privilege_unless_the_user_clicked() {
        assert_eq!(launch_plan(false, true, false), Launch::Disabled);
        assert_eq!(launch_plan(true, true, false), Launch::NeedsOpen);
        assert_eq!(launch_plan(true, true, true), Launch::Run { inherit: true });
        assert_eq!(
            launch_plan(true, false, false),
            Launch::Run { inherit: false }
        );
        // An ordinary port never inherits sockets, even if some are left over.
        assert_eq!(
            launch_plan(true, false, true),
            Launch::Run { inherit: false }
        );
    }

    #[test]
    fn the_ipv4_only_notice_shows_while_held() {
        let v = view(&Inputs {
            held: true,
            running: true,
            notice: Some("IPv6 isn't available; only 127.0.0.1 is open"),
            ..inputs(&Access::Ready)
        });
        assert!(v.warning.contains("IPv6"));
    }

    #[test]
    fn effective_port_follows_tls() {
        let mut settings = CollectorSettings::default();
        assert_eq!(effective_port(&settings), 4318);
        settings.tls = true;
        assert_eq!(effective_port(&settings), 443);
    }

    #[test]
    fn a_reservation_ends_when_off_or_the_port_changes() {
        let mut hold = Hold::default();
        hold.keep(443, "sockets");
        assert!(hold.holds(443));
        assert_eq!(hold.get(443), Some(&"sockets"));
        assert_eq!(hold.get(444), None);
        // Same port: a restart reuses it.
        assert_eq!(hold.keep_only(Some(443)), None);
        assert!(hold.holds(443));
        // Another port, or no collector: gone.
        assert_eq!(hold.keep_only(Some(80)), Some(443));
        assert_eq!(hold.port(), None);
        hold.keep(443, "sockets");
        assert_eq!(hold.keep_only(None), Some(443));
        assert_eq!(hold.release(Release::Quit), None);
    }

    #[test]
    fn dropping_the_hold_drops_the_sockets() {
        use std::sync::Arc;
        let sockets = Arc::new(());
        let mut hold = Hold::default();
        hold.keep(443, Arc::clone(&sockets));
        assert_eq!(Arc::strong_count(&sockets), 2);
        hold.release(Release::StartupFailed);
        assert_eq!(Arc::strong_count(&sockets), 1);
        hold.keep(80, Arc::clone(&sockets));
        // A newer reservation replaces and closes the old one.
        hold.keep(81, Arc::clone(&sockets));
        assert_eq!(Arc::strong_count(&sockets), 2);
        drop(hold);
        assert_eq!(Arc::strong_count(&sockets), 1);
    }
}
