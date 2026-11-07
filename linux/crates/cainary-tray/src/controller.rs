use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};

use async_channel::Sender;
use cainary_tray_dbus::UiEvent;
use cainary_tray_model::collector::TrustAction;
use cainary_tray_model::privport::PrivState;
use cainary_tray_model::runner::{BindError, Reserved, StreamMsg};
use cainary_tray_model::store::StoreEvent;

static APP_MESSAGES: OnceLock<Sender<AppMessage>> = OnceLock::new();
const COLLECTOR_QUEUE_BYTES: usize = 16 << 20;

#[derive(Default)]
struct CollectorQueueState {
    messages: VecDeque<StreamMsg>,
    bytes: usize,
    wake_pending: bool,
    closed: bool,
}

/// Bounded handoff from the pipe reader to the controller thread. A single wake message covers
/// queued lines, so the app-wide event channel cannot accumulate collector output without bound.
#[derive(Default)]
pub struct CollectorMailbox {
    state: Mutex<CollectorQueueState>,
    space: Condvar,
}

impl CollectorMailbox {
    /// Adds a message and returns whether the producer should queue a controller wake-up. `None`
    /// means the mailbox was closed while the producer was waiting for space.
    pub fn enqueue(&self, message: StreamMsg) -> Option<bool> {
        let bytes = stream_message_bytes(&message);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while !state.closed && state.bytes.saturating_add(bytes) > COLLECTOR_QUEUE_BYTES {
            state = self
                .space
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        if state.closed {
            return None;
        }
        state.bytes += bytes;
        state.messages.push_back(message);
        let wake = !state.wake_pending;
        state.wake_pending = true;
        Some(wake)
    }

    /// Removes one message and releases its byte budget. Clears the wake flag atomically with an
    /// empty-queue check, so a concurrent producer either joins this drain or sends a new wake.
    pub fn pop(&self) -> Option<StreamMsg> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(message) = state.messages.pop_front() else {
            state.wake_pending = false;
            return None;
        };
        state.bytes = state.bytes.saturating_sub(stream_message_bytes(&message));
        self.space.notify_one();
        Some(message)
    }

    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.messages.clear();
        state.bytes = 0;
        state.wake_pending = false;
        self.space.notify_all();
    }
}

fn stream_message_bytes(message: &StreamMsg) -> usize {
    match message {
        StreamMsg::Line(line) | StreamMsg::Fault(line) => line.len(),
        StreamMsg::Exited { stderr_tail, .. } => stderr_tail.len(),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SidebarSection {
    Scan,
    Live,
}

#[derive(Debug)]
pub enum AppCommand {
    Refresh,
    MarkAsSeen,
    CopyReport,
    Reveal(String),
    CopyFindingJson {
        entry_id: String,
        finding_id: String,
    },
    SetNotInstalledExpanded(bool),
    SetSidebarCollapsed {
        section: SidebarSection,
        collapsed: bool,
    },
    SetRefresh(String),
    SetNotifications(bool),
    SetLaunchAtLogin(bool),
    SetStartMinimized(bool),
    SetCloseToTray(bool),
    SetIconStyle(String),
    SetCollector(String),
    ChooseCollectorLogFile,
    RetryCollector,
    CheckHosts,
    /// "Add to /etc/hosts…": the one place that asks the hosts helper to `set`.
    EditHosts,
    /// "Remove from /etc/hosts…": likewise for `clear`.
    RemoveHostsLines,
    OpenPrivilegedPort,
    ClearCollector,
    CollectorTrust(TrustAction),
    CancelClaudeTrustPreview,
    CopyText(String),
    Quit,
}

pub enum AppMessage {
    Command(AppCommand),
    Ui(UiEvent),
    Store(StoreEvent),
    CollectorStreamReady {
        generation: u64,
        mailbox: std::sync::Arc<CollectorMailbox>,
    },
    CollectorLogPathChosen(Option<String>),
    CollectorTrustFinished {
        action: TrustAction,
        result: Result<cainary_tray_model::runner::Output, String>,
    },
    /// The helper probe for a port below 1024 finished (on a worker thread).
    PrivilegeAssessed {
        port: u16,
        seq: u64,
        state: PrivState,
    },
    /// The authentication for opening a port finished. The sockets close with the message if
    /// nothing wants them any more.
    PortOpened {
        port: u16,
        result: Result<Reserved, BindError>,
    },
    /// The takeover host lookups finished (on a worker thread).
    HostsChecked {
        seq: u64,
        results: Vec<cainary_tray_model::hostcheck::HostResult>,
    },
    /// `/etc/hosts` was read (on a worker thread) for these names.
    HostsFileRead {
        seq: u64,
        file: cainary_tray_model::hostsfile::HostsFile,
    },
    /// The hosts helper was looked at (on a worker thread).
    HostsHelperAssessed {
        seq: u64,
        state: cainary_tray_model::hostsedit::HostsHelperState,
    },
    /// The authentication and the hosts helper finished (on a worker thread). `op` is
    /// `HostsOp::word()`.
    HostsEdited {
        op: &'static str,
        /// The names the edit was asked for (an add of other names than the current ones is
        /// dropped).
        hosts: Vec<String>,
        outcome: cainary_tray_model::runner::HostsEditOutcome,
    },
    /// A stopped collector has held its port for `STOPPED_HOLD`.
    HoldExpired {
        token: u64,
    },
    StopCollector(std::sync::mpsc::Sender<()>),
    Clipboard(String),
    Timer,
    Stop,
}

pub fn install(sender: Sender<AppMessage>) {
    let _ = APP_MESSAGES.set(sender);
}

pub fn send(message: AppMessage) {
    if let Some(sender) = APP_MESSAGES.get() {
        let _ = sender.try_send(message);
    }
}

#[cfg(test)]
mod tests {
    use super::CollectorMailbox;
    use cainary_tray_model::runner::StreamMsg;

    #[test]
    fn collector_mailbox_coalesces_wakes_and_closes() {
        let mailbox = CollectorMailbox::default();
        assert_eq!(mailbox.enqueue(StreamMsg::Line("one".into())), Some(true));
        assert_eq!(mailbox.enqueue(StreamMsg::Line("two".into())), Some(false));
        assert_eq!(mailbox.pop(), Some(StreamMsg::Line("one".into())));
        assert_eq!(mailbox.pop(), Some(StreamMsg::Line("two".into())));
        assert_eq!(mailbox.pop(), None);
        assert_eq!(mailbox.enqueue(StreamMsg::Line("three".into())), Some(true));
        mailbox.close();
        assert_eq!(mailbox.pop(), None);
        assert_eq!(mailbox.enqueue(StreamMsg::Line("four".into())), None);
    }
}
