//! The tray's D-Bus side (plan §5, I5, I6): the StatusNotifierItem, notifications, the
//! single-instance interface, resume from sleep, the file manager. No Qt
//! here; it all runs on one thread and talks to the controller only through channels.

pub mod events;
pub mod filemanager;
pub mod instance;
pub mod logind;
pub mod notifications;
pub mod tray;
pub mod watcher;

use std::future::Future;
use std::thread::JoinHandle;
use std::time::Duration;

use async_channel::{Receiver, Sender};
use futures_lite::future;
use ksni::TrayMethods;

pub use events::{Command, Notification, Pixmap, TrayUpdate, UiEvent};

/// The bus name, SNI id, desktop-entry hint and icon base name.
pub const APP_ID: &str = "ua.SkeLLLa.cAInary";

/// How the service starts.
pub struct Options {
    pub icon_theme_path: String,
    /// What the item shows until the first update.
    pub tray: TrayUpdate,
    /// Register the StatusNotifierItem (off for `--self-test`).
    pub with_tray: bool,
}

/// A running D-Bus thread.
pub struct Service {
    commands: Sender<Command>,
    thread: Option<JoinHandle<()>>,
    /// Signalled when the thread's work is over, so `shutdown` can stop waiting for a hang.
    finished: std::sync::mpsc::Receiver<()>,
}

impl Service {
    /// Starts the thread on `conn`, the session connection that won the instance [`claim`].
    ///
    /// [`claim`]: instance::claim
    pub fn start(
        conn: zbus::Connection,
        options: Options,
        events: Sender<UiEvent>,
    ) -> std::io::Result<Self> {
        let (commands, rx) = async_channel::unbounded();
        let (done, finished) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("cainary-dbus".into())
            .spawn(move || {
                future::block_on(run(conn, options, events, rx));
                let _ = done.send(());
            })?;
        Ok(Self {
            commands,
            thread: Some(thread),
            finished,
        })
    }

    /// A handle for sending commands from any thread.
    pub fn commands(&self) -> Sender<Command> {
        self.commands.clone()
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.try_send(command);
    }

    /// Unregisters the item and stops the thread. A thread that doesn't finish within
    /// [`SHUTDOWN_WAIT`] is left behind so quitting can't hang on a stuck daemon.
    pub fn shutdown(&mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
        if let Some(t) = self.thread.take() {
            if self.finished.recv_timeout(SHUTDOWN_WAIT).is_err() {
                eprintln!("cainary-tray: the D-Bus thread didn't stop in time");
                return;
            }
            let _ = t.join();
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// How long one outbound D-Bus call may take before the serial loop moves on, so a hung daemon
/// cannot stall tray updates, Reveal or placement.
const CALL_TIMEOUT: Duration = Duration::from_secs(8);

/// How long [`Service::shutdown`] waits for the thread; shorter than a call timeout, because
/// the user is quitting.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// `fut`'s output, or `None` once `limit` has passed.
async fn with_timeout<T>(limit: Duration, fut: impl Future<Output = T>) -> Option<T> {
    future::or(async { Some(fut.await) }, async {
        async_io::Timer::after(limit).await;
        None
    })
    .await
}

async fn run(
    conn: zbus::Connection,
    options: Options,
    events: Sender<UiEvent>,
    commands: Receiver<Command>,
) {
    let tray = if options.with_tray {
        let item = tray::CainaryTray {
            state: options.tray,
            icon_theme_path: options.icon_theme_path,
            events: events.clone(),
        };
        // Without a watcher yet (GNOME before the extension, a session still starting) the item
        // waits and registers when one appears, instead of failing.
        match item.assume_sni_available(true).spawn().await {
            Ok(handle) => Some(handle),
            Err(e) => {
                eprintln!("cainary-tray: no tray icon: {e}");
                None
            }
        }
    } else {
        None
    };
    let notifier = notifications::Notifier::new(&conn).await.ok();

    let serve = async {
        while let Ok(command) = commands.recv().await {
            match command {
                Command::Tray(update) => {
                    if let Some(handle) = &tray {
                        let _ =
                            with_timeout(CALL_TIMEOUT, handle.update(|t| t.state = update)).await;
                    }
                }
                Command::Notify(n, reply) => {
                    let ok = match &notifier {
                        Some(notifier) => with_timeout(CALL_TIMEOUT, notifier.post(&n))
                            .await
                            .is_some_and(|posted| posted.is_ok()),
                        None => false,
                    };
                    if let Some(reply) = reply {
                        let _ = reply.send(ok).await;
                    }
                }
                Command::Reveal(path) => {
                    let shown =
                        with_timeout(CALL_TIMEOUT, filemanager::show_item(&conn, &path)).await;
                    if !shown.is_some_and(|result| result.is_ok()) {
                        let _ = events.send(UiEvent::RevealFailed { path }).await;
                    }
                }
                Command::Shutdown => break,
            }
        }
    };
    // The listeners end only with their connections; errors just mean that feature is absent.
    let listen = async {
        let clicks = async {
            if let Some(n) = &notifier {
                let _ = n.listen(events.clone()).await;
            }
            future::pending::<()>().await
        };
        let resume = async {
            let _ = logind::watch(events.clone()).await;
            future::pending::<()>().await
        };
        let host = async {
            let _ = watcher::watch(&conn, events.clone()).await;
            future::pending::<()>().await
        };
        future::zip(clicks, future::zip(resume, host)).await;
    };
    future::or(serve, listen).await;
    if let Some(handle) = tray
        && with_timeout(SHUTDOWN_WAIT, handle.shutdown())
            .await
            .is_none()
    {
        eprintln!("cainary-tray: unregistering the tray item timed out");
    }
}
