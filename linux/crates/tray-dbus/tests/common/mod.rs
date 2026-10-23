//! Helpers for the D-Bus tests. They need a private session bus
//! (`dbus-run-session -- cargo test`); on a desktop session, where the real tray, notification
//! server or watcher own the names, they skip instead of fighting them.

#![allow(dead_code)]

use std::time::Duration;

use cainary_tray_dbus::UiEvent;

pub const WAIT: Duration = Duration::from_secs(10);

pub fn block_on<T>(f: impl Future<Output = T>) -> T {
    futures_lite::future::block_on(f)
}

/// A fresh session connection, or `None` (and a note) without a session bus.
pub async fn session() -> Option<zbus::Connection> {
    match zbus::Connection::session().await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("skipped: no session bus ({e})");
            None
        }
    }
}

/// Takes `name` on `conn`; false (and a note) when someone else has it.
pub async fn own(conn: &zbus::Connection, name: &'static str) -> bool {
    let flags = zbus::fdo::RequestNameFlags::DoNotQueue.into();
    match conn.request_name_with_flags(name, flags).await {
        Ok(zbus::fdo::RequestNameReply::PrimaryOwner) => true,
        other => {
            eprintln!("skipped: {name} is taken ({other:?}); run under dbus-run-session");
            false
        }
    }
}

/// The next event, failing the test after [`WAIT`].
pub async fn next(rx: &async_channel::Receiver<UiEvent>) -> UiEvent {
    let timeout = async {
        async_io_sleep(WAIT).await;
        panic!("no event within {WAIT:?}");
    };
    futures_lite::future::or(async { rx.recv().await.expect("events open") }, timeout).await
}

/// The next event that matches `want`, skipping others.
pub async fn next_matching(
    rx: &async_channel::Receiver<UiEvent>,
    want: impl Fn(&UiEvent) -> bool,
) -> UiEvent {
    loop {
        let e = next(rx).await;
        if want(&e) {
            return e;
        }
    }
}

/// A sleep that doesn't need a reactor: a thread wakes the future.
pub async fn async_io_sleep(d: Duration) {
    let (tx, rx) = async_channel::bounded::<()>(1);
    std::thread::spawn(move || {
        std::thread::sleep(d);
        let _ = tx.send_blocking(());
    });
    let _ = rx.recv().await;
}
