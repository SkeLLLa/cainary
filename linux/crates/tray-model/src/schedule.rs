//! The background refresh timer: a thread waiting on its control channel with
//! `recv_timeout`, so changing the interval or stopping takes effect at once.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

enum Control {
    Interval(Duration),
    Stop,
}

pub struct Scheduler {
    tx: mpsc::Sender<Control>,
    thread: Option<JoinHandle<()>>,
}

impl Scheduler {
    /// Calls `tick` every `interval` until stopped. The first tick is one interval away; the
    /// startup scan is the caller's.
    pub fn start(interval: Duration, tick: impl Fn() + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("cainary-schedule".into())
            .spawn(move || {
                let mut interval = interval;
                loop {
                    match rx.recv_timeout(interval) {
                        Err(RecvTimeoutError::Timeout) => tick(),
                        // A new interval restarts the wait from now.
                        Ok(Control::Interval(d)) => interval = d,
                        Ok(Control::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .expect("spawn the scheduler thread");
        Self {
            tx,
            thread: Some(thread),
        }
    }

    pub fn set_interval(&self, interval: Duration) {
        let _ = self.tx.send(Control::Interval(interval));
    }

    pub fn stop(&mut self) {
        let _ = self.tx.send(Control::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.stop();
    }
}
