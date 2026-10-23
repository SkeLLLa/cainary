//! The scan state the views read, and what makes scans happen (macos.md §2.7). Scans never
//! overlap: requests made during one collapse into a single follow-up, and a result that was
//! invalidated while in flight is dropped for a fresh scan.
//!
//! Scans and notification posts run on their own threads; everything the views need goes out
//! through the event sink, which must not block.

use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::baseline::BaselineStore;
use crate::change::ChangeTracker;
use crate::notify_plan::{Planned, plan};
use crate::report::Report;
use crate::runner::{Client, Scan, ScanError};

/// Why a scan was asked for. All of them behave the same; the reason is for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Startup,
    Timer,
    Manual,
    Resume,
    /// A second instance asked (`Refresh()` on D-Bus).
    Remote,
    Settings,
    /// A change is waiting to be confirmed.
    Confirm,
}

/// A good scan.
#[derive(Debug)]
pub struct Snapshot {
    pub report: Report,
    /// Exact schema-3 bytes used as the next baseline and for "Mark as seen".
    pub raw: Vec<u8>,
    pub at: SystemTime,
}

#[derive(Clone, Debug)]
pub enum ScanState {
    Scanning {
        last: Option<Arc<Snapshot>>,
    },
    Ready(Arc<Snapshot>),
    /// The last good snapshot, if any, is kept and shown as stale.
    Failed {
        error: ScanError,
        last: Option<Arc<Snapshot>>,
    },
}

impl ScanState {
    pub fn last_good(&self) -> Option<&Arc<Snapshot>> {
        match self {
            Self::Ready(s) => Some(s),
            Self::Scanning { last } | Self::Failed { last, .. } => last.as_ref(),
        }
    }

    pub fn is_scanning(&self) -> bool {
        matches!(self, Self::Scanning { .. })
    }
}

#[derive(Clone, Debug)]
pub enum StoreEvent {
    Started,
    Updated(Arc<Snapshot>),
    Failed {
        error: ScanError,
        last: Option<Arc<Snapshot>>,
    },
}

/// Runs one scan. [`Client`] is the real one.
pub trait Scanner: Send + Sync + 'static {
    fn scan(&self, baseline: Option<&[u8]>) -> Result<Scan, ScanError>;
    /// The human-readable report for "Copy report", compared against `baseline`.
    fn report_text(&self, baseline: Option<&[u8]>) -> Result<String, ScanError>;
    /// Ends the run in progress, if any (shutdown). It must return at once.
    fn cancel(&self) {}
}

impl Scanner for Client {
    fn scan(&self, baseline: Option<&[u8]>) -> Result<Scan, ScanError> {
        Client::scan(self, baseline)
    }

    fn report_text(&self, baseline: Option<&[u8]>) -> Result<String, ScanError> {
        Client::report_text(self, baseline)
    }

    fn cancel(&self) {
        Client::cancel(self);
    }
}

/// Posts planned notifications, returning the change ids it handled (posted, or deliberately
/// dropped because notifications are off). Unhandled ids stay due for the next scan.
/// `is_current` turns false once the baseline was replaced; stop posting then.
pub trait Notifier: Send + Sync + 'static {
    fn post(&self, planned: &[Planned], is_current: &dyn Fn() -> bool) -> HashSet<String>;
}

type CopyDone = Box<dyn FnOnce(Option<String>) + Send>;

pub type Sink = Box<dyn Fn(StoreEvent) + Send + Sync>;

#[derive(Clone)]
pub struct Store {
    shared: Arc<Shared>,
}

struct Shared {
    inner: Mutex<Inner>,
    /// Notified whenever `in_flight` becomes false.
    idle: Condvar,
    scanner: Box<dyn Scanner>,
    notifier: Box<dyn Notifier>,
    sink: Sink,
}

struct Inner {
    state: ScanState,
    /// A scan is running.
    in_flight: bool,
    /// A request arrived during a scan; one follow-up will run.
    pending: bool,
    /// "Copy report" requests waiting for the gate; one run answers them all.
    copy_waiters: Vec<CopyDone>,
    /// Bumped whenever results in flight must be dropped.
    generation: u64,
    tracker: ChangeTracker,
    baselines: BaselineStore,
    /// The baseline couldn't be replaced, so changes can't be tracked.
    tracking_unavailable: bool,
    /// Bumped to cancel the pending confirm timer.
    confirm_seq: u64,
    stopped: bool,
    /// Scans started so far, for tests.
    scans: u64,
}

impl Store {
    pub fn new(
        scanner: impl Scanner,
        notifier: impl Notifier,
        baselines: BaselineStore,
        tracker: ChangeTracker,
        sink: Sink,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    state: ScanState::Scanning { last: None },
                    in_flight: false,
                    pending: false,
                    copy_waiters: Vec::new(),
                    generation: 0,
                    tracker,
                    baselines,
                    tracking_unavailable: false,
                    confirm_seq: 0,
                    stopped: false,
                    scans: 0,
                }),
                idle: Condvar::new(),
                scanner: Box::new(scanner),
                notifier: Box::new(notifier),
                sink,
            }),
        }
    }

    pub fn state(&self) -> ScanState {
        self.shared.lock().state.clone()
    }

    pub fn tracking_unavailable(&self) -> bool {
        self.shared.lock().tracking_unavailable
    }

    /// Uses the latest raw report as the new baseline and hides its current changes.
    /// Returns false when no scan result is available yet.
    pub fn mark_as_seen(&self) -> bool {
        let mut inner = self.shared.lock();
        let Some(last) = inner.state.last_good().cloned() else {
            return false;
        };

        inner.tracking_unavailable = !inner.baselines.replace(&last.raw);
        inner.tracker.reset();
        inner.generation = inner.generation.wrapping_add(1);
        inner.confirm_seq = inner.confirm_seq.wrapping_add(1);

        let mut report = last.report.clone();
        report.changes = Some(Vec::new());
        let snapshot = Arc::new(Snapshot {
            report,
            raw: last.raw.clone(),
            at: last.at,
        });
        inner.state = match &inner.state {
            ScanState::Scanning { .. } => ScanState::Scanning {
                last: Some(Arc::clone(&snapshot)),
            },
            ScanState::Ready(_) => ScanState::Ready(Arc::clone(&snapshot)),
            ScanState::Failed { error, .. } => ScanState::Failed {
                error: error.clone(),
                last: Some(Arc::clone(&snapshot)),
            },
        };
        true
    }

    /// How many scans have started.
    pub fn scans(&self) -> u64 {
        self.shared.lock().scans
    }

    /// Asks for a scan: starts one, or folds into the follow-up if one is running.
    pub fn request(&self, _trigger: Trigger) {
        let mut inner = self.shared.lock();
        if inner.stopped {
            return;
        }
        if inner.in_flight {
            inner.pending = true;
        } else {
            Shared::begin(&self.shared, inner);
        }
    }

    /// Runs `cainary scan --no-color --since -` through the same one-at-a-time gate as scans
    /// and calls `done` with the text, or `None` when it couldn't be made. `done` runs on the
    /// copy thread (or, when stopped, right here), so it must not block. Requests made while a
    /// run is going share the next one.
    pub fn copy_report(&self, done: impl FnOnce(Option<String>) + Send + 'static) {
        let mut inner = self.shared.lock();
        if inner.stopped {
            drop(inner);
            done(None);
            return;
        }
        inner.copy_waiters.push(Box::new(done));
        Shared::run_next(&self.shared, inner);
    }

    /// Stops the confirm timer and refuses further requests. A scan in flight still finishes.
    pub fn stop(&self) {
        let mut inner = self.shared.lock();
        inner.stopped = true;
        inner.confirm_seq += 1;
    }

    /// [`stop`](Self::stop), plus: results in flight are dropped, waiting copies get `None`, the
    /// run in progress is cancelled, and this waits up to `grace` for it to end. True when the
    /// store is idle.
    pub fn shutdown(&self, grace: Duration) -> bool {
        let mut inner = self.shared.lock();
        inner.stopped = true;
        inner.confirm_seq += 1;
        inner.generation = inner.generation.wrapping_add(1);
        inner.pending = false;
        let waiters = std::mem::take(&mut inner.copy_waiters);
        drop(inner);
        for done in waiters {
            done(None);
        }
        self.shared.scanner.cancel();
        let deadline = Instant::now() + grace;
        let mut inner = self.shared.lock();
        while inner.in_flight {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            inner = self
                .shared
                .idle
                .wait_timeout(inner, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        !inner.in_flight
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panicking scan thread must not take the tray down with it.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn begin(this: &Arc<Self>, mut inner: MutexGuard<'_, Inner>) {
        inner.in_flight = true;
        inner.pending = false;
        inner.scans += 1;
        let generation = inner.generation;
        let started = Instant::now();
        let last = inner.state.last_good().cloned();
        inner.state = ScanState::Scanning { last };
        let baseline = inner.baselines.baseline().map(<[u8]>::to_vec);
        drop(inner);
        (this.sink)(StoreEvent::Started);
        let me = Arc::clone(this);
        // The thread owns `me`; if it cannot start, `finish` must still run or `in_flight`
        // would stay set forever.
        let worker = Arc::clone(&me);
        let spawned = std::thread::Builder::new()
            .name("cainary-scan".into())
            .spawn(move || {
                let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.scanner.scan(baseline.as_deref())
                }));
                let result = scanned
                    .unwrap_or_else(|_| Err(ScanError::Spawn("the scan thread panicked".into())));
                Self::finish(&worker, result, generation, started);
            });
        if let Err(error) = spawned {
            Self::finish(
                &me,
                Err(ScanError::Spawn(format!(
                    "couldn't start a thread: {error}"
                ))),
                generation,
                started,
            );
        }
    }

    /// Starts whatever is waiting, if nothing is running: a scan first, else the copies.
    fn run_next(this: &Arc<Self>, inner: MutexGuard<'_, Inner>) {
        if inner.in_flight || inner.stopped {
            return;
        }
        if inner.pending {
            Self::begin(this, inner);
        } else if !inner.copy_waiters.is_empty() {
            Self::begin_copy(this, inner);
        }
    }

    fn begin_copy(this: &Arc<Self>, mut inner: MutexGuard<'_, Inner>) {
        inner.in_flight = true;
        let waiters = std::mem::take(&mut inner.copy_waiters);
        let baseline = inner.baselines.baseline().map(<[u8]>::to_vec);
        drop(inner);
        // The waiters move into the thread; they are shared with the spawn-failure path.
        let jobs = Arc::new(Mutex::new(Some(waiters)));
        let worker = Arc::clone(this);
        let worker_jobs = Arc::clone(&jobs);
        let spawned = std::thread::Builder::new()
            .name("cainary-copy".into())
            .spawn(move || {
                let made = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.scanner.report_text(baseline.as_deref())
                }));
                let text = match made {
                    Ok(Ok(text)) => Some(text),
                    Ok(Err(e)) => {
                        eprintln!("cainary-tray: copy report failed: {}", e.reason());
                        None
                    }
                    Err(_) => {
                        eprintln!("cainary-tray: copy report failed: the copy thread panicked");
                        None
                    }
                };
                Self::finish_copy(&worker, take_jobs(&worker_jobs), text);
            });
        if let Err(e) = spawned {
            eprintln!("cainary-tray: copy report failed: couldn't start a thread: {e}");
            Self::finish_copy(this, take_jobs(&jobs), None);
        }
    }

    /// Answers the waiters, then frees the gate and moves on. Scan state is untouched.
    fn finish_copy(this: &Arc<Self>, waiters: Vec<CopyDone>, text: Option<String>) {
        for done in waiters {
            done(text.clone());
        }
        let mut inner = this.lock();
        inner.in_flight = false;
        this.idle.notify_all();
        Self::run_next(this, inner);
    }

    fn finish(
        this: &Arc<Self>,
        result: Result<Scan, ScanError>,
        generation: u64,
        started: Instant,
    ) {
        let mut inner = this.lock();
        inner.in_flight = false;
        this.idle.notify_all();
        let mut event = None;
        let mut post = None;
        if generation == inner.generation {
            match result {
                Ok(scan) => {
                    post = track(&mut inner, &scan, started);
                    let snapshot = Arc::new(Snapshot {
                        report: scan.report,
                        raw: scan.raw,
                        at: SystemTime::now(),
                    });
                    inner.state = ScanState::Ready(Arc::clone(&snapshot));
                    event = Some(StoreEvent::Updated(snapshot));
                }
                Err(error) => {
                    let last = inner.state.last_good().cloned();
                    inner.state = ScanState::Failed {
                        error: error.clone(),
                        last: last.clone(),
                    };
                    event = Some(StoreEvent::Failed { error, last });
                }
            }
            Self::schedule_confirm(this, &mut inner);
        } else {
            // Something invalidated this result; look again.
            inner.pending = true;
        }
        drop(inner);
        if let Some(event) = event {
            (this.sink)(event);
        }
        if let Some(job) = post {
            Self::post(this, job);
        }
        Self::run_next(this, this.lock());
    }

    /// Posts on its own thread: the notification server may be slow or absent.
    fn post(this: &Arc<Self>, job: PostJob) {
        let me = Arc::clone(this);
        let spawned = std::thread::Builder::new()
            .name("cainary-notify".into())
            .spawn(move || {
                let is_current = || me.lock().tracker.epoch() == job.epoch;
                let handled = me.notifier.post(&job.planned, &is_current);
                let mut inner = me.lock();
                let mut notified = inner.baselines.notified().clone();
                inner
                    .tracker
                    .finish_post(&job.due, &handled, job.epoch, &mut notified);
                inner.baselines.set_notified(notified);
                // Unhandled ids wait for the next scan; arming the timer for them would loop.
            });
        if let Err(e) = spawned {
            eprintln!("cainary-tray: couldn't start a notification thread: {e}");
        }
    }

    /// One timer, for the earliest id waiting to be confirmed; it asks for the confirm scan.
    fn schedule_confirm(this: &Arc<Self>, inner: &mut Inner) {
        inner.confirm_seq += 1;
        let Some(at) = inner.tracker.next_confirm() else {
            return;
        };
        let seq = inner.confirm_seq;
        let me = Arc::clone(this);
        let spawned = std::thread::Builder::new()
            .name("cainary-confirm".into())
            .spawn(move || {
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                let current = {
                    let inner = me.lock();
                    inner.confirm_seq == seq && !inner.stopped
                };
                if current {
                    Store { shared: me }.request(Trigger::Confirm);
                }
            });
        if let Err(e) = spawned {
            eprintln!("cainary-tray: couldn't start the confirm timer: {e}");
        }
    }
}

fn take_jobs(jobs: &Mutex<Option<Vec<CopyDone>>>) -> Vec<CopyDone> {
    jobs.lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default()
}

struct PostJob {
    planned: Vec<Planned>,
    due: Vec<String>,
    epoch: u64,
}

/// What the store does with a good scan (macos.md §2.7 steps 1–7). Returns the post to make.
fn track(inner: &mut Inner, scan: &Scan, started: Instant) -> Option<PostJob> {
    let report = &scan.report;
    if inner.baselines.baseline().is_none() {
        // 1. First scan: today's exposure is the baseline, silently.
        rebaseline(inner, &scan.raw);
        return None;
    }
    if report.since.as_ref().is_some_and(|s| s.error.is_some()) {
        // 2. A core upgrade or a corrupt baseline: start over, silently.
        rebaseline(inner, &scan.raw);
        return None;
    }
    let notifying = report.notifying_change_ids();
    let mut notified = inner.baselines.notified().clone();
    let due = inner.tracker.observe(&notifying, &mut notified, started);
    let ids: HashSet<String> = due.iter().cloned().collect();
    let planned = plan(report.changes.as_deref().unwrap_or_default(), report, &ids);
    let posted: Vec<String> = planned.iter().flat_map(|p| p.change_ids.clone()).collect();
    // Changes the planner skips (an entry missing from the report) count as handled.
    let skipped: Vec<String> = due
        .iter()
        .filter(|id| !posted.contains(id))
        .cloned()
        .collect();
    if !skipped.is_empty() {
        let handled: HashSet<String> = skipped.iter().cloned().collect();
        let epoch = inner.tracker.epoch();
        inner
            .tracker
            .finish_post(&skipped, &handled, epoch, &mut notified);
    }
    inner.baselines.set_notified(notified);
    if planned.is_empty() {
        return None;
    }
    Some(PostJob {
        planned,
        due: posted,
        epoch: inner.tracker.epoch(),
    })
}

/// Replaces the baseline. Only a successful replacement invalidates tracking state and posts in
/// flight; a failed one keeps both, since the old baseline is still what scans compare to.
fn rebaseline(inner: &mut Inner, raw: &[u8]) {
    if !inner.baselines.replace(raw) {
        inner.tracking_unavailable = true;
        return;
    }
    inner.tracking_unavailable = false;
    inner.tracker.reset();
}
