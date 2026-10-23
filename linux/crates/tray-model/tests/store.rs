//! The store: coalescing against the counting stub, then change tracking with a scripted
//! scanner and a recording notifier (as StoreTests.swift).

mod common;

use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cainary_tray_model::baseline::BaselineStore;
use cainary_tray_model::change::ChangeTracker;
use cainary_tray_model::notify_plan::Planned;
use cainary_tray_model::report::Report;
use cainary_tray_model::runner::{Client, Scan, ScanError};
use cainary_tray_model::store::{Notifier, ScanState, Scanner, Store, StoreEvent, Trigger};
use common::{change, golden, stub, temp_dir, with_changes};

const WAIT: Duration = Duration::from_secs(10);

/// Records what it was asked to post; handles everything.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Planned>>>);

impl Notifier for Recorder {
    fn post(&self, planned: &[Planned], _is_current: &dyn Fn() -> bool) -> HashSet<String> {
        self.0.lock().unwrap().extend_from_slice(planned);
        planned.iter().flat_map(|p| p.change_ids.clone()).collect()
    }
}

impl Recorder {
    fn posted(&self) -> Vec<Planned> {
        self.0.lock().unwrap().clone()
    }
}

type Scripted = Result<Vec<u8>, ScanError>;

/// Hands out scripted results (the last one repeats) and records the baselines it was given.
#[derive(Clone, Default)]
struct Script {
    results: Arc<Mutex<VecDeque<Scripted>>>,
    baselines: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
}

impl Script {
    fn push(&self, r: Scripted) {
        self.results.lock().unwrap().push_back(r);
    }
}

impl Scanner for Script {
    fn scan(&self, baseline: Option<&[u8]>) -> Result<Scan, ScanError> {
        self.baselines
            .lock()
            .unwrap()
            .push(baseline.map(<[u8]>::to_vec));
        let mut q = self.results.lock().unwrap();
        let r = if q.len() > 1 {
            q.pop_front()
        } else {
            q.front().cloned()
        };
        let raw = r.expect("a scripted result")?;
        Ok(Scan {
            report: Report::decode(&raw).unwrap(),
            raw,
        })
    }

    fn report_text(&self, _baseline: Option<&[u8]>) -> Result<String, ScanError> {
        Ok("report".into())
    }
}

fn store(
    scanner: impl Scanner,
    notifier: impl Notifier,
    baselines: BaselineStore,
    delay: Duration,
) -> (Store, Receiver<StoreEvent>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink = Box::new(move |e| {
        let _ = tx.lock().unwrap().send(e);
    });
    let s = Store::new(
        scanner,
        notifier,
        baselines,
        ChangeTracker::new(delay),
        sink,
    );
    (s, rx)
}

/// Waits for the next result (skipping `Started`).
fn next_result(rx: &Receiver<StoreEvent>) -> StoreEvent {
    loop {
        match rx.recv_timeout(WAIT).expect("a store event") {
            StoreEvent::Started => continue,
            e => return e,
        }
    }
}

fn golden_bytes(name: &str) -> Vec<u8> {
    std::fs::read(golden(name)).unwrap()
}

#[test]
fn requests_during_a_scan_collapse_into_one_follow_up() {
    let dir = temp_dir("counting");
    let counter = dir.join("count");
    let mut client = Client::new(Some(stub("counting.sh")));
    client.extra_args = vec![
        OsString::from(&counter),
        OsString::from(golden("empty-linux.json")),
    ];
    let (s, rx) = store(
        client,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    for t in [
        Trigger::Startup,
        Trigger::Manual,
        Trigger::Timer,
        Trigger::Remote,
    ] {
        s.request(t);
    }
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    std::thread::sleep(Duration::from_millis(600));
    let runs = std::fs::read_to_string(&counter).unwrap().lines().count();
    assert_eq!(runs, 2);
    assert_eq!(s.scans(), 2);
    // The second scan had the first one's report as its baseline (`--since -`).
    assert!(matches!(s.state(), ScanState::Ready(_)));
}

#[test]
fn a_failure_keeps_the_last_good_report() {
    let script = Script::default();
    script.push(Ok(golden_bytes("claude-code-linux.json")));
    script.push(Err(ScanError::TimedOut));
    let (s, rx) = store(
        script,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    s.request(Trigger::Startup);
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    s.request(Trigger::Manual);
    let StoreEvent::Failed { error, last } = next_result(&rx) else {
        panic!("expected a failure")
    };
    assert_eq!(error, ScanError::TimedOut);
    assert_eq!(last.unwrap().report.apps[0].id, "claude");
    assert!(matches!(s.state(), ScanState::Failed { last: Some(_), .. }));
}

#[test]
fn a_change_notifies_once_after_it_is_confirmed() {
    let dir = temp_dir("tracking");
    let script = Script::default();
    let first = golden_bytes("claude-code-linux.json");
    let changed = with_changes(
        "claude-code-linux.json",
        vec![change("c1", "claude", "Bedrock routing was turned on")],
        None,
    );
    script.push(Ok(first.clone()));
    script.push(Ok(changed));
    let recorder = Recorder::default();
    let (s, rx) = store(
        script.clone(),
        recorder.clone(),
        BaselineStore::open(Some(dir.clone())),
        Duration::from_millis(300),
    );

    // 1. The first scan becomes the baseline, silently.
    s.request(Trigger::Startup);
    next_result(&rx);
    assert_eq!(std::fs::read(dir.join("baseline.json")).unwrap(), first);
    // A change is seen, waits for its confirm time, and the confirm scan posts it.
    s.request(Trigger::Manual);
    next_result(&rx);
    assert!(
        recorder.posted().is_empty(),
        "nothing before the confirm scan"
    );
    next_result(&rx);
    std::thread::sleep(Duration::from_millis(200));
    let posted = recorder.posted();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].entry, "claude");
    assert_eq!(posted[0].body, "Bedrock routing was turned on");
    // Later scans still see it, but it is notified already.
    s.request(Trigger::Manual);
    next_result(&rx);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(recorder.posted().len(), 1);
    let notified = std::fs::read_to_string(dir.join("notified.json")).unwrap();
    assert_eq!(notified, r#"["c1"]"#);
    // Every scan after the first compared against the baseline.
    let baselines = script.baselines.lock().unwrap();
    assert!(baselines[0].is_none());
    assert!(
        baselines[1..]
            .iter()
            .all(|b| b.as_deref() == Some(&first[..]))
    );
    // Restarting reads the baseline and the notified ids back.
    let reopened = BaselineStore::open(Some(dir));
    assert_eq!(reopened.baseline(), Some(&first[..]));
    assert!(reopened.notified().contains("c1"));
}

#[test]
fn mark_as_seen_rebaselines_the_last_report_and_clears_its_changes() {
    let dir = temp_dir("mark-seen");
    let first = golden_bytes("empty-linux.json");
    let changed = with_changes(
        "claude-code-linux.json",
        vec![change(
            "seen-change",
            "claude",
            "Bedrock routing was turned on",
        )],
        None,
    );
    let no_changes = with_changes("claude-code-linux.json", Vec::new(), None);
    let script = Script::default();
    script.push(Ok(first));
    script.push(Ok(changed.clone()));
    script.push(Ok(no_changes));
    let recorder = Recorder::default();
    let (s, rx) = store(
        script.clone(),
        recorder.clone(),
        BaselineStore::open(Some(dir.clone())),
        Duration::from_secs(30),
    );

    s.request(Trigger::Startup);
    next_result(&rx);
    s.request(Trigger::Manual);
    next_result(&rx);
    assert!(s.mark_as_seen());
    let ScanState::Ready(snapshot) = s.state() else {
        panic!("marking a ready scan should keep it ready")
    };
    assert_eq!(snapshot.raw, changed);
    assert_eq!(snapshot.report.changes, Some(Vec::new()));
    assert_eq!(std::fs::read(dir.join("baseline.json")).unwrap(), changed);

    s.request(Trigger::Manual);
    next_result(&rx);
    assert!(recorder.posted().is_empty());
    let baselines = script.baselines.lock().unwrap();
    assert_eq!(baselines[2].as_deref(), Some(changed.as_slice()));
}

#[test]
fn an_unusable_baseline_rebaselines_silently() {
    let script = Script::default();
    let broken = with_changes(
        "claude-code-linux.json",
        vec![change("c1", "claude", "should not notify")],
        Some("baseline schema 2"),
    );
    script.push(Ok(golden_bytes("empty-linux.json")));
    script.push(Ok(broken.clone()));
    let recorder = Recorder::default();
    let (s, rx) = store(
        script.clone(),
        recorder.clone(),
        BaselineStore::open(None),
        Duration::from_millis(100),
    );
    s.request(Trigger::Startup);
    next_result(&rx);
    s.request(Trigger::Manual);
    next_result(&rx);
    s.request(Trigger::Manual);
    next_result(&rx);
    std::thread::sleep(Duration::from_millis(400));
    assert!(recorder.posted().is_empty());
    let baselines = script.baselines.lock().unwrap();
    assert_eq!(baselines.last().unwrap().as_deref(), Some(&broken[..]));
}

#[test]
fn a_report_too_big_to_keep_turns_tracking_off() {
    let dir = temp_dir("bigreport");
    let path = dir.join("report.json");
    std::fs::write(&path, golden_bytes("empty-linux.json")).unwrap();
    let mut client = Client::new(Some(stub("bigreport.sh")));
    client.extra_args = vec![OsString::from(&path)];
    let (s, rx) = store(
        client,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    s.request(Trigger::Startup);
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    assert!(s.tracking_unavailable());
}

struct Panicker;

impl Scanner for Panicker {
    fn scan(&self, _baseline: Option<&[u8]>) -> Result<Scan, ScanError> {
        panic!("scanner bug");
    }

    fn report_text(&self, _baseline: Option<&[u8]>) -> Result<String, ScanError> {
        panic!("scanner bug");
    }
}

#[test]
fn a_panicking_scanner_fails_the_scan_and_does_not_wedge_the_store() {
    let (s, rx) = store(
        Panicker,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    for _ in 0..2 {
        s.request(Trigger::Manual);
        assert!(matches!(
            next_result(&rx),
            StoreEvent::Failed {
                error: ScanError::Spawn(_),
                ..
            }
        ));
    }
    assert_eq!(s.scans(), 2, "the second request started a fresh scan");
}

/// Blocks `scan` and `report_text` until released, counting the runs and recording order.
#[derive(Clone, Default)]
struct Gated {
    log: Arc<Mutex<Vec<&'static str>>>,
    baselines: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    open: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

impl Gated {
    fn release(&self) {
        *self.open.0.lock().unwrap() = true;
        self.open.1.notify_all();
    }

    fn wait(&self) {
        let mut open = self.open.0.lock().unwrap();
        while !*open {
            open = self.open.1.wait(open).unwrap();
        }
    }

    fn log(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().clone()
    }

    fn wait_for_log(&self, n: usize) {
        for _ in 0..500 {
            if self.log().len() >= n {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("log: {:?}", self.log());
    }
}

impl Scanner for Gated {
    fn scan(&self, _baseline: Option<&[u8]>) -> Result<Scan, ScanError> {
        self.log.lock().unwrap().push("scan");
        self.wait();
        let raw = golden_bytes("empty-linux.json");
        Ok(Scan {
            report: Report::decode(&raw).unwrap(),
            raw,
        })
    }

    fn report_text(&self, baseline: Option<&[u8]>) -> Result<String, ScanError> {
        self.log.lock().unwrap().push("copy");
        self.baselines
            .lock()
            .unwrap()
            .push(baseline.map(<[u8]>::to_vec));
        self.wait();
        Ok("the report".into())
    }
}

fn gated_store(g: &Gated) -> (Store, Receiver<StoreEvent>) {
    store(
        g.clone(),
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    )
}

fn collect_copy(s: &Store) -> Receiver<Option<String>> {
    let (tx, rx) = mpsc::channel();
    s.copy_report(move |text| {
        let _ = tx.send(text);
    });
    rx
}

#[test]
fn copy_waiters_share_one_run() {
    let g = Gated::default();
    let (s, _rx) = gated_store(&g);
    let first = collect_copy(&s);
    g.wait_for_log(1);
    let second = collect_copy(&s);
    let third = collect_copy(&s);
    g.release();
    for rx in [first, second, third] {
        assert_eq!(
            rx.recv_timeout(WAIT).unwrap().as_deref(),
            Some("the report")
        );
    }
    // The first copy was already running; the two that queued behind it share the next run.
    assert_eq!(g.log(), ["copy", "copy"]);
}

#[test]
fn a_copy_during_a_scan_runs_after_it() {
    let g = Gated::default();
    let (s, rx) = gated_store(&g);
    s.request(Trigger::Manual);
    g.wait_for_log(1);
    let copied = collect_copy(&s);
    assert!(copied.recv_timeout(Duration::from_millis(200)).is_err());
    g.release();
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    assert_eq!(
        copied.recv_timeout(WAIT).unwrap().as_deref(),
        Some("the report")
    );
    assert_eq!(g.log(), ["scan", "copy"]);
    // The copy used the baseline the scan left behind, and left the scan state alone.
    assert!(matches!(s.state(), ScanState::Ready(_)));
}

#[test]
fn a_pending_scan_wins_over_waiting_copies() {
    let g = Gated::default();
    let (s, rx) = gated_store(&g);
    s.request(Trigger::Manual);
    g.wait_for_log(1);
    let copied = collect_copy(&s);
    s.request(Trigger::Manual);
    g.release();
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    assert!(matches!(next_result(&rx), StoreEvent::Updated(_)));
    assert_eq!(
        copied.recv_timeout(WAIT).unwrap().as_deref(),
        Some("the report")
    );
    assert_eq!(g.log(), ["scan", "scan", "copy"]);
}

#[test]
fn a_failed_copy_reports_none_and_frees_the_gate() {
    let (s, _rx) = store(
        Panicker,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    assert_eq!(collect_copy(&s).recv_timeout(WAIT).unwrap(), None);
    assert_eq!(collect_copy(&s).recv_timeout(WAIT).unwrap(), None);
}

#[test]
fn copy_report_after_stop_gets_none() {
    let g = Gated::default();
    let (s, _rx) = gated_store(&g);
    s.stop();
    assert_eq!(collect_copy(&s).recv_timeout(WAIT).unwrap(), None);
    assert!(g.log().is_empty());
}

#[test]
fn shutdown_cancels_a_sleeping_scan_and_leaves_no_child() {
    let (script, pid_file) = common::sleeper(&temp_dir("shutdown"));
    let mut client = Client::new(Some(script));
    client.limits.deadline = Duration::from_secs(60);
    let (s, _rx) = store(
        client,
        Recorder::default(),
        BaselineStore::open(None),
        Duration::from_secs(30),
    );
    s.request(Trigger::Startup);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse::<i32>().ok())
        {
            break pid;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let waiting = collect_copy(&s);
    let started = std::time::Instant::now();
    assert!(s.shutdown(Duration::from_secs(3)));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(waiting.recv_timeout(WAIT).unwrap(), None);
    // SAFETY: signal 0 only checks for existence.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "the scan's child outlived the shutdown");
    // Nothing starts after a shutdown.
    s.request(Trigger::Manual);
    assert_eq!(collect_copy(&s).recv_timeout(WAIT).unwrap(), None);
}

#[test]
fn shutdown_gives_up_after_the_grace_when_the_scan_will_not_end() {
    let g = Gated::default();
    let (s, _rx) = gated_store(&g);
    s.request(Trigger::Manual);
    g.wait_for_log(1);
    assert!(!s.shutdown(Duration::from_millis(100)));
    g.release();
    assert!(s.shutdown(Duration::from_secs(3)));
}

#[test]
fn nothing_starts_after_stop_even_with_a_pending_scan() {
    let g = Gated::default();
    let (s, _rx) = gated_store(&g);
    let copied = collect_copy(&s);
    g.wait_for_log(1);
    s.request(Trigger::Manual);
    s.stop();
    g.release();
    assert_eq!(
        copied.recv_timeout(WAIT).unwrap().as_deref(),
        Some("the report")
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(g.log(), ["copy"]);
    assert_eq!(s.scans(), 0);
}
