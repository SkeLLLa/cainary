//! ChangeTracker with explicit times, no CLI (ported from macos/Tests/Unit/TrackerTests.swift).

use std::collections::HashSet;
use std::time::{Duration, Instant};

use cainary_tray_model::change::ChangeTracker;

struct Clock(Instant);

impl Clock {
    fn at(&self, secs: u64) -> Instant {
        self.0 + Duration::from_secs(secs)
    }
}

fn setup() -> (ChangeTracker, HashSet<String>, Clock) {
    (
        ChangeTracker::new(Duration::from_secs(30)),
        HashSet::new(),
        Clock(Instant::now()),
    )
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn set(list: &[&str]) -> HashSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn nothing_is_due_before_the_confirm_time() {
    let (mut t, mut notified, c) = setup();
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(0)).is_empty());
    assert_eq!(t.next_confirm(), Some(c.at(30)));
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(29)).is_empty());
    assert_eq!(t.next_confirm(), Some(c.at(30)), "the confirm time is kept");
    assert_eq!(
        t.observe(&ids(&["a"]), &mut notified, c.at(31)),
        ids(&["a"])
    );
    assert_eq!(t.next_confirm(), None, "due ids leave the candidates");
    assert!(t.is_posting("a"));
}

#[test]
fn a_flap_posts_nothing_and_is_forgotten() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a"]), &mut notified, c.at(0));
    assert!(t.observe(&[], &mut notified, c.at(31)).is_empty());
    assert_eq!(t.next_confirm(), None);
    // It returns later: a fresh wait, not the old confirm time.
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(40)).is_empty());
    assert_eq!(t.next_confirm(), Some(c.at(70)));
}

#[test]
fn a_returning_id_waits_for_its_own_confirm() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a"]), &mut notified, c.at(0));
    let first = t.observe(&ids(&["a"]), &mut notified, c.at(31));
    let epoch = t.epoch();
    t.finish_post(&first, &set(&["a"]), epoch, &mut notified);
    assert_eq!(notified, set(&["a"]));
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(60)).is_empty());

    t.observe(&ids(&["b"]), &mut notified, c.at(100));
    assert!(notified.is_empty(), "notified is trimmed to present ids");
    assert!(
        t.observe(&ids(&["a", "b"]), &mut notified, c.at(110))
            .is_empty()
    );
    assert_eq!(t.next_confirm(), Some(c.at(130)));
    assert_eq!(
        t.observe(&ids(&["a", "b"]), &mut notified, c.at(131)),
        ids(&["b"])
    );
    assert_eq!(
        t.observe(&ids(&["a", "b"]), &mut notified, c.at(141)),
        ids(&["a"])
    );
}

#[test]
fn an_id_being_posted_is_not_a_candidate() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a"]), &mut notified, c.at(0));
    t.observe(&ids(&["a"]), &mut notified, c.at(31));
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(32)).is_empty());
    assert_eq!(t.next_confirm(), None);
}

#[test]
fn unhandled_ids_stay_due_with_their_old_time() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a", "b"]), &mut notified, c.at(0));
    let due = t.observe(&ids(&["a", "b"]), &mut notified, c.at(31));
    let epoch = t.epoch();
    t.finish_post(&due, &set(&["b"]), epoch, &mut notified);
    assert_eq!(notified, set(&["b"]));
    assert_eq!(t.next_confirm(), Some(c.at(30)));
    assert_eq!(
        t.observe(&ids(&["a", "b"]), &mut notified, c.at(40)),
        ids(&["a"])
    );
}

#[test]
fn a_post_from_an_older_epoch_records_nothing() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a"]), &mut notified, c.at(0));
    let due = t.observe(&ids(&["a"]), &mut notified, c.at(31));
    let old = t.epoch();
    t.reset();
    assert_eq!(t.epoch(), old + 1);
    t.finish_post(&due, &set(&["a"]), old, &mut notified);
    assert!(notified.is_empty());
    assert!(t.next_confirm().is_none() && t.posting_is_empty());
}

#[test]
fn a_stale_completion_keeps_the_newer_reservation() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a"]), &mut notified, c.at(0));
    let stale = t.observe(&ids(&["a"]), &mut notified, c.at(31));
    let old = t.epoch();
    t.reset();
    t.observe(&ids(&["a"]), &mut notified, c.at(100));
    let fresh = t.observe(&ids(&["a"]), &mut notified, c.at(131));
    assert!(fresh == ids(&["a"]) && t.is_posting("a"));
    t.finish_post(&stale, &set(&["a"]), old, &mut notified);
    assert!(t.is_posting("a"));
    assert!(t.observe(&ids(&["a"]), &mut notified, c.at(140)).is_empty());
}

#[test]
fn a_post_records_only_ids_still_present() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a", "b"]), &mut notified, c.at(0));
    let due = t.observe(&ids(&["a", "b"]), &mut notified, c.at(31));
    t.observe(&ids(&["b"]), &mut notified, c.at(35));
    let epoch = t.epoch();
    t.finish_post(&due, &set(&["a"]), epoch, &mut notified);
    assert!(notified.is_empty(), "a removed id is not recorded");
    assert_eq!(
        t.next_confirm(),
        Some(c.at(30)),
        "a present unhandled id is retried"
    );
    assert!(t.posting_is_empty());
}

#[test]
fn reset_forgets_everything() {
    let (mut t, mut notified, c) = setup();
    t.observe(&ids(&["a", "b"]), &mut notified, c.at(0));
    t.observe(&ids(&["a", "b"]), &mut notified, c.at(31));
    t.reset();
    assert!(t.next_confirm().is_none() && t.posting_is_empty() && t.latest().is_empty());
}
