import Foundation

// ChangeTracker with explicit times, no helper (macos.md §5b).

@MainActor
func trackerTests() {
    let t0 = Date(timeIntervalSince1970: 1_000_000)
    func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    // Nothing is due before confirmAfter, even if a scan runs; it is due after.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        check(
            "tracker: new id waits",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(0)).isEmpty)
        check("tracker: confirm time", tracker.nextConfirm == at(30))
        check(
            "tracker: early scan can't confirm",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(29)).isEmpty)
        check("tracker: confirm time kept", tracker.nextConfirm == at(30))
        check(
            "tracker: due after the delay",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(31)) == ["a"])
        check("tracker: due ids leave candidates", tracker.nextConfirm == nil)
        check("tracker: due ids are posting", tracker.posting.keys.contains("a"))
    }

    // A flap: seen, then gone at the confirm scan, posts nothing and is forgotten.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(0))
        let due = tracker.observe(notifying: [], notified: &notified, started: at(31))
        check("tracker: flap posts nothing", due.isEmpty)
        check("tracker: flap forgotten", tracker.nextConfirm == nil)
        // It returns later: a fresh wait, not an old confirm time.
        check(
            "tracker: returning id waits again",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(40)).isEmpty)
        check("tracker: new confirm time", tracker.nextConfirm == at(70))
    }

    // Notify A; a scan sees only B; then A+B: A is due again after a new confirm.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(0))
        let first = tracker.observe(notifying: ["a"], notified: &notified, started: at(31))
        tracker.finishPost(
            due: first, handled: ["a"], epoch: tracker.epoch, notified: &notified)
        check("tracker: A notified", notified == ["a"])
        check(
            "tracker: A not due again",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(60)).isEmpty)

        _ = tracker.observe(notifying: ["b"], notified: &notified, started: at(100))
        check("tracker: notified trimmed to present ids", notified.isEmpty)
        check(
            "tracker: A returns, B waits",
            tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(110)).isEmpty)
        check("tracker: A has a new confirm time", tracker.nextConfirm == at(130))
        let due = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(131))
        check("tracker: B due first", due == ["b"])
        let later = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(141))
        check("tracker: A due after its own new confirm", later == ["a"])
    }

    // An id being posted isn't a candidate again.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(0))
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(31))
        let again = tracker.observe(notifying: ["a"], notified: &notified, started: at(32))
        check("tracker: in-flight id excluded", again.isEmpty && tracker.nextConfirm == nil)
    }

    // Unhandled ids stay due: back in candidates with their old confirm time.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(0))
        let due = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(31))
        tracker.finishPost(
            due: due, handled: ["b"], epoch: tracker.epoch, notified: &notified)
        check("tracker: handled recorded", notified == ["b"])
        check("tracker: unhandled keeps its time", tracker.nextConfirm == at(30))
        let retry = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(40))
        check("tracker: unhandled due on the next scan", retry == ["a"])
    }

    // A post from before a baseline replacement records nothing and leaves no trace.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(0))
        let due = tracker.observe(notifying: ["a"], notified: &notified, started: at(31))
        let old = tracker.epoch
        tracker.reset()
        check("tracker: reset bumps the epoch", tracker.epoch == old + 1)
        tracker.finishPost(due: due, handled: ["a"], epoch: old, notified: &notified)
        check("tracker: stale post records nothing", notified.isEmpty)
        check(
            "tracker: stale post leaves nothing waiting",
            tracker.nextConfirm == nil && tracker.posting.isEmpty)
    }

    // A stale completion can't erase the reservation a newer epoch made for the same id.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(0))
        let stale = tracker.observe(notifying: ["a"], notified: &notified, started: at(31))
        let old = tracker.epoch
        tracker.reset()
        _ = tracker.observe(notifying: ["a"], notified: &notified, started: at(100))
        let fresh = tracker.observe(notifying: ["a"], notified: &notified, started: at(131))
        check("tracker: new epoch reserves the id", fresh == ["a"] && tracker.posting["a"] != nil)
        tracker.finishPost(due: stale, handled: ["a"], epoch: old, notified: &notified)
        check("tracker: stale completion keeps the new reservation", tracker.posting["a"] != nil)
        check(
            "tracker: the id isn't due twice",
            tracker.observe(notifying: ["a"], notified: &notified, started: at(140)).isEmpty)
    }

    // A post only records ids that are still present; the others are dropped, not retried.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(0))
        let due = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(31))
        _ = tracker.observe(notifying: ["b"], notified: &notified, started: at(35))
        tracker.finishPost(due: due, handled: ["a"], epoch: tracker.epoch, notified: &notified)
        check("tracker: removed id not recorded", notified.isEmpty)
        check("tracker: present unhandled id retried", tracker.nextConfirm == at(30))
        check(
            "tracker: nothing left posting",
            tracker.posting.isEmpty)
    }

    // reset forgets candidates and posts in flight.
    do {
        var tracker = ChangeTracker(confirmDelay: 30)
        var notified: Set<String> = []
        _ = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(0))
        _ = tracker.observe(notifying: ["a", "b"], notified: &notified, started: at(31))
        tracker.reset()
        check(
            "tracker: reset",
            tracker.nextConfirm == nil && tracker.posting.isEmpty && tracker.latest.isEmpty)
    }
}
