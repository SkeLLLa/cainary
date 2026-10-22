import Foundation

// What the app remembers between scans: the baseline report and the change ids it has already
// notified (macos.md §2.4), plus the pure bookkeeping that decides what is due (macos.md §2.7).

/// The baseline report's bytes and `notifiedChangeIds`, in the app's prefs domain.
final class BaselineStore {
    /// The core rejects a larger baseline every time, so there is no point saving one.
    static let maxBytes = 1 << 20

    private let defaults: KeyValueStore

    init(defaults: KeyValueStore) {
        self.defaults = defaults
    }

    /// The last report the user acknowledged, as the core printed it.
    var baseline: Data? { defaults.data(forKey: PrefKey.baseline) }

    /// Change ids already notified or muted.
    var notifiedChangeIds: Set<String> {
        get { Set(defaults.stringArray(forKey: PrefKey.notifiedChangeIds) ?? []) }
        set { defaults.set(newValue.sorted(), forKey: PrefKey.notifiedChangeIds) }
    }

    /// Makes `raw` the baseline and forgets the notified ids (seeding, rebaselining, Mark as
    /// seen). False, with the old baseline and ids untouched, when `raw` is too big to keep.
    func replace(_ raw: Data) -> Bool {
        guard raw.count <= Self.maxBytes else { return false }
        defaults.set(raw, forKey: PrefKey.baseline)
        defaults.removeObject(forKey: PrefKey.notifiedChangeIds)
        return true
    }
}

/// Decides which notifying changes are due, without a helper, a clock or a notifier (§2.7).
/// A new notifying id waits `confirmDelay` and is posted only if a scan that *started* after that
/// is still seeing it, so a file caught mid-rewrite can't fire and then vanish.
struct ChangeTracker: Equatable, Sendable {
    /// Seconds a new id waits before it may be posted.
    var confirmDelay: TimeInterval
    /// Id → the time after which a scan may confirm it.
    private(set) var candidates: [String: Date] = [:]
    /// Id → its `confirmAfter`, for a post still in flight.
    private(set) var posting: [String: Date] = [:]
    /// Bumped whenever the baseline is replaced; a post from an older epoch is dropped whole.
    private(set) var epoch = 0
    /// The notifying ids of the latest scan observed: the only ones a post may record.
    private(set) var latest: Set<String> = []

    init(confirmDelay: TimeInterval = 30) {
        self.confirmDelay = confirmDelay
    }

    /// Steps 3–5, for a scan that started at `started` and saw `notifying` (in core order).
    /// Trims `notified` to what is still present, then returns the ids due now: still present,
    /// not notified, not being posted, and past their confirm time. They move to `posting`.
    mutating func observe(
        notifying: [String], notified: inout Set<String>, started: Date
    ) -> [String] {
        let present = Set(notifying)
        latest = present
        notified.formIntersection(present)
        let fresh = present.subtracting(notified).subtracting(posting.keys)
        candidates = candidates.filter { fresh.contains($0.key) }
        for id in notifying where fresh.contains(id) && candidates[id] == nil {
            candidates[id] = started.addingTimeInterval(confirmDelay)
        }
        let due = notifying.filter { id in
            candidates[id].map { $0 <= started } ?? false
        }
        for id in due {
            posting[id] = candidates.removeValue(forKey: id)
        }
        return due
    }

    /// The bookkeeping after a post (step 6) that was started in `epoch`. A post from an older
    /// epoch changes nothing, so it can't erase a newer reservation. Otherwise it records the
    /// handled ids that the latest scan still sees; the unhandled ones stay due.
    mutating func finishPost(
        due: [String], handled: Set<String>, epoch: Int, notified: inout Set<String>
    ) {
        guard epoch == self.epoch else { return }
        let confirmAfter = posting
        for id in due { posting.removeValue(forKey: id) }
        notified.formUnion(Set(due).intersection(handled).intersection(latest))
        for id in due where !handled.contains(id) && latest.contains(id) {
            candidates[id] = confirmAfter[id]
        }
    }

    /// The earliest time a scan could confirm something, if anything is waiting.
    var nextConfirm: Date? { candidates.values.min() }

    /// Forgets everything in memory (the baseline was replaced) and starts a new epoch.
    mutating func reset() {
        candidates = [:]
        posting = [:]
        latest = []
        epoch += 1
    }
}
