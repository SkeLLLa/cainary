import AppKit
import Foundation

// The scan state the views read, and what makes scans happen (macos.md §2.7). Scans never
// overlap: requests made during one collapse into a single follow-up.

@MainActor
final class ReportStore: ObservableObject {
    @Published private(set) var state: ScanState = .scanning(last: nil)

    /// What the menu bar icon shows for `state`.
    var menuState: MenuState { MenuState(state: state) }

    /// A scan is running.
    private(set) var inFlight = false
    /// A request arrived during a scan; one follow-up will run.
    private(set) var pending = false
    /// Bumped whenever results in flight must be dropped.
    private(set) var generation = 0
    /// When the last scan (good or not) finished.
    private(set) var lastFinished: Date?

    private let client: CoreClient
    private let notifier: NotificationPosting
    private let baselines: BaselineStore
    private let defaults: KeyValueStore
    /// Opening the popover rescans only if the last scan is older than this.
    private let staleAfter: TimeInterval
    private var timer: Timer?
    private var wakeObserver: NSObjectProtocol?
    /// Candidates and posts in flight (§2.7); in memory only.
    private(set) var tracker: ChangeTracker
    private var confirmTask: Task<Void, Never>?
    /// The last good scan's bytes, which Mark as seen turns into the baseline.
    private var lastRaw: Data?
    /// Copy report requests waiting for the next run.
    private var copyWaiters: [@MainActor (String?) -> Void] = []
    /// The baseline couldn't be replaced, so changes can't be tracked (shown in the popover).
    @Published private(set) var trackingUnavailable = false

    init(
        client: CoreClient, defaults: KeyValueStore,
        notifier: NotificationPosting? = nil, confirmDelay: TimeInterval = 30,
        staleAfter: TimeInterval = 30
    ) {
        self.client = client
        self.defaults = defaults
        self.notifier = notifier ?? UNNotifier(defaults: defaults)
        self.baselines = BaselineStore(defaults: defaults)
        self.tracker = ChangeTracker(confirmDelay: confirmDelay)
        self.staleAfter = staleAfter
    }

    // MARK: Triggers

    /// Scans now, then on the timer, on wake and when the popover opens.
    func start() {
        stop()
        restartTimer()
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        refresh()
    }

    /// Stops the timer, the wake observer and the pending confirm scan. Safe to repeat.
    func stop() {
        confirmTask?.cancel()
        confirmTask = nil
        timer?.invalidate()
        timer = nil
        if let wakeObserver { NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver) }
        wakeObserver = nil
    }

    /// (Re)starts the background timer from `refreshMinutes`; call when the setting changes.
    func restartTimer() {
        timer?.invalidate()
        let interval = TimeInterval(defaults.refreshMinutes * 60)
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    /// The popover opened: rescan unless a scan just finished.
    func popoverOpened(now: Date = Date()) {
        if let lastFinished, now.timeIntervalSince(lastFinished) <= staleAfter { return }
        refresh()
    }

    /// Asks for a scan: starts one, or folds into the follow-up if one is running.
    func refresh() {
        if inFlight {
            pending = true
        } else {
            beginScan()
        }
    }

    // MARK: Scanning

    private func beginScan() {
        inFlight = true
        pending = false
        let started = generation
        let startedAt = Date()
        state = .scanning(last: state.lastGood)
        let baseline = baselines.baseline
        Task { [client] in
            let result = await client.scan(baseline: baseline)
            self.finishScan(result, generation: started, startedAt: startedAt)
        }
    }

    private func finishScan(
        _ result: Result<Scan, CoreError>, generation started: Int, startedAt: Date
    ) {
        inFlight = false
        if started == generation {
            lastFinished = Date()
            switch result {
            case .success(let scan):
                state = .ready(scan.report, at: Date())
                lastRaw = scan.raw
                track(scan, startedAt: startedAt)
            case .failure(let error): state = .failed(error, last: state.lastGood)
            }
        } else {
            // Something invalidated this result; look again.
            pending = true
        }
        runNext()
    }

    /// Starts whatever is waiting: the follow-up scan first, then a Copy report batch.
    private func runNext() {
        guard !inFlight else { return }
        if pending {
            beginScan()
        } else if !copyWaiters.isEmpty {
            beginCopy()
        }
    }

    // MARK: Copy report

    /// Runs the plain-text report once and hands it to `completion` (nil if it failed). It goes
    /// through the same one-at-a-time gate as scans, and requests made while one is waiting or
    /// running share the next run, so a click can't overlap a scan or overwrite a newer result.
    func copyReport(completion: @escaping @MainActor (String?) -> Void) {
        copyWaiters.append(completion)
        runNext()
    }

    private func beginCopy() {
        inFlight = true
        let waiters = copyWaiters
        copyWaiters = []
        let baseline = baselines.baseline
        Task { [client] in
            let text = try? await client.copyReport(baseline: baseline).get()
            self.inFlight = false
            for waiter in waiters { waiter(text) }
            self.runNext()
        }
    }

    // MARK: Change tracking

    /// What the app does with a good scan (macos.md §2.7 steps 1–7).
    private func track(_ scan: Scan, startedAt: Date) {
        let report = scan.report
        guard baselines.baseline != nil else {
            // 1. First scan: today's exposure is the baseline, silently.
            return rebaseline(scan.raw)
        }
        if report.since?.error != nil {
            // 2. A core upgrade or a corrupt baseline: start over, silently.
            return rebaseline(scan.raw)
        }
        let notifying = report.notifyingChanges.map(\.id)
        var notified = baselines.notifiedChangeIds
        let before = notified
        let due = tracker.observe(notifying: notifying, notified: &notified, started: startedAt)
        // Changes the planner skips (an entry missing from the report) are as good as handled.
        let planned = plan(changes: report.changes ?? [], report: report, ids: Set(due))
        let posted = planned.flatMap(\.changeIds)
        // Changes the planner skips (an entry missing from the report) count as handled.
        let skipped = due.filter { !posted.contains($0) }
        if !skipped.isEmpty {
            tracker.finishPost(
                due: skipped, handled: Set(skipped), epoch: tracker.epoch, notified: &notified)
        }
        if notified != before { baselines.notifiedChangeIds = notified }
        scheduleConfirm()
        guard !planned.isEmpty else { return }
        let epoch = tracker.epoch
        Task { [notifier] in
            let handled = await notifier.post(planned, isCurrent: { self.tracker.epoch == epoch })
            self.postFinished(due: posted, handled: handled, epoch: epoch)
        }
    }

    /// A post is done. If the baseline was replaced meanwhile the tracker drops it untouched;
    /// otherwise the handled ids that are still present are recorded.
    private func postFinished(due: [String], handled: Set<String>, epoch: Int) {
        var notified = baselines.notifiedChangeIds
        let before = notified
        tracker.finishPost(due: due, handled: handled, epoch: epoch, notified: &notified)
        if notified != before { baselines.notifiedChangeIds = notified }
        // Unhandled ids wait for the next scan; arming the timer for them would loop.
    }

    /// Replaces the baseline. Only a successful replacement invalidates tracking state and posts
    /// in flight; a failed one keeps both, since the old baseline is still what scans compare to.
    private func rebaseline(_ raw: Data) {
        guard baselines.replace(raw) else {
            trackingUnavailable = true
            return
        }
        trackingUnavailable = false
        tracker.reset()
        confirmTask?.cancel()
        confirmTask = nil
    }

    /// One timer, for the earliest id waiting to be confirmed; it asks for the confirm scan.
    private func scheduleConfirm() {
        confirmTask?.cancel()
        confirmTask = nil
        guard let next = tracker.nextConfirm else { return }
        let delay = max(next.timeIntervalSinceNow, 0)
        confirmTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }

    /// Makes the current report the baseline, drops whatever is in flight, and rescans.
    func markAsSeen() {
        guard let lastRaw else { return }
        guard baselines.replace(lastRaw) else {
            trackingUnavailable = true
            return
        }
        trackingUnavailable = false
        tracker.reset()
        confirmTask?.cancel()
        confirmTask = nil
        generation += 1
        refresh()
    }
}
