import Foundation

// State of the opt-in OTel debug collector: the child's lifecycle, what it printed
// (kept in memory only, bounded) and red-flag notifications. No auto-restart: a crash shows
// "Stopped" with Retry. The persisted `enabled` means intent, so it starts at launch.

/// Posts a plain-text notification. `UNAlertNotifier` is the real one; tests record.
@MainActor
protocol AlertPosting: AnyObject {
    func post(title: String, body: String, identifier: String) async
}

/// A retained `batch` and the line it came from (for "Raw records").
struct StoredBatch: Identifiable, Equatable, Sendable {
    var id: Int
    var batch: CollectorBatch
    var line: Data
}

struct StoredAlert: Identifiable, Equatable, Sendable {
    var id: Int
    var alert: CollectorAlert
    var lineBytes: Int
}

@MainActor
final class CollectorStore: ObservableObject {
    enum State: Equatable {
        case off
        case starting
        case listening(CollectorHello)
        case failed(String)
    }

    static let maxBatches = 50
    static let maxAlerts = 200
    static let maxRetainedBytes = 16 << 20
    static let notifyInterval: TimeInterval = 60
    /// Shown as the quit budget; a toggle off allows 2 s.
    static let quitGrace: TimeInterval = 1
    static let stopGrace: TimeInterval = 2

    @Published private(set) var state = State.off
    /// Oldest first.
    @Published private(set) var batches: [StoredBatch] = []
    /// Oldest first.
    @Published private(set) var alerts: [StoredAlert] = []
    /// Red flags seen since the collector started, including ones no longer retained.
    @Published private(set) var alertTotal = 0
    @Published private(set) var batchTotal = 0
    @Published private(set) var lastError: String?
    /// The child's stderr when it stopped after a `listen` error: the privileged-port note, for a
    /// selectable box. Rare on macOS, where low ports are normally allowed.
    @Published private(set) var failureNote: String?
    @Published private(set) var settings: CollectorSettings

    private let defaults: KeyValueStore
    private let poster: AlertPosting?
    private let helper: URL
    private let now: () -> Date
    private let restartDelay: Duration
    private let makeClient:
        (URL, [String], Data, @escaping @Sendable (CollectorClient.Event) -> Void) ->
            CollectorClient

    private var client: CollectorClient?
    /// Bumped on every start and stop, so late events from an old child are dropped.
    private(set) var generation = 0
    private var nextId = 0
    private var retainedBytes = 0
    private var lastNotified: [String: Date] = [:]
    private var sawListenError = false
    private var stopping: Task<Void, Never>?
    private var restartTask: Task<Void, Never>?

    init(
        defaults: KeyValueStore, poster: AlertPosting? = nil,
        helper: URL = CollectorClient.locate(), now: @escaping () -> Date = Date.init,
        restartDelay: Duration = .milliseconds(800),
        makeClient:
            @escaping (
                URL, [String], Data, @escaping @Sendable (CollectorClient.Event) -> Void
            ) -> CollectorClient = { helper, args, config, onEvent in
                CollectorClient(helper: helper, args: args, config: config, onEvent: onEvent)
            }
    ) {
        self.defaults = defaults
        self.poster = poster
        self.helper = helper
        self.now = now
        self.restartDelay = restartDelay
        self.makeClient = makeClient
        settings = defaults.collectorSettings
    }

    var isRunning: Bool {
        switch state {
        case .starting, .listening: return true
        case .off, .failed: return false
        }
    }

    // MARK: Settings

    /// Saves `new`. Turning it on or off starts or stops the child; any other change that
    /// reaches the child restarts it after a short pause, so typing a pattern doesn't restart
    /// it on every key.
    func apply(_ new: CollectorSettings) {
        let old = settings
        settings = new
        defaults.collectorSettings = new
        if new.enabled != old.enabled {
            restartTask?.cancel()
            new.enabled ? start() : stop()
        } else if new.enabled, new.arguments != old.arguments || new.configLine != old.configLine {
            scheduleRestart()
        }
    }

    private func scheduleRestart() {
        restartTask?.cancel()
        restartTask = Task { [restartDelay] in
            try? await Task.sleep(for: restartDelay)
            guard !Task.isCancelled else { return }
            restart()
        }
    }

    // MARK: Lifecycle

    /// Starts at launch when the toggle is on.
    func launchIfEnabled() {
        if settings.enabled { start() }
    }

    func start() {
        guard !isRunning else { return }
        restartTask?.cancel()
        generation += 1
        let mine = generation
        batches = []
        alerts = []
        alertTotal = 0
        batchTotal = 0
        retainedBytes = 0
        lastError = nil
        failureNote = nil
        sawListenError = false
        lastNotified = [:]
        if let problem = settings.takeoverProblem {
            state = .failed(problem)
            return
        }
        guard let config = settings.configLine else {
            state = .failed("Too many red-flag patterns.")
            return
        }
        state = .starting
        let previous = stopping
        Task {
            // A port is free only once the old child is reaped.
            await previous?.value
            guard generation == mine else { return }
            launch(config: config, generation: mine)
        }
    }

    private func launch(config: Data, generation mine: Int) {
        let child = makeClient(helper, settings.arguments, config) { event in
            Task { @MainActor [weak self] in self?.handle(event, generation: mine) }
        }
        client = child
        child.start()
    }

    /// Stops the child and waits for it in the background.
    func stop() {
        restartTask?.cancel()
        generation += 1
        state = .off
        guard let child = client else { return }
        client = nil
        stopInBackground(child)
    }

    /// Queued after any earlier stop, so two children never overlap.
    private func stopInBackground(_ child: CollectorClient) {
        let previous = stopping
        let grace = Self.stopGrace
        stopping = Task.detached {
            await previous?.value
            child.stop(grace: grace)
        }
    }

    func restart() {
        guard settings.enabled else { return }
        stop()
        start()
    }

    func retry() {
        guard case .failed = state else { return }
        start()
    }

    /// The app is quitting: stop the child before returning, within `quitGrace`.
    func stopForQuit() {
        generation += 1
        state = .off
        restartTask?.cancel()
        client?.stop(grace: Self.quitGrace)
        client = nil
    }

    // MARK: Events

    func handle(_ event: CollectorClient.Event, generation mine: Int) {
        guard mine == generation else { return }
        switch event {
        case .line(let line): handleLine(line)
        case .oversize: fail("Stopped: output too large.")
        case .exited(let code, let stderr):
            guard case .failed = state else {
                let first = stderr.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
                if sawListenError, !stderr.isEmpty { failureNote = stderr.plainMultilineText }
                return fail(
                    first.isEmpty
                        ? "Stopped: exited with code \(code)." : "Stopped: \(first.plainText)")
            }
        case .failed(let reason): fail("Couldn't start: \(reason.plainText)")
        }
    }

    private func handleLine(_ line: Data) {
        switch CollectorEvent.decode(line) {
        case .hello(let hello): state = .listening(hello)
        case .batch(let batch):
            batchTotal += 1
            batches.append(StoredBatch(id: newId(), batch: batch, line: line))
            retain(line.count)
        case .alert(let alert):
            alertTotal += 1
            alerts.append(StoredAlert(id: newId(), alert: alert, lineBytes: line.count))
            retain(line.count)
            notify(alert)
        case .error(let error):
            lastError = error.message?.plainText
            if error.source == "listen" { sawListenError = true }
        case .unsupported:
            fail("Update cAInary: this collector speaks a newer format.")
        case .ignored: break
        }
    }

    private func newId() -> Int {
        nextId += 1
        return nextId
    }

    /// Drops the oldest batches (then alerts) beyond 50, 200 and 16 MiB in all.
    private func retain(_ added: Int) {
        retainedBytes += added
        while batches.count > Self.maxBatches { dropOldestBatch() }
        while alerts.count > Self.maxAlerts { dropOldestAlert() }
        while retainedBytes > Self.maxRetainedBytes {
            if batches.count > 1 {
                dropOldestBatch()
            } else if !alerts.isEmpty {
                dropOldestAlert()
            } else if !batches.isEmpty {
                dropOldestBatch()
            } else {
                break
            }
        }
    }

    private func dropOldestBatch() {
        retainedBytes -= batches.removeFirst().line.count
    }

    private func dropOldestAlert() {
        retainedBytes -= alerts.removeFirst().lineBytes
    }

    /// Stops the child and shows why.
    private func fail(_ reason: String) {
        state = .failed(reason)
        guard let child = client else { return }
        client = nil
        stopInBackground(child)
    }

    // MARK: Notifications

    /// One notification per pattern per minute, plain text.
    private func notify(_ alert: CollectorAlert) {
        guard settings.notify, let poster else { return }
        let pattern = alert.pattern ?? "unknown"
        let at = now()
        if let last = lastNotified[pattern], at.timeIntervalSince(last) < Self.notifyInterval {
            return
        }
        lastNotified[pattern] = at
        let place = [alert.event, alert.attribute].compactMap { $0 }.joined(separator: " · ")
        let match = alert.match.map { " (\($0))" } ?? ""
        Task {
            await poster.post(
                title: "Red flag: \(pattern.plainText)", body: "\(place)\(match)".plainText,
                identifier: Self.notificationPrefix + pattern.plainText)
        }
    }

    /// A notification click with this identifier opens the collector pane.
    static let notificationPrefix = "otel-collector-alert:"
}
