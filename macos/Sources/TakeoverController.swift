import Foundation

// The state and the async actions behind the takeover guide: the one-click helper check, reading
// /etc/hosts, the host lookups, and the hosts and pf-redirect edits. Everything that touches the
// system comes in through `Dependencies`, so tests run it on fakes. Two rules (plan R9):
//   - a generation counter: a read or lookup that finishes after a newer one (or an edit) started
//     is dropped, so a slow answer never overwrites a fresh one;
//   - one edit at a time: set/clear of the hosts block and of the redirect share `busy`.
// The views never compute; they take a `TakeoverState` value from `state(...)` and closures.

enum TakeoverTone: Equatable, Sendable {
    case info, warning, error
}

/// One line about how the last action went.
struct TakeoverMessage: Equatable, Sendable {
    var text: String
    var tone: TakeoverTone
}

enum TakeoverBusy: Equatable, Sendable {
    case hosts(HostsOp)
    case redirect(HostsOp)
}

/// Whether the pf redirect is on. The app can't read pf without root, so this only follows what
/// the app itself did this session.
enum RedirectKnown: Equatable, Sendable {
    case unknown, enabled, disabled
}

enum StepStatus: Equatable, Sendable {
    case done, todo, waiting, unknown, off
}

/// A step's status and the few words next to it.
struct StepIndicator: Equatable, Sendable {
    var status: StepStatus
    var text: String
}

/// Whether the trust step is done: a value taken from `TrustStore`.
struct TrustSnapshot: Equatable, Sendable {
    var status: TrustStatus?
    var busy = false
    var message: String?
    var failed = false

    var claudeApplied: Bool { status?.claudeCode?.state == "applied" }
    var claudeOther: Bool { status?.claudeCode?.state == "other-value" }
    var claudeManaged: Bool { status?.claudeCode?.state == "managed" }
    var codexReady: Bool { status?.codex?.state == "ready" }
    var codexCommand: String? { codexReady ? status?.codex?.command : nil }
    /// The certificate is made when the takeover first starts.
    var caMissing: Bool { status?.caExists == false }
    var noWriteCommand: String? {
        caMissing ? nil : status?.caPath.map(nodeExtraCACommand(caPath:))
    }
}

/// Everything the guide shows about /etc/hosts, the lookups, the redirect and the collector.
struct TakeoverState: Equatable, Sendable {
    /// The valid configured names (`CollectorSettings.validHosts`).
    var hosts: [String] = []
    var port = CollectorSettings.defaultTakeoverPort
    /// Nil before the first check.
    var helper: HostsHelperStatus?
    /// Nil before the first read.
    var file: HostsFileSummary?
    var lookups: [String: LookupResult] = [:]
    var checking = false
    var busy: TakeoverBusy?
    var hostsMessage: TakeoverMessage?
    var redirectMessage: TakeoverMessage?
    var redirect = RedirectKnown.unknown
    /// The port the last successful enable pointed pf at.
    var redirectPort: Int?
    var listening = false
    var batchCount = 0

    var gate: HostsGate { HostsFile.gate(hosts: hosts, file: file) }

    /// The redirect is on, but for another port than the one the collector uses now.
    var redirectStale: Bool {
        guard redirect == .enabled, let redirectPort else { return false }
        return redirectPort != port
    }

    /// What to tell the user when `redirectStale`.
    var redirectStaleNote: String? {
        guard redirectStale, let redirectPort else { return nil }
        return "The redirect points at port \(redirectPort); enable it again for \(port)."
    }

    var helperReason: String? {
        if case .unavailable(let reason) = helper { return reason }
        return nil
    }

    private var helperReady: Bool {
        if case .ready = helper { return true }
        return false
    }

    var canAdd: Bool { gate.canEdit && helperReady && busy == nil }
    var canRemove: Bool { gate.canRemove && helperReady && busy == nil }

    /// Why "Add to /etc/hosts" is disabled: the file or names first, then the build.
    var addReason: String? {
        if gate.canEdit { return helperReason }
        return gate.editReason ?? helperReason
    }

    /// Why "Remove" is disabled while there is something to remove.
    var removeReason: String? { gate.canRemove ? helperReason : nil }

    /// cAInary's lines are in /etc/hosts (a block it can remove).
    var ownBlock: Bool {
        guard let state = file?.analysis?.state else { return false }
        return state == .current || state == .stale
    }

    var damagedBlock: Bool { file?.analysis?.state == .damaged }

    var lookedUp: Bool { !hosts.isEmpty && hosts.allSatisfy { lookups[$0] != nil } }
    var allResolveHere: Bool { lookedUp && hosts.allSatisfy { lookups[$0] == .here } }

    /// "resolves to 127.0.0.1" or "not yet …" for one name.
    func lookupText(_ host: String) -> String {
        switch lookups[host] {
        case .here: return "resolves to 127.0.0.1"
        case .elsewhere(let others): return "not yet: resolves to \(others.joined(separator: ", "))"
        case .error(let why): return "not yet: \(why)"
        case nil: return checking ? "checking…" : "not checked"
        }
    }

    // MARK: step indicators

    func indicator(_ kind: StepKind, trust: TrustSnapshot) -> StepIndicator {
        switch kind {
        case .hosts: return hostsIndicator
        case .redirect: return redirectIndicator
        case .flush:
            return allResolveHere
                ? StepIndicator(status: .done, text: "Names resolve here")
                : StepIndicator(status: .unknown, text: "After the hosts step")
        case .trust: return trustIndicator(trust)
        case .restart: return restartIndicator
        case .other: return StepIndicator(status: .unknown, text: "")
        }
    }

    private var hostsIndicator: StepIndicator {
        if busy == .hosts(.set) || busy == .hosts(.clear) {
            return StepIndicator(status: .waiting, text: "Waiting for permission")
        }
        if checking { return StepIndicator(status: .waiting, text: "Checking…") }
        if hosts.isEmpty { return StepIndicator(status: .todo, text: "Add a host name") }
        if !lookedUp { return StepIndicator(status: .unknown, text: "Not checked") }
        if allResolveHere { return StepIndicator(status: .done, text: "Points here") }
        switch file?.analysis?.state {
        case .current: return StepIndicator(status: .todo, text: "Still points elsewhere")
        case .stale: return StepIndicator(status: .todo, text: "Out of date")
        default: break
        }
        let results = hosts.compactMap { lookups[$0] }
        let allErrors = results.allSatisfy {
            if case .error = $0 { return true }
            return false
        }
        return StepIndicator(
            status: .todo, text: allErrors ? "Doesn't resolve" : "Points elsewhere")
    }

    private var redirectIndicator: StepIndicator {
        if busy == .redirect(.set) || busy == .redirect(.clear) {
            return StepIndicator(status: .waiting, text: "Waiting for permission")
        }
        switch redirect {
        case .enabled:
            if let redirectPort, redirectPort != port {
                return StepIndicator(status: .todo, text: "Points at port \(redirectPort)")
            }
            return StepIndicator(status: .done, text: "Enabled")
        case .disabled: return StepIndicator(status: .todo, text: "Not enabled")
        case .unknown: return StepIndicator(status: .unknown, text: "Can't check")
        }
    }

    private func trustIndicator(_ trust: TrustSnapshot) -> StepIndicator {
        if trust.status == nil || trust.caMissing {
            return StepIndicator(status: .off, text: "Starts after the collector runs once")
        }
        if trust.claudeApplied && trust.codexReady {
            return StepIndicator(status: .done, text: "Both ready")
        }
        if trust.claudeApplied { return StepIndicator(status: .done, text: "Claude Code trusted") }
        if trust.codexReady { return StepIndicator(status: .done, text: "Codex ready") }
        if trust.claudeOther {
            return StepIndicator(status: .todo, text: "Claude Code uses another certificate")
        }
        return StepIndicator(status: .todo, text: "Not done")
    }

    private var restartIndicator: StepIndicator {
        if !listening { return StepIndicator(status: .off, text: "Collector isn't running") }
        if batchCount > 0 {
            return StepIndicator(
                status: .done,
                text: batchCount == 1 ? "Receiving · 1 batch" : "Receiving · \(batchCount) batches")
        }
        return StepIndicator(status: .waiting, text: "Waiting for the first batch")
    }
}

@MainActor
final class TakeoverController: ObservableObject {
    struct Dependencies: Sendable {
        /// Locates and verifies the bundled helper. Blocks; run off the main thread.
        var checkHelper: @Sendable () -> HostsHelperStatus
        /// Reads and analyzes /etc/hosts for these names. Blocks; run off the main thread.
        var readHosts: @Sendable ([String]) -> HostsFileSummary
        var lookup: @Sendable ([String]) async -> [String: LookupResult]
        /// `requirement` comes from `HostsHelperStatus.ready`. A clear gets no names.
        var editHosts: @Sendable (HostsOp, [String], String) async -> HostsEditOutcome
        /// `port` is the redirect target for a set; nil for a clear.
        var editRedirect: @Sendable (HostsOp, Int?) async -> RedirectOutcome
        /// The redirect port remembered from an earlier run, and the setter; nil means off.
        var loadRedirectPort: @Sendable () -> Int? = { nil }
        var saveRedirectPort: @Sendable (Int?) -> Void = { _ in }

        static let system = Dependencies(
            checkHelper: { HostsHelperCheck.check() },
            readHosts: { HostsFile.read(hosts: $0) },
            lookup: { await HostLookup.check($0) },
            editHosts: { op, hosts, requirement in
                await HostsEditor.editHosts(
                    op: op, hosts: hosts,
                    helperPath: HostsHelperCheck.helperPath(bundleURL: Bundle.main.bundleURL),
                    requirement: requirement)
            },
            editRedirect: { op, port in await HostsEditor.editRedirect(op: op, port: port) },
            loadRedirectPort: {
                let port = UserDefaults.standard.integer(forKey: PrefKey.takeoverRedirectPort)
                return port > 0 ? port : nil
            },
            saveRedirectPort: { port in
                if let port {
                    UserDefaults.standard.set(port, forKey: PrefKey.takeoverRedirectPort)
                } else {
                    UserDefaults.standard.removeObject(forKey: PrefKey.takeoverRedirectPort)
                }
            })
    }

    @Published private(set) var helper: HostsHelperStatus?
    @Published private(set) var file: HostsFileSummary?
    @Published private(set) var lookups: [String: LookupResult] = [:]
    @Published private(set) var checking = false
    @Published private(set) var busy: TakeoverBusy?
    @Published private(set) var hostsMessage: TakeoverMessage?
    @Published private(set) var redirectMessage: TakeoverMessage?
    @Published private(set) var redirect = RedirectKnown.unknown
    @Published private(set) var redirectPort: Int?
    /// The host sets `file` and `lookups` were computed for; a different set hides them.
    private var fileHosts: [String]?
    private var lookupHosts: [String]?
    /// Step key → whether the user opened (true) or closed (false) it. The guide's default is
    /// open while a step isn't done; a choice here wins and outlives a tab switch.
    @Published var stepOpen: [String: Bool] = [:]

    /// Bumped by every refresh and edit; a result from an older number is dropped.
    private(set) var generation = 0
    private let deps: Dependencies

    init(dependencies: Dependencies = .system) {
        deps = dependencies
        // A redirect enabled in an earlier run may still be on (pf keeps it until a restart).
        if let port = dependencies.loadRedirectPort() {
            redirect = .enabled
            redirectPort = port
        }
    }

    /// The value the views render.
    func state(
        hosts: [String], port: Int, listening: Bool = false, batchCount: Int = 0
    ) -> TakeoverState {
        TakeoverState(
            hosts: hosts, port: port, helper: helper,
            // An analysis made for other names says nothing about these.
            file: fileHosts == hosts ? file : nil,
            // Only answers for the names shown now.
            lookups: lookupHosts == hosts ? lookups.filter { hosts.contains($0.key) } : [:],
            checking: checking, busy: busy,
            hostsMessage: hostsMessage, redirectMessage: redirectMessage, redirect: redirect,
            redirectPort: redirectPort, listening: listening, batchCount: batchCount)
    }

    // MARK: Reading

    /// Checks the helper (once, or again with `recheckHelper`), re-reads /etc/hosts and looks the
    /// names up. A newer refresh or an edit makes this one drop its results.
    func refresh(hosts: [String], recheckHelper: Bool = false) async {
        generation += 1
        let mine = generation
        checking = true
        let deps = deps
        if helper == nil || recheckHelper {
            let found = await Task.detached { deps.checkHelper() }.value
            guard mine == generation else { return }
            helper = found
        }
        let summary = await Task.detached { deps.readHosts(hosts) }.value
        guard mine == generation else { return }
        file = summary
        fileHosts = hosts
        guard !hosts.isEmpty else {
            lookups = [:]
            lookupHosts = hosts
            checking = false
            return
        }
        let found = await deps.lookup(hosts)
        guard mine == generation else { return }
        lookups = found
        lookupHosts = hosts
        checking = false
    }

    // MARK: Edits

    /// One-click "Add to /etc/hosts". Does nothing while another edit runs or when the helper
    /// isn't trusted. Re-reads and re-checks afterwards, never retries.
    /// `latest` gives the names configured when the edit ends (the user may have changed them
    /// while the admin prompt was open); the re-read uses those, not `hosts`.
    func addHosts(_ hosts: [String], latest: (() -> [String])? = nil) async {
        guard busy == nil, case .ready(let requirement) = helper else { return }
        busy = .hosts(.set)
        hostsMessage = nil
        generation += 1
        let outcome = await deps.editHosts(.set, hosts, requirement)
        hostsMessage = Self.message(outcome, op: .set)
        busy = nil
        await refresh(hosts: latest?() ?? hosts)
    }

    /// One-click "Remove". `hosts` (or `latest()` when given) are only the names to re-analyze
    /// afterwards.
    func removeHosts(hosts: [String], latest: (() -> [String])? = nil) async {
        guard busy == nil, case .ready(let requirement) = helper else { return }
        busy = .hosts(.clear)
        hostsMessage = nil
        generation += 1
        let outcome = await deps.editHosts(.clear, [], requirement)
        hostsMessage = Self.message(outcome, op: .clear)
        busy = nil
        await refresh(hosts: latest?() ?? hosts)
    }

    func enableRedirect(port: Int) async {
        guard busy == nil else { return }
        busy = .redirect(.set)
        redirectMessage = nil
        let outcome = await deps.editRedirect(.set, port)
        apply(outcome, op: .set, port: port)
        busy = nil
    }

    func disableRedirect() async {
        guard busy == nil else { return }
        busy = .redirect(.clear)
        redirectMessage = nil
        let outcome = await deps.editRedirect(.clear, nil)
        apply(outcome, op: .clear, port: nil)
        busy = nil
    }

    /// `port` is the one pf was pointed at; it's kept so a later port change shows as pending.
    private func apply(_ outcome: RedirectOutcome, op: HostsOp, port: Int?) {
        switch outcome {
        case .done(let text):
            redirect = op == .set ? .enabled : .disabled
            redirectPort = op == .set ? port : nil
            deps.saveRedirectPort(redirectPort)
            redirectMessage = TakeoverMessage(text: text, tone: .info)
        case .cancelled(let text):
            redirectMessage = TakeoverMessage(text: text, tone: .info)
        case .notRun(let text), .failed(let text):
            redirectMessage = TakeoverMessage(text: text, tone: .error)
        case .uncertain(let text):
            redirect = .unknown
            redirectPort = nil
            redirectMessage = TakeoverMessage(text: text, tone: .warning)
        }
    }

    /// The outcome as one line for the hosts step.
    static func message(_ outcome: HostsEditOutcome, op: HostsOp) -> TakeoverMessage {
        switch outcome {
        case .done(let changed, let synced, let text):
            if !text.isEmpty {
                return TakeoverMessage(text: text, tone: synced ? .info : .warning)
            }
            if !changed { return TakeoverMessage(text: "Already up to date.", tone: .info) }
            return TakeoverMessage(
                text: op == .set
                    ? "Added cAInary's lines to /etc/hosts." : "Removed cAInary's lines.",
                tone: .info)
        case .cancelled(let text): return TakeoverMessage(text: text, tone: .info)
        case .notRun(let text): return TakeoverMessage(text: text, tone: .error)
        case .refused(_, let text): return TakeoverMessage(text: text, tone: .error)
        case .uncertain(let text): return TakeoverMessage(text: text, tone: .warning)
        }
    }
}

extension TrustStore {
    /// What the guide needs from the trust store.
    var snapshot: TrustSnapshot {
        TrustSnapshot(status: status, busy: busy, message: message, failed: failed)
    }
}
