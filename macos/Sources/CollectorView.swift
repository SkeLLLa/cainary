import AppKit
import SwiftUI

// The collector window (Details › Live › OTel collector): a header with the status and the
// start/stop button, the failure banner when the collector can't run, and the tabs Feed, Red flags,
// Rules, Logs and Setup. Twin of linux/crates/cainary-tray/qml/CollectorPage.qml. `CollectorView`
// wires the stores; `CollectorPageView` takes plain values and a content closure so it can be
// snapshot.

extension CollectorStore.State {
    /// The dot's colour: green while it listens, orange while it starts or has failed.
    var dotColor: Color {
        switch self {
        case .off: Color.secondary
        case .starting, .failed: Color.orange
        case .listening: Color.green
        }
    }

    var label: String {
        switch self {
        case .off: "Off"
        case .starting: "Starting…"
        case .listening: "Listening"
        case .failed: "Failed"
        }
    }

    /// The URL agents send to, once the collector listens.
    var endpoint: String? {
        if case .listening(let hello) = self { return hello.endpoint }
        return nil
    }
}

extension FeedFilter {
    /// The feed's starting filter: all three signals on, nothing else.
    static var initial: FeedFilter { FeedFilter(signals: ["logs", "metrics", "traces"]) }
}

/// A small coloured dot that says the collector's state; the state text sits next to it.
struct CollectorStatusDot: View {
    let state: CollectorStore.State

    var body: some View {
        Circle().fill(state.dotColor).frame(width: 9, height: 9)
            .accessibilityLabel(state.label)
    }
}

// MARK: - The wired window

struct CollectorView: View {
    @ObservedObject var store: CollectorStore
    @ObservedObject var navigation: Navigation
    @ObservedObject var trust: TrustStore
    /// Held by the Details window, so the steps a user opened and a running edit outlive a switch
    /// to another sidebar row.
    @ObservedObject var takeover: TakeoverController
    @Binding var filter: FeedFilter
    @Binding var selected: String?
    /// Host names found in the latest scan, offered in Setup.
    var hostSuggestions: [String] = []

    var body: some View {
        let settings = store.settings
        CollectorPageView(
            state: store.state, batchTotal: store.batchTotal, enabled: settings.enabled,
            tab: $navigation.collectorTab, unseenFlags: store.unseenFlagCount,
            errorCount: store.errors.count + (store.stderrTail.isEmpty ? 0 : 1),
            failure: store.failure,
            nextPort: store.failure.flatMap { FailureAdvice.tryNextPort($0, in: settings)?.port },
            onToggle: toggle, onRetry: { store.retry() },
            onOpenSettings: { WindowOpener.shared.openSettings() },
            onOpenSetup: { navigation.collectorTab = .setup },
            onOpenRules: { navigation.collectorTab = .rules }, takeover: settings.takeover,
            onShowLogs: { navigation.collectorTab = .logs }, onTryPort: tryPort
        ) {
            tabContent(settings)
        }
        .onAppear(perform: takePattern)
        .onChange(of: navigation.feedPattern) { _, _ in takePattern() }
        .onChange(of: store.alertTotal) { _, _ in
            if navigation.collectorTab == .flags { store.markFlagsSeen() }
        }
        .task(id: store.tlsHelloCount) {
            // Each new TLS collector start may have made or changed the certificate.
            if store.tlsHelloCount > 0 { await trust.refresh() }
        }
        .task(id: navigation.collectorTab) {
            if navigation.collectorTab == .setup { await trust.refresh() }
        }
    }

    @ViewBuilder
    private func tabContent(_ settings: CollectorSettings) -> some View {
        switch navigation.collectorTab {
        case .feed:
            CollectorFeedView(
                rows: buildFeedRows(
                    batches: store.feedBatches.map(\.batch), alerts: store.feedAlerts.map(\.alert)),
                filter: $filter, selected: $selected, paused: store.paused,
                heldCount: store.heldCount, enabled: settings.enabled,
                onTogglePause: { store.togglePause() }, onClear: { store.clearFeed() },
                rawRecords: { seq in
                    store.feedBatches.first { $0.batch.seq == seq }
                        .flatMap { CollectorBatch.rawResources(in: $0.line) }
                })
        case .flags:
            CollectorFlagsView(
                groups: buildFlagGroups(alerts: store.alerts.reversed().map(\.alert)),
                focus: navigation.flagFocus, enabled: settings.enabled,
                markSeen: { store.markFlagsSeen() }, onShowInFeed: showInFeed,
                onLeave: { navigation.flagFocus = nil })
        case .rules:
            ScrollView {
                CollectorRulesView(settings: settings, onChange: { store.apply($0) })
            }
        case .logs:
            CollectorLogsView(
                errors: store.errors, stderrTail: store.stderrTail,
                formatTime: { formatClock($0) }, onCopy: copy)
        case .setup:
            setup(settings)
        }
    }

    // MARK: actions

    private func toggle() {
        var next = store.settings
        next.enabled.toggle()
        store.apply(next)
    }

    /// Moves the port that is in use to the next one. A running collector restarts by itself.
    private func tryPort(_ port: Int) {
        guard let failure = store.failure,
            let change = FailureAdvice.tryNextPort(failure, in: store.settings)
        else { return }
        store.apply(change.settings)
    }

    private func showInFeed(_ pattern: String) {
        filter.pattern = pattern
        selected = nil
        navigation.collectorTab = .feed
    }

    /// A pattern another part of the app asked the feed to filter on.
    private func takePattern() {
        guard let pattern = navigation.feedPattern else { return }
        navigation.feedPattern = nil
        showInFeed(pattern)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    // MARK: setup

    private func setup(_ settings: CollectorSettings) -> some View {
        var hello: CollectorHello?
        if case .listening(let found) = store.state { hello = found }
        return CollectorSetupView(
            settings: settings, onChange: { store.apply($0) },
            takeoverLines: hello?.setup?.takeover, lastTakeoverLines: store.lastTakeoverLines,
            setup: hello?.setup, endpoint: hello?.endpoint,
            collectorOn: settings.enabled, suggestions: hostSuggestions,
            state: takeover.state(
                hosts: settings.validHosts, port: settings.takeoverPort,
                listening: hello != nil, batchCount: store.batchTotal),
            trust: trust.snapshot, trustPending: trust.pending,
            onConfirmTrust: { Task { await trust.confirm() } },
            onCancelTrust: { trust.cancel() }, openSteps: $takeover.stepOpen, actions: actions)
    }

    private var actions: TakeoverActions {
        let store = store, trust = trust, takeover = takeover
        return TakeoverActions(
            refresh: {
                Task { await takeover.refresh(hosts: store.settings.validHosts) }
            },
            addHosts: {
                Task {
                    await takeover.addHosts(
                        store.settings.validHosts, latest: { store.settings.validHosts })
                }
            },
            removeHosts: {
                Task {
                    await takeover.removeHosts(
                        hosts: store.settings.validHosts, latest: { store.settings.validHosts })
                }
            },
            enableRedirect: {
                Task { await takeover.enableRedirect(port: store.settings.takeoverPort) }
            },
            disableRedirect: { Task { await takeover.disableRedirect() } },
            requestClaudeTrust: { Task { await trust.requestClaudeCodeTrust() } },
            undoClaudeTrust: { Task { await trust.undoClaudeCode() } },
            prepareCodex: { Task { await trust.prepareCodex() } },
            removeCodex: { Task { await trust.removeCodex() } },
            switchOff: {
                var next = store.settings
                next.takeover = false
                store.apply(next)
            })
    }
}

// MARK: - The page, as values

struct CollectorPageView<Content: View>: View {
    let state: CollectorStore.State
    let batchTotal: Int
    /// The persisted on/off intent, which the start/stop button flips.
    let enabled: Bool
    @Binding var tab: CollectorTab
    let unseenFlags: Int
    let errorCount: Int
    let failure: CollectorFailure?
    /// The "Try port N+1" offer for a port that is in use.
    var nextPort: Int?
    let onToggle: () -> Void
    let onRetry: () -> Void
    let onOpenSettings: () -> Void
    let onOpenSetup: () -> Void
    var onOpenRules: () -> Void = {}
    /// The HTTPS takeover is on: port failures point at Setup.
    var takeover = false
    let onShowLogs: () -> Void
    var onTryPort: (Int) -> Void = { _ in }
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if let failure {
                CollectorFailureView(
                    failure: failure, onRetry: onRetry, onOpenSettings: onOpenSettings,
                    onOpenSetup: onOpenSetup, onOpenRules: onOpenRules, takeover: takeover,
                    onShowLogs: onShowLogs, nextPort: nextPort,
                    onTryPort: onTryPort
                )
                .padding(.horizontal, 12).padding(.bottom, 8)
            }
            CollectorTabBar(tab: $tab, unseenFlags: unseenFlags, errorCount: errorCount)
            Divider()
            content().frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("OTel debug collector").font(.title3.weight(.semibold))
            CollectorStatusDot(state: state)
            Text(state.label).foregroundStyle(.secondary)
            if let endpoint = state.endpoint {
                Text(verbatim: endpoint)
                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            Text(verbatim: String(batchTotal) + (batchTotal == 1 ? " batch" : " batches"))
                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            Button(action: onToggle) {
                Text(enabled ? "Stop" : "Start").font(.callout)
                    .padding(.horizontal, 10).padding(.vertical, 3)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(enabled ? "Stop the collector" : "Start the collector")
        }
        .padding(12)
    }
}

/// Feed | Red flags | Rules | Logs | Setup, with the unseen red-flag count and the error count.
private struct CollectorTabBar: View {
    @Binding var tab: CollectorTab
    let unseenFlags: Int
    let errorCount: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(CollectorTab.allCases, id: \.self) { item in
                let on = tab == item
                Button {
                    tab = item
                } label: {
                    HStack(spacing: 5) {
                        Text(item.title).fontWeight(on ? .semibold : .regular)
                        badge(item)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(
                        on ? Color.accentColor.opacity(0.18) : Color.clear,
                        in: RoundedRectangle(cornerRadius: 6))
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    @ViewBuilder
    private func badge(_ item: CollectorTab) -> some View {
        if item == .flags, unseenFlags > 0 {
            CountBadge(count: unseenFlags, color: .red)
        } else if item == .logs, errorCount > 0 {
            CountBadge(count: errorCount, color: .secondary)
        }
    }
}

/// A count in a coloured capsule; white on red for unseen red flags.
struct CountBadge: View {
    let count: Int
    let color: Color

    var body: some View {
        Text(verbatim: String(count))
            .font(.caption2.weight(.semibold).monospacedDigit())
            .foregroundStyle(.white)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color, in: Capsule())
            .accessibilityLabel(String(count))
    }
}

// MARK: - Sidebar pieces

/// The Live section's collector row: a status dot, the name and the unseen red-flag badge.
struct CollectorSidebarRow: View {
    let state: CollectorStore.State
    let unseenFlags: Int

    var body: some View {
        HStack(spacing: 6) {
            Label("OTel collector", systemImage: "antenna.radiowaves.left.and.right")
                .lineLimit(1)
            Spacer(minLength: 4)
            if unseenFlags > 0 { CountBadge(count: unseenFlags, color: .red) }
            CollectorStatusDot(state: state)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The toolbar's compact collector status: the dot, a few words and the unseen red flags.
struct CollectorPill: View {
    let state: CollectorStore.State
    let unseenFlags: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                CollectorStatusDot(state: state)
                Text("Collector " + state.label.lowercased()).font(.callout)
                if unseenFlags > 0 { CountBadge(count: unseenFlags, color: .red) }
            }
            .padding(.horizontal, 8).padding(.vertical, 2)
        }
        .buttonStyle(.plain)
        .help("Open the OTel debug collector")
    }
}

// MARK: - View-owned state

/// What the collector page keeps while another sidebar row is shown: the feed's filter and open
/// row. A class, because the toolchain has no `@State` (it is a macro there).
@MainActor
final class CollectorPageState: ObservableObject {
    @Published var filter = FeedFilter.initial
    @Published var selected: String?
}
