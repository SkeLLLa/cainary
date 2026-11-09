import Foundation
import SwiftUI

// The whole collector window (header, failure banner, tabs and a tab's content) and the sidebar's
// Live row, on the sample lines of the contract (Tests/Support) and fixture names only
// (example-corp.test), with a fixed UTC clock. The Details split view and its List don't render
// in ImageRenderer, so the sidebar is drawn from the same row, badge and pill views in a plain
// stack, and tab contents use their static layouts.

@MainActor
func collectorSnapshot(out: URL) {
    let utc = { (ts: String) in formatClock(ts, timeZone: TimeZone(identifier: "UTC")!) }
    func event(_ line: String) -> CollectorEvent {
        CollectorEvent.decode(CollectorSamples.data(line))
    }
    guard case .hello(let hello) = event(CollectorSamples.hello),
        case .batch(let first) = event(CollectorSamples.batch),
        case .batch(let second) = event(CollectorSamples.batchProtobufGzip),
        case .alert(let alert) = event(CollectorSamples.alert)
    else {
        check("collector window: sample lines decode", false)
        return
    }
    var third = first
    third.seq = 3
    third.ts = "2026-01-01T12:00:11Z"
    third.bytes = 3120
    third.records = 2
    let batches = [first, second, third]
    var other = alert
    other.seq = 2
    other.pattern = "internal-host"
    other.preset = false
    other.count = 1
    other.ts = "2026-01-01T12:00:11Z"
    let alerts = [alert, other]

    func render(_ file: String, _ view: some View, heights: ClosedRange<CGFloat> = 100...3000) {
        let url = out.appendingPathComponent(file)
        checkPNG(file, url, size: writePNG(view, to: url), heights: heights)
    }

    func window(
        _ state: CollectorStore.State, tab: CollectorTab, unseen: Int, errors: Int,
        failure: CollectorFailure? = nil, nextPort: Int? = nil, total: Int = 3,
        @ViewBuilder content: @escaping () -> some View
    ) -> some View {
        CollectorPageView(
            state: state, batchTotal: total, enabled: true, tab: .constant(tab),
            unseenFlags: unseen, errorCount: errors, failure: failure, nextPort: nextPort,
            onToggle: {}, onRetry: {}, onOpenSettings: {}, onOpenSetup: {}, onShowLogs: {},
            content: content
        )
        .frame(width: 760, height: 520, alignment: .topLeading)
    }

    // Feed tab with data, and the badge on Red flags.
    let rows = buildFeedRows(batches: batches, alerts: alerts, formatTime: utc)
    render(
        "collector-window-feed.png",
        window(.listening(hello), tab: .feed, unseen: 2, errors: 1) {
            CollectorFeedView(
                rows: rows, filter: .constant(.initial),
                selected: .constant(rows.first(where: { $0.batchID == 3 })?.key), paused: false,
                heldCount: 0, enabled: true, onTogglePause: {}, onClear: {}, staticLayout: true)
        })

    // Red flags tab, badge still on the tab.
    let groups = buildFlagGroups(alerts: alerts.reversed(), formatTime: utc)
    render(
        "collector-window-flags.png",
        window(.listening(hello), tab: .flags, unseen: 2, errors: 0) {
            CollectorFlagsView(
                groups: groups, focus: "aws-access-key", enabled: true, markSeen: {},
                onShowInFeed: { _ in }, staticLayout: true)
        })

    // The failure banner above the tabs: port in use, with the next port on offer.
    let failure = CollectorFailure(code: "port-in-use", port: 8443, message: "address in use")
    let logs = [
        CollectorError(
            ts: "2026-01-01T12:00:01Z", source: "listen",
            message: "127.0.0.1:8443 is already in use", code: "port-in-use")
    ]
    let tail = ["cainary-otel-debug: listen 127.0.0.1:8443: Address already in use (os error 48)"]
    render(
        "collector-window-failure.png",
        window(
            .failed("Stopped: 127.0.0.1:8443 is already in use"), tab: .logs, unseen: 0,
            errors: 1, failure: failure, nextPort: 8444, total: 0
        ) {
            CollectorLogsView(
                errors: logs, stderrTail: tail, formatTime: utc, onCopy: { _ in },
                staticLayout: true)
        })

    // The sidebar's Scan and Live sections with the unseen badge, and the toolbar pill.
    func heading(_ title: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: "chevron.down").font(.caption2.weight(.bold))
            Text(title).font(.caption.weight(.semibold))
        }
        .foregroundStyle(.secondary).padding(.top, 8)
    }
    func sidebar(_ state: CollectorStore.State, unseen: Int) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            heading("Scan")
            Label("Claude Code", systemImage: "terminal").lineLimit(1)
            Label("Checked locations", systemImage: "doc.text.magnifyingglass")
            heading("Live")
            CollectorSidebarRow(state: state, unseenFlags: unseen)
                .padding(.vertical, 3).padding(.horizontal, 6)
                .background(Color.accentColor.opacity(0.2), in: RoundedRectangle(cornerRadius: 6))
            Divider().padding(.vertical, 4)
            HStack(spacing: 12) {
                CollectorPill(state: state, unseenFlags: unseen) {}
                CollectorPill(state: .off, unseenFlags: 0) {}
            }
        }
        .padding(12).frame(width: 260, alignment: .topLeading)
    }
    render("sidebar-live.png", sidebar(.listening(hello), unseen: 2), heights: 50...600)
}
