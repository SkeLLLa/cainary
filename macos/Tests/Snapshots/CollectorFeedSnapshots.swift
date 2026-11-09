import Foundation
import SwiftUI

// The collector Feed and Red flags views on fixture data (example-corp.test names only), with a
// fixed UTC clock so the PNGs don't depend on the machine's time zone.

@MainActor
func collectorFeedSnapshots(out: URL) {
    let utc = { (ts: String) in formatClock(ts, timeZone: TimeZone(identifier: "UTC")!) }
    let allSignals: Set<String> = ["logs", "metrics", "traces"]

    func batch(
        _ seq: Int, _ ts: String, _ signal: String, _ vendor: String, _ bytes: Int,
        records: Int = 4, missing: Int = 0, host: String? = nil, format: String? = nil,
        encoding: String? = nil
    ) -> CollectorBatch {
        CollectorBatch(
            ts: ts, seq: seq, signal: signal, path: "/v1/\(signal)", bytes: bytes, vendor: vendor,
            service: .init(name: vendor, version: "2.1.0"), catalog: "\(vendor) 2.1.0",
            records: records,
            notInCatalog: missing,
            summary: .init(
                identity: ["user.email"], resource: ["host.arch", "os.type"],
                records: [
                    .init(
                        name: "agent.tool_result", kind: "event", count: records, known: true,
                        what: "A tool finished", attrs: [])
                ]),
            host: host, format: format, encoding: encoding)
    }
    func alert(_ seq: Int, _ ts: String, _ pattern: String, _ event: String, count: Int = 1)
        -> CollectorAlert
    {
        CollectorAlert(
            ts: ts, seq: seq, pattern: pattern, preset: pattern != "internal-host",
            signal: "logs", event: event, events: [event], attribute: "tool_input",
            place: "value", count: count, match: "AKI…(20 chars)")
    }

    let batches = [
        batch(1, "2026-01-01T12:00:01Z", "logs", "agent-one", 20431, records: 12, missing: 1),
        batch(
            2, "2026-01-01T12:00:03Z", "metrics", "agent-two", 812, host: "otel.example-corp.test",
            format: "protobuf", encoding: "gzip"),
        batch(3, "2026-01-01T12:00:05Z", "logs", "agent-one", 3120, records: 2),
    ]
    let alerts = [
        alert(1, "2026-01-01T12:00:05Z", "aws-access-key", "agent.tool_result", count: 2),
        alert(2, "2026-01-01T12:00:05Z", "internal-host", "agent.tool_result"),
        alert(3, "2026-01-01T12:00:09Z", "email", "agent.prompt"),
    ]
    let rows = buildFeedRows(batches: batches, alerts: alerts, formatTime: utc)
    let expand = rows.first(where: { $0.batchID == 3 })?.key

    func feed(_ rows: [FeedRow], _ filter: FeedFilter, selected: String?, paused: Bool = false)
        -> some View
    {
        CollectorFeedView(
            rows: rows, filter: .constant(filter), selected: .constant(selected), paused: paused,
            heldCount: paused ? 3 : 0, enabled: true, onTogglePause: {}, onClear: {},
            staticLayout: true
        )
        .frame(width: 640, height: 420)
    }

    func render(_ file: String, _ view: some View, heights: ClosedRange<CGFloat> = 100...3000) {
        let url = out.appendingPathComponent(file)
        checkPNG(file, url, size: writePNG(view, to: url), heights: heights)
    }

    render(
        "collector-feed.png",
        feed(rows, FeedFilter(signals: allSignals), selected: expand, paused: true))
    render("collector-feed-empty.png", feed([], FeedFilter(signals: allSignals), selected: nil))
    render(
        "collector-feed-nomatch.png",
        feed(rows, FeedFilter(signals: allSignals, search: "zzz"), selected: nil))

    let groups = buildFlagGroups(alerts: alerts.reversed(), formatTime: utc)
    func flags(_ groups: [FlagGroup], focus: String?, height: CGFloat = 740) -> some View {
        CollectorFlagsView(
            groups: groups, focus: focus, enabled: true, markSeen: {}, onShowInFeed: { _ in },
            staticLayout: true
        )
        .frame(width: 640, height: height)
    }
    render("collector-flags.png", flags(groups, focus: "aws-access-key"))
    render("collector-flags-empty.png", flags([], focus: nil, height: 240))
}
