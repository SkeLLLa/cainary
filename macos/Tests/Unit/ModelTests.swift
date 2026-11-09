import Foundation

// Ports of the tray-model feed tests (linux/crates/tray-model/src/collector.rs, `feed_tests`).

private func batch(_ id: Int, _ ts: String, _ signal: String) -> CollectorBatch {
    var b = CollectorBatch()
    b.seq = id
    b.ts = ts
    b.signal = signal
    b.path = "/v1/logs"
    b.vendor = "Acme"
    b.service = .init(name: "worker", version: "1.2")
    b.bytes = 2048
    b.records = 3
    b.notInCatalog = 1
    b.summary = .init(
        records: [
            .init(
                name: "claude-code.tool_result", kind: "event", count: 1, known: true,
                what: "A tool result",
                attrs: [.init(key: "user.email", group: "identity", flag: nil, known: true)])
        ])
    return b
}

private func alert(
    _ seq: Int, _ ts: String, _ signal: String, _ pattern: String, _ count: Int
) -> CollectorAlert {
    var a = CollectorAlert()
    a.seq = seq
    a.ts = ts
    a.pattern = pattern
    a.preset = true
    a.signal = signal
    a.event = "claude-code.tool_result"
    a.attribute = "tool_input"
    a.place = "record"
    a.count = count
    a.match = "secret"
    return a
}

private let utc = TimeZone(identifier: "UTC")!

@MainActor
func modelTests() {
    let fixed: (String) -> String = { _ in "12:00:00" }

    // Linking: the nearest same-signal batch, 5 s inclusive.
    var rows = buildFeedRows(
        batches: [
            batch(1, "2026-11-07T11:59:57Z", "logs"), batch(2, "2026-11-07T11:59:58Z", "logs"),
        ],
        alerts: [alert(7, "2026-11-07T12:00:03Z", "logs", "aws-access-key", 2)],
        formatTime: fixed)
    let linked = rows.first { $0.key == "batch:2" }
    check("model: alert at +5 s links the nearest batch", linked?.flagDetails.count == 1)
    check(
        "model: linked flags carry the count",
        linked?.flags == [FeedFlag(pattern: "aws-access-key", count: 2)])
    check("model: farther batch stays unflagged", rows.first { $0.key == "batch:1" }?.flags == [])
    check("model: linked alert makes no own row", rows.count == 2)
    check("model: flags cell", linked?.flagsCell == "⚑ aws-access-key")

    // 0 s edge links, and an alert before its batch does not.
    rows = buildFeedRows(
        batches: [batch(1, "2026-11-07T12:00:00Z", "logs")],
        alerts: [alert(7, "2026-11-07T12:00:00Z", "logs", "p", 1)], formatTime: fixed)
    check("model: 0 s edge links", rows.count == 1 && rows[0].flags.count == 1)
    rows = buildFeedRows(
        batches: [batch(1, "2026-11-07T12:00:01Z", "logs")],
        alerts: [alert(7, "2026-11-07T12:00:00Z", "logs", "p", 1)], formatTime: fixed)
    check("model: alert before the batch does not link", rows.count == 2)

    // Outside the window: 6 s.
    let outside = [alert(7, "2026-11-07T12:00:00Z", "logs", "aws-access-key", 1)]
    rows = buildFeedRows(
        batches: [batch(1, "2026-11-07T11:59:54Z", "logs")], alerts: outside, formatTime: fixed)
    let orphan = rows.first { $0.isAlert }
    check("model: outside 5 s makes two rows", rows.count == 2)
    check("model: unlinked key", orphan?.key == "alert:7")
    check("model: unlinked row carries its flag", orphan?.flags.count == 1)
    check("model: unlinked details", orphan?.flagDetails == outside)

    // Orphan: other signal.
    rows = buildFeedRows(
        batches: [batch(1, "2026-11-07T11:59:59Z", "metrics")],
        alerts: [alert(9, "2026-11-07T12:00:00Z", "logs", "private-value", 1)], formatTime: fixed)
    let lone = rows.first { $0.isAlert }
    check("model: other-signal alert is its own row", lone?.key == "alert:9")
    check("model: orphan source is the event", lone?.source == "claude-code.tool_result")
    check("model: orphan has no batch", lone?.batchID == nil)

    // Orphan source falls back to where, then "?".
    var bare = alert(10, "2026-11-07T12:00:00Z", "logs", "p", 1)
    bare.event = nil
    check(
        "model: orphan source falls back to place",
        buildFeedRows(batches: [], alerts: [bare], formatTime: fixed)[0].source == "record")
    bare.place = nil
    check(
        "model: orphan source falls back to ?",
        buildFeedRows(batches: [], alerts: [bare], formatTime: fixed)[0].source == "?")
    bare.seq = 0
    check(
        "model: seq-less alert key",
        buildFeedRows(batches: [], alerts: [bare], formatTime: fixed)[0].key
            == "alert:2026-11-07T12:00:00Z:logs:p::tool_input")

    // Newest first.
    rows = buildFeedRows(
        batches: [
            batch(1, "2026-11-07T12:00:00Z", "logs"), batch(2, "2026-11-07T12:05:00Z", "metrics"),
        ],
        alerts: [alert(8, "2026-11-07T12:03:00Z", "traces", "private-value", 1)],
        formatTime: { _ in "" })
    check("model: newest first", rows.map(\.key) == ["batch:2", "alert:8", "batch:1"])

    // Clock, size and source.
    let first = buildFeedRows(
        batches: [batch(1, "2026-11-07T12:34:56Z", "logs")], alerts: [],
        formatTime: { formatClock($0, timeZone: TimeZone(secondsFromGMT: 7200)!) })[0]
    check("model: clock preformatted", first.time == "14:34:56")
    check("model: size preformatted", first.size == "2 KB")
    check("model: vendor and service source", first.source == "Acme worker 1.2")
    var cataloged = batch(1, "2026-11-07T12:34:56Z", "logs")
    cataloged.catalog = "Claude Code"
    check(
        "model: catalog source wins",
        buildFeedRows(batches: [cataloged], alerts: [], formatTime: fixed)[0].source
            == "Claude Code")
    check(
        "model: empty source is ?",
        buildFeedRows(batches: [CollectorBatch()], alerts: [], formatTime: fixed)[0].source == "?")
    check("model: formatSize 0", formatSize(0) == "")
    check("model: formatSize 1", formatSize(1) == "1 B")
    check("model: formatSize 1023", formatSize(1023) == "1023 B")
    check("model: formatSize 1024", formatSize(1024) == "1 KB")
    check("model: formatSize rounds KB", formatSize(1536) == "2 KB")
    check("model: formatSize just under 1 MiB", formatSize(1_048_575) == "1024 KB")
    check("model: formatSize 1 MiB", formatSize(1_048_576) == "1.0 MB")
    check("model: formatSize 2.5 MiB", formatSize(2_621_440) == "2.5 MB")
    check("model: formatClock unreadable", formatClock("unreadable", timeZone: utc) == "unreadable")
    check(
        "model: formatClock UTC", formatClock("2026-11-07T12:34:56Z", timeZone: utc) == "12:34:56")
    check(
        "model: formatClock honours the offset in the stamp",
        formatClock("2026-11-07T12:34:56+02:00", timeZone: utc) == "10:34:56")
    check(
        "model: formatClock fraction",
        formatClock("2026-11-07T12:34:56.789Z", timeZone: utc) == "12:34:56")
    check(
        "model: formatClock wraps the day",
        formatClock("2026-11-07T23:30:00Z", timeZone: TimeZone(secondsFromGMT: 3600)!) == "00:30:00"
    )

    // Filters.
    let row = buildFeedRows(
        batches: [batch(1, "2026-11-07T12:00:00Z", "logs")],
        alerts: [alert(7, "2026-11-07T12:00:01Z", "logs", "aws-access-key", 2)],
        formatTime: { _ in "" }
    ).first { $0.key == "batch:1" }!
    var filter = FeedFilter(
        signals: ["logs"], flaggedOnly: true, uncatalogedOnly: true, search: "  USER.EMAIL  ",
        pattern: "aws-access-key")
    check("model: filter all conditions", matches(row, filter))
    filter.signals = []
    check("model: filter signal off", !matches(row, filter))
    filter.signals = ["logs"]
    filter.flaggedOnly = false
    filter.pattern = ""
    filter.uncatalogedOnly = false
    filter.search = "missing"
    check("model: filter search miss", !matches(row, filter))
    filter.search = ""
    filter.pattern = "another-pattern"
    check("model: filter other pattern", !matches(row, filter))
    filter.pattern = ""
    filter.uncatalogedOnly = true
    var all = row
    all.notInCatalog = 0
    check("model: filter uncataloged only", !matches(all, filter) && matches(row, filter))
    filter.uncatalogedOnly = false
    filter.flaggedOnly = true
    var plain = row
    plain.flags = []
    check("model: filter flagged only", !matches(plain, filter) && matches(row, filter))
    check("model: empty filter signals match nothing", !matches(row, FeedFilter()))
    check(
        "model: search is case-insensitive over alerts",
        matches(row, FeedFilter(signals: ["logs"], search: "TOOL_INPUT")))

    // Flag groups.
    let alerts = [
        alert(3, "2026-11-07T12:02:00Z", "logs", "aws-access-key", 2),
        alert(2, "2026-11-07T12:01:00Z", "metrics", "aws-access-key", 1),
        alert(1, "2026-11-07T12:00:00Z", "traces", "private-value", 3),
    ]
    let groups = buildFlagGroups(alerts: alerts, formatTime: fixed)
    check(
        "model: groups one per pattern",
        groups.map(\.pattern) == ["aws-access-key", "private-value"])
    check("model: group hits", groups[0].hits == 2)
    check("model: group total", groups[0].total == 3)
    check("model: group last", groups[0].last == "2026-11-07T12:02:00Z")
    check("model: group last time", groups[0].lastTime == "12:00:00")
    check("model: group signals", groups[0].signals == ["logs", "metrics"])
    check(
        "model: group events and attributes",
        groups[0].events == ["claude-code.tool_result"]
            && groups[0].attributes == ["tool_input"])
    check("model: group preset and matched", groups[0].preset && groups[0].matched == "secret")
    check("model: second group total", groups[1].hits == 1 && groups[1].total == 3)
    var zero = alert(4, "2026-11-07T12:03:00Z", "logs", "z", 0)
    zero.count = nil
    check("model: missing count counts as one", buildFlagGroups(alerts: [zero])[0].total == 1)
}
