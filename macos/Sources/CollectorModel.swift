import Foundation

// Pure collector view logic: feed rows, filters, flag groups and formatting. No SwiftUI.
// Swift twin of linux/crates/tray-model/src/collector.rs (build_feed_rows, matches, format_size,
// format_local_clock, build_flag_groups). Keep the two in step: change one, change the other.

/// A compact flag label on a feed row. Details stay on `FeedRow.flagDetails`.
struct FeedFlag: Equatable, Sendable {
    var pattern: String
    var count: Int
}

/// One stable, presentation-ready row in the collector feed.
struct FeedRow: Equatable, Sendable {
    var key: String
    var timestamp: String
    var time: String
    var size: String
    var source: String
    var signal: String
    var records: Int
    var flags: [FeedFlag]
    var flagDetails: [CollectorAlert]
    var notInCatalog: Int
    var isAlert: Bool
    /// Lowercased text the search box matches against.
    var haystack: String
    var batchID: Int?
    var alert: CollectorAlert?
    var batch: CollectorBatch?

    /// The flags cell: "⚑ first" plus " +N" for the other patterns. Empty when unflagged.
    var flagsCell: String {
        guard let first = flags.first else { return "" }
        let extra = flags.count - 1
        return "⚑ \(first.pattern)" + (extra > 0 ? " +\(extra)" : "")
    }
}

/// Red Flags tab groups, in order of the most recent alert for each pattern.
struct FlagGroup: Equatable, Sendable {
    var pattern: String
    var preset: Bool
    var hits: Int
    var total: Int
    var last: String
    var lastTime: String
    var events: [String]
    var attributes: [String]
    var signals: [String]
    var matched: String
}

/// The feed's user-controlled filters. `signals` holds the enabled signal names.
struct FeedFilter: Equatable, Sendable {
    var signals: Set<String> = []
    var flaggedOnly = false
    var uncatalogedOnly = false
    var search = ""
    var pattern = ""
}

/// The alert's event, else its first event, else empty (Rust `AlertView.event`).
private func eventName(_ alert: CollectorAlert) -> String {
    alert.event ?? alert.events?.first ?? ""
}

private func alertKey(_ alert: CollectorAlert) -> String {
    let seq = alert.seq ?? 0
    if seq != 0 { return "alert:\(seq)" }
    return "alert:\(alert.ts ?? ""):\(alert.signal ?? ""):\(alert.pattern ?? ""):"
        + "\(eventName(alert)):\(alert.attribute ?? "")"
}

private func batchSource(_ batch: CollectorBatch) -> String {
    if let catalog = batch.catalog, !catalog.isEmpty { return catalog }
    let source = [batch.vendor ?? "", serviceText(batch)].filter { !$0.isEmpty }
        .joined(separator: " ")
    return source.isEmpty ? "?" : source
}

/// Vendor and service as one string, with the version when present (Rust `BatchView.service`).
private func serviceText(_ batch: CollectorBatch) -> String {
    let name = batch.service?.name ?? ""
    guard let version = batch.service?.version, !version.isEmpty else { return name }
    return "\(name) \(version)"
}

private func rowHaystack(_ batch: CollectorBatch?, _ alerts: [CollectorAlert]) -> String {
    var parts: [String] = []
    if let batch {
        parts += [
            batch.signal ?? "", batch.catalog ?? "", batch.vendor ?? "", serviceText(batch),
            batch.path ?? "",
        ]
        for record in batch.summary?.records ?? [] {
            parts += [record.name ?? "", record.what ?? ""]
            for attr in record.attrs ?? [] {
                parts += [attr.key ?? "", attr.group ?? "", attr.flag ?? ""]
            }
        }
    }
    for alert in alerts {
        parts += [alert.pattern ?? "", eventName(alert), alert.attribute ?? ""]
    }
    return parts.filter { !$0.isEmpty }.joined(separator: "\n").lowercased()
}

private func summarizeFlags(_ alerts: [CollectorAlert]) -> [FeedFlag] {
    var flags: [FeedFlag] = []
    var index: [String: Int] = [:]
    for alert in alerts {
        let pattern = alert.pattern ?? ""
        let count = max(alert.count ?? 0, 1)
        if let at = index[pattern] {
            flags[at].count += count
        } else {
            index[pattern] = flags.count
            flags.append(FeedFlag(pattern: pattern, count: count))
        }
    }
    return flags
}

/// Seconds since the epoch and nanoseconds for an RFC 3339 timestamp, or nil if unreadable.
private func parseTimestamp(_ text: String) -> (seconds: Int, nanos: Int)? {
    let b = Array(text.utf8)
    func digits(_ start: Int, _ length: Int) -> Int? {
        guard start >= 0, start + length <= b.count else { return nil }
        var value = 0
        for byte in b[start..<(start + length)] {
            guard byte >= 48, byte <= 57 else { return nil }
            value = value * 10 + Int(byte - 48)
        }
        return value
    }
    guard b.count >= 20, b[4] == 45, b[7] == 45, b[10] == 84 || b[10] == 116, b[13] == 58,
        b[16] == 58,
        let year = digits(0, 4), let month = digits(5, 2), let day = digits(8, 2),
        let hour = digits(11, 2), let minute = digits(14, 2), let second = digits(17, 2)
    else { return nil }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    let monthDays: Int
    switch month {
    case 2: monthDays = leap ? 29 : 28
    case 4, 6, 9, 11: monthDays = 30
    default: monthDays = 31
    }
    guard (1...12).contains(month), day >= 1, day <= monthDays, hour <= 23, minute <= 59,
        second <= 59
    else { return nil }

    var index = 19
    var nanos = 0
    if index < b.count, b[index] == 46 {
        index += 1
        let start = index
        while index < b.count, b[index] >= 48, b[index] <= 57 { index += 1 }
        if index == start { return nil }
        let precision = min(index - start, 9)
        guard let fraction = digits(start, precision) else { return nil }
        var scale = 1
        for _ in 0..<(9 - precision) { scale *= 10 }
        nanos = fraction * scale
    }

    var offset = 0
    guard index < b.count else { return nil }
    switch b[index] {
    case 90, 122:
        guard index + 1 == b.count else { return nil }
    case 43, 45:
        guard index + 6 == b.count, b[index + 3] == 58,
            let hours = digits(index + 1, 2), let minutes = digits(index + 4, 2),
            hours <= 23, minutes <= 59
        else { return nil }
        let magnitude = hours * 3600 + minutes * 60
        offset = b[index] == 43 ? magnitude : -magnitude
    default: return nil
    }

    // days_from_civil
    let y = month <= 2 ? year - 1 : year
    let era = (y >= 0 ? y : y - 399) / 400
    let yoe = y - era * 400
    let adjusted = month + (month > 2 ? -3 : 9)
    let doy = (153 * adjusted + 2) / 5 + day - 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    let days = era * 146_097 + doe - 719_468
    return (days * 86400 + hour * 3600 + minute * 60 + second - offset, nanos)
}

private func timestampNanos(_ text: String?) -> Int? {
    guard let text, let parsed = parseTimestamp(text) else { return nil }
    return parsed.seconds * 1_000_000_000 + parsed.nanos
}

/// The batch an alert belongs to: the nearest (latest) same-signal batch that is 0…5 s older.
private func linkedBatchIndex(_ alert: CollectorAlert, _ batches: [CollectorBatch]) -> Int? {
    let window = 5_000_000_000
    guard let alertTime = timestampNanos(alert.ts) else { return nil }
    var nearest: (time: Int, index: Int)?
    for (index, batch) in batches.enumerated() {
        guard (batch.signal ?? "") == (alert.signal ?? ""),
            let batchTime = timestampNanos(batch.ts)
        else { continue }
        let elapsed = alertTime - batchTime
        let closer = nearest.map { batchTime > $0.time } ?? true
        if (0...window).contains(elapsed), closer { nearest = (batchTime, index) }
    }
    return nearest?.index
}

/// Builds the feed: one row per batch, alerts folded into the batch they belong to, the rest as
/// rows of their own, newest first. `batches` and `alerts` are in any order; each alert links by
/// timestamp. `formatTime` renders the timestamp cell.
func buildFeedRows(
    batches: [CollectorBatch], alerts: [CollectorAlert],
    formatTime: (String) -> String = { formatClock($0) }
) -> [FeedRow] {
    var rows: [FeedRow] = batches.map { batch in
        FeedRow(
            key: "batch:\(batch.seq ?? 0)", timestamp: batch.ts ?? "",
            time: formatTime(batch.ts ?? ""), size: formatSize(batch.bytes ?? 0),
            source: batchSource(batch), signal: batch.signal ?? "", records: batch.records ?? 0,
            flags: [], flagDetails: [], notInCatalog: batch.notInCatalog ?? 0, isAlert: false,
            haystack: "", batchID: batch.seq ?? 0, alert: nil, batch: batch)
    }
    var batchRows: [Int: Int] = [:]
    for (index, row) in rows.enumerated() {
        if let id = row.batchID { batchRows[id] = index }
    }

    for alert in alerts {
        if let at = linkedBatchIndex(alert, batches),
            let rowIndex = batchRows[batches[at].seq ?? 0]
        {
            rows[rowIndex].flagDetails.append(alert)
            continue
        }
        let event = eventName(alert)
        let place = alert.place ?? ""
        rows.append(
            FeedRow(
                key: alertKey(alert), timestamp: alert.ts ?? "", time: formatTime(alert.ts ?? ""),
                size: "", source: !event.isEmpty ? event : (!place.isEmpty ? place : "?"),
                signal: alert.signal ?? "", records: 0, flags: [], flagDetails: [alert],
                notInCatalog: 0, isAlert: true, haystack: "", batchID: nil, alert: alert,
                batch: nil))
    }

    for index in rows.indices {
        rows[index].flags = summarizeFlags(rows[index].flagDetails)
        rows[index].haystack = rowHaystack(rows[index].batch, rows[index].flagDetails)
    }
    // Newest first; unreadable timestamps compare as text. The index keeps ties in input order.
    let order = rows.indices.sorted { left, right in
        let l = rows[left].timestamp
        let r = rows[right].timestamp
        if let ln = timestampNanos(l), let rn = timestampNanos(r), ln != rn { return ln > rn }
        if timestampNanos(l) == nil || timestampNanos(r) == nil, l != r { return l > r }
        return left < right
    }
    return order.map { rows[$0] }
}

/// Whether a precomputed row passes the feed's filters.
func matches(_ row: FeedRow, _ filter: FeedFilter) -> Bool {
    if !filter.signals.contains(row.signal) { return false }
    if filter.flaggedOnly, row.flags.isEmpty { return false }
    if !filter.pattern.isEmpty, !row.flags.contains(where: { $0.pattern == filter.pattern }) {
        return false
    }
    if filter.uncatalogedOnly, row.notInCatalog == 0 { return false }
    let search = filter.search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return search.isEmpty || row.haystack.contains(search)
}

/// "" for 0, "N B" under 1 KiB, "N KB" (rounded) under 1 MiB, else "x.y MB".
func formatSize(_ bytes: Int) -> String {
    if bytes <= 0 { return "" }
    if bytes < 1024 { return "\(bytes) B" }
    if bytes < 1024 * 1024 { return "\(Int((Double(bytes) / 1024).rounded())) KB" }
    return String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
}

/// HH:MM:SS in `timeZone` (local by default). Unreadable timestamps come back unchanged.
func formatClock(_ timestamp: String, timeZone: TimeZone = .current) -> String {
    guard let (seconds, _) = parseTimestamp(timestamp) else { return timestamp }
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = timeZone
    let parts = calendar.dateComponents(
        [.hour, .minute, .second], from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    func two(_ n: Int?) -> String {
        let s = String(n ?? 0)
        return s.count < 2 ? "0" + s : s
    }
    return "\(two(parts.hour)):\(two(parts.minute)):\(two(parts.second))"
}

/// One group per pattern, in the order each pattern first appears in `alerts`: pass them newest
/// first and the groups run by most recent alert. `hits` counts alerts, `total` sums max(count, 1).
func buildFlagGroups(
    alerts: [CollectorAlert], formatTime: (String) -> String = { formatClock($0) }
) -> [FlagGroup] {
    var groups: [FlagGroup] = []
    var index: [String: Int] = [:]
    func addUnique(_ values: inout [String], _ value: String) {
        if !value.isEmpty, !values.contains(value) { values.append(value) }
    }
    for alert in alerts {
        let pattern = alert.pattern ?? ""
        let at: Int
        if let known = index[pattern] {
            at = known
        } else {
            at = groups.count
            index[pattern] = at
            groups.append(
                FlagGroup(
                    pattern: pattern, preset: alert.preset ?? false, hits: 0, total: 0,
                    last: alert.ts ?? "", lastTime: formatTime(alert.ts ?? ""), events: [],
                    attributes: [], signals: [], matched: alert.match ?? ""))
        }
        groups[at].hits += 1
        groups[at].total += max(alert.count ?? 0, 1)
        addUnique(&groups[at].events, eventName(alert))
        addUnique(&groups[at].attributes, alert.attribute ?? "")
        addUnique(&groups[at].signals, alert.signal ?? "")
    }
    return groups
}
