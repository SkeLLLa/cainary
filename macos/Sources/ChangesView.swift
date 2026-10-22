import SwiftUI

// What changed since the baseline (§2.2 item 2, §2.3 Changes pane). The popover shows a few rows
// and a Mark as seen button; Details shows every change with its `from → to`.

/// Helpers shared by the popover section and the Details pane.
enum ChangeText {
    /// `+` added, `−` removed, `↑` raised, `↓` lowered, `~` changed, `•` anything else.
    static func marker(_ kind: ChangeKind) -> String {
        switch kind.slug {
        case "added": return "+"
        case "removed": return "−"
        case "raised": return "↑"
        case "lowered": return "↓"
        case "changed": return "~"
        default: return "•"
        }
    }

    /// The entry's name by id; "Scan" for report-scope changes (and ids the report lacks).
    static func subject(_ change: Change, in report: Report) -> String {
        if change.scope.slug == "report" { return "Scan" }
        guard let id = change.entry else { return "Scan" }
        return report.entries.first { $0.id == id }?.name ?? id
    }

    /// "16:40" for a core timestamp, or the raw string when it doesn't parse.
    static func time(_ scannedAt: String) -> String {
        let plain = ISO8601DateFormatter()
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = plain.date(from: scannedAt) ?? fractional.date(from: scannedAt) else {
            return scannedAt
        }
        return date.formatted(.dateTime.hour().minute())
    }

    /// "Changes since 16:40"
    static func title(_ report: Report) -> String {
        guard let since = report.since else { return "Changes" }
        return "Changes since \(time(since.scannedAt))"
    }
}

/// One change: marker, entry name and text. `detail` adds the `from → to` line (Details pane).
struct ChangeRow: View {
    let change: Change
    let report: Report
    var detail = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(ChangeText.marker(change.kind))
                .font(.callout.weight(.semibold).monospaced())
                .frame(width: 14)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(ChangeText.subject(change, in: report))
                    .font(detail ? .callout.weight(.medium) : .caption.weight(.medium))
                Text(change.text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(detail ? nil : 2)
                    .fixedSize(horizontal: false, vertical: true)
                if detail, let from = change.from, let to = change.to {
                    Text("\(from) → \(to)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The popover's Changes section: up to 5 rows, "+N more" and Mark as seen.
struct ChangesView: View {
    static let limit = 5

    let report: Report
    var openChanges: () -> Void = {}
    var markAsSeen: () -> Void = {}

    var body: some View {
        let changes = report.changes ?? []
        VStack(alignment: .leading, spacing: 4) {
            Text(ChangeText.title(report))
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .accessibilityAddTraits(.isHeader)
            ForEach(Array(changes.prefix(Self.limit)), id: \.id) { change in
                ChangeRow(change: change, report: report)
            }
            HStack {
                if changes.count > Self.limit {
                    Button("+\(changes.count - Self.limit) more", action: openChanges)
                        .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                        .font(.caption)
                }
                Spacer()
                // Plain + accent: ImageRenderer draws bordered buttons as placeholders.
                Button("Mark as seen", action: markAsSeen)
                    .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                    .font(.caption.weight(.medium))
            }
        }
    }
}
