import SwiftUI

/// The collector's Feed tab: one row per batch (alerts folded in), newest first, with a filter
/// bar, Pause/Clear and an expandable detail. Takes values and closures; the caller owns the
/// store. Twin of linux/crates/cainary-tray/qml/CollectorFeed.qml.
struct CollectorFeedView: View {
    let rows: [FeedRow]
    @Binding var filter: FeedFilter
    @Binding var selected: String?
    let paused: Bool
    let heldCount: Int
    let enabled: Bool
    let onTogglePause: () -> Void
    let onClear: () -> Void
    /// A batch's records as pretty JSON (values masked by the collector), by batch `seq`.
    var rawRecords: (Int) -> String? = { _ in nil }
    /// Snapshots only: ImageRenderer draws no ScrollView or TextField, so render a static stand-in.
    var staticLayout = false

    static let signals = ["logs", "metrics", "traces"]

    private var visible: [FeedRow] { rows.filter { matches($0, filter) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            controls
            filters
            Divider()
            if visible.isEmpty {
                // Scrolls, like the rows: a fixed-height block under a tall failure banner would
                // overflow the window and push the header off the top.
                if staticLayout { emptyState } else { ScrollView { emptyState } }
            } else {
                if staticLayout {
                    VStack(alignment: .leading, spacing: 0) { rowList }
                } else {
                    ScrollView { LazyVStack(alignment: .leading, spacing: 0) { rowList } }
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var rowList: some View {
        ForEach(visible, id: \.key) { row in
            FeedRowView(
                row: row, open: selected == row.key, raw: { row.batchID.flatMap(rawRecords) }
            ) {
                selected = selected == row.key ? nil : row.key
            }
            Divider()
        }
    }

    private var controls: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                if staticLayout {
                    Text(filter.search.isEmpty ? "Filter" : filter.search)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    TextField("Filter", text: $filter.search).textFieldStyle(.plain)
                }
            }
            .padding(.horizontal, 6).padding(.vertical, 4)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            actionButton(
                paused ? "Resume" : "Pause", paused ? "play.fill" : "pause.fill", onTogglePause)
            if paused {
                Text("\(heldCount) held")
                    .font(.caption.monospacedDigit()).foregroundStyle(.orange)
            }
            actionButton("Clear", "trash", onClear)
        }
    }

    private func actionButton(_ title: String, _ symbol: String, _ action: @escaping () -> Void)
        -> some View
    {
        Button(action: action) {
            Label(title, systemImage: symbol).font(.callout)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
    }

    private var filters: some View {
        HStack(spacing: 6) {
            ForEach(Self.signals, id: \.self) { name in
                chip(name, on: filter.signals.contains(name)) {
                    if filter.signals.contains(name) {
                        filter.signals.remove(name)
                    } else {
                        filter.signals.insert(name)
                    }
                }
            }
            chip("⚑ flagged", on: filter.flaggedOnly) { filter.flaggedOnly.toggle() }
            chip("not in catalog", on: filter.uncatalogedOnly) { filter.uncatalogedOnly.toggle() }
            if !filter.pattern.isEmpty {
                chip("⚑ \(filter.pattern) ✕", on: true) { filter.pattern = "" }
            }
            Spacer(minLength: 0)
        }
    }

    private func chip(_ title: String, on: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.caption)
                .padding(.horizontal, 8).padding(.vertical, 2)
                .background(on ? Color.accentColor.opacity(0.2) : Color.clear, in: Capsule())
                .overlay(Capsule().stroke(on ? Color.accentColor : Color.secondary.opacity(0.4)))
        }
        .buttonStyle(.plain)
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: "tray").font(.largeTitle).foregroundStyle(.secondary)
            Text(rows.isEmpty ? "Nothing received yet" : "No rows match the filter")
                .fontWeight(.semibold)
            Text(
                rows.isEmpty
                    ? (enabled
                        ? "Batches show up here as the agents send telemetry."
                        : "The collector is off.")
                    : "Clear the filter to see all \(rows.count) rows."
            )
            .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity).padding(.top, 40)
    }
}

private struct FeedRowView: View {
    let row: FeedRow
    let open: Bool
    let raw: () -> String?
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button(action: toggle) {
                HStack(spacing: 8) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption2).foregroundStyle(.secondary).frame(width: 10)
                    Text(row.time).font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary).frame(width: 62, alignment: .leading)
                    Text(row.signal).font(.caption).foregroundStyle(.secondary)
                        .frame(width: 52, alignment: .leading)
                    Text(row.source).lineLimit(1).truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    if row.notInCatalog > 0 {
                        Image(systemName: "questionmark.circle").foregroundStyle(.orange)
                            .help("\(row.notInCatalog) not in catalog")
                    }
                    Text(row.size).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        .frame(width: 56, alignment: .trailing)
                    Text(row.flagsCell).font(.caption).foregroundStyle(.red).lineLimit(1)
                        .frame(width: 130, alignment: .leading)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open {
                FeedDetail(row: row, raw: raw).padding(.leading, 18).padding(.bottom, 6)
            }
        }
        .padding(.vertical, 5)
        .background(row.isAlert ? Color.red.opacity(0.05) : Color.clear)
    }
}

/// Whether a row's raw records are shown. A class: the toolchain has no `@State`.
private final class RawToggle: ObservableObject {
    @Published var shown = false
}

private struct FeedDetail: View {
    let row: FeedRow
    let raw: () -> String?
    @StateObject private var rawToggle = RawToggle()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let batch = row.batch {
                field("Signal", batch.signal)
                field("Source", row.source)
                field("Host", batch.host)
                field("Path", batch.path)
                field("Format", batch.format)
                field("Encoding", batch.encoding)
                field("Size", row.size.isEmpty ? nil : row.size)
                field("Records", batch.records.map(String.init))
                field("Not in catalog", row.notInCatalog > 0 ? "\(row.notInCatalog)" : nil)
                field("Identity", batch.summary?.identity?.joined(separator: ", "))
                field("Resource", batch.summary?.resource?.joined(separator: ", "))
                if batch.scanIncomplete == true {
                    Text("The red-flag scan of this batch is incomplete.")
                        .font(.caption).foregroundStyle(.orange)
                }
                ForEach(Array((batch.summary?.records ?? []).enumerated()), id: \.offset) {
                    _, rec in
                    let line = "\(rec.name ?? "?") ×\(rec.count ?? 1)"
                    field("Record", line + (rec.known == false ? " (not in catalog)" : ""))
                }
                rawRecords(batch)
            }
            ForEach(Array(row.flagDetails.enumerated()), id: \.offset) { _, alert in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "flag.fill").foregroundStyle(.red).font(.caption)
                    Text(flagLine(alert)).font(.caption).fixedSize(
                        horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// "Raw records": the batch's resources as the collector sent them, pretty-printed. Values
    /// are masked by the collector. Twin of the Linux feed's "Raw records".
    @ViewBuilder
    private func rawRecords(_ batch: CollectorBatch) -> some View {
        if batch.resourcesOmitted == true {
            Text("Raw records left out: the batch was too large.")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            Button(rawToggle.shown ? "Hide raw records" : "Raw records") {
                rawToggle.shown.toggle()
            }
            .buttonStyle(.link).font(.caption)
            if rawToggle.shown {
                Text(verbatim: raw() ?? "No records in this batch.")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
                Text("Attribute values are masked by the collector.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    private func flagLine(_ alert: CollectorAlert) -> String {
        var parts = [alert.pattern ?? "?"]
        if let event = alert.event ?? alert.events?.first { parts.append(event) }
        if let attribute = alert.attribute { parts.append(attribute) }
        if let place = alert.place { parts.append("in \(place)") }
        if let match = alert.match { parts.append(match) }
        if let count = alert.count, count > 1 { parts.append("×\(count)") }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private func field(_ title: String, _ value: String?) -> some View {
        if let value, !value.isEmpty {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(.caption).foregroundStyle(.secondary)
                    .frame(width: 90, alignment: .trailing)
                Text(value).font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
