import SwiftUI

// The Details pane for the opt-in OTel debug collector (design §9): status, how to point an agent
// at it, red flags, and what each batch carried, drawn from `summary`. Values are masked by the
// collector; "Raw records" shows its masked `resources`. Nothing is computed here.

/// The pane wired to the store. `CollectorPaneView` takes plain values so it can be snapshot.
struct CollectorView: View {
    @ObservedObject var store: CollectorStore

    var body: some View {
        CollectorPaneView(
            state: store.state, batches: store.batches, alerts: store.alerts,
            batchTotal: store.batchTotal, alertTotal: store.alertTotal,
            lastError: store.lastError, onRetry: { store.retry() },
            onOpenSettings: { WindowOpener.shared.openSettings() })
    }
}

struct CollectorPaneView: View {
    let state: CollectorStore.State
    /// Oldest first, as the store keeps them.
    let batches: [StoredBatch]
    let alerts: [StoredAlert]
    let batchTotal: Int
    let alertTotal: Int
    let lastError: String?
    let onRetry: () -> Void
    let onOpenSettings: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("OTel debug collector").font(.title2.weight(.semibold))
            Text(
                "Receives OpenTelemetry on this Mac only (127.0.0.1 and ::1), so you can see what an AI tool's telemetry export contains. Values are masked, and nothing leaves your Mac."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            statusLine
            if let lastError {
                Text("Last error: \(lastError)").font(.caption).foregroundStyle(.secondary)
            }
            if case .listening(let hello) = state, let setup = hello.setup { setupBlocks(setup) }
            if !alerts.isEmpty { alertList }
            if !batches.isEmpty { batchList }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Status

    @ViewBuilder
    private var statusLine: some View {
        switch state {
        case .off:
            HStack {
                Label("Off", systemImage: "circle.dashed").foregroundStyle(.secondary)
                Button("Open Settings…", action: onOpenSettings)
            }
        case .starting:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Starting…")
            }
        case .listening(let hello):
            Label(listeningText(hello), systemImage: "dot.radiowaves.left.and.right")
                .foregroundStyle(.green)
        case .failed(let reason):
            HStack(spacing: 8) {
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Retry", action: onRetry)
                Button("Settings…", action: onOpenSettings)
            }
        }
    }

    private func listeningText(_ hello: CollectorHello) -> String {
        let batchText = batchTotal == 1 ? "1 batch" : "\(batchTotal) batches"
        let flagText = alertTotal == 1 ? "1 red flag" : "\(alertTotal) red flags"
        return "Listening on \(hello.endpoint ?? "this Mac") · \(batchText) · \(flagText)"
    }

    // MARK: Setup

    private func setupBlocks(_ setup: CollectorHello.Setup) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Point an agent at it").font(.headline)
            if let lines = setup.claudeCode, !lines.isEmpty {
                Text("Claude Code (start it from a shell with these set)").font(.callout)
                CopyBlock(text: lines.joined(separator: "\n"))
            }
            if let lines = setup.codex, !lines.isEmpty {
                Text("Codex (~/.codex/config.toml [otel], or one -c per line)").font(.callout)
                CopyBlock(text: lines.joined(separator: "\n"))
            }
            ForEach((setup.notes ?? []).indices, id: \.self) { i in
                Text(setup.notes?[i] ?? "")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Alerts and batches

    private var alertList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Red flags").font(.headline)
            ForEach(alerts.reversed()) { item in
                let a = item.alert
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "flag.fill").foregroundStyle(.red).accessibilityHidden(true)
                    Text(alertText(a)).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 4)
                    Text(Self.clock(a.ts)).font(.caption).foregroundStyle(.secondary)
                }
                .font(.callout)
            }
        }
    }

    private func alertText(_ a: CollectorAlert) -> String {
        let count = (a.count ?? 1) > 1 ? " ×\(a.count ?? 1)" : ""
        let place = [a.event, a.attribute].compactMap { $0 }.joined(separator: " · ")
        let match = a.match.map { " (\($0))" } ?? ""
        return "\(a.pattern ?? "unknown")\(count): \(place)\(match)"
    }

    private var batchList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Batches").font(.headline)
            ForEach(batches.reversed()) { CollectorBatchRow(item: $0) }
        }
    }

    /// "12:17:49" from an RFC 3339 timestamp, or the text itself when it doesn't parse.
    static func clock(_ ts: String?) -> String {
        guard let ts else { return "" }
        let plain = ISO8601DateFormatter()
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = plain.date(from: ts) ?? fractional.date(from: ts) else { return ts }
        return date.formatted(.dateTime.hour().minute().second())
    }
}

/// One batch, collapsed to a line; opened it lists what it carried.
private struct CollectorBatchRow: View {
    let item: StoredBatch

    private var batch: CollectorBatch { item.batch }

    var body: some View {
        DisclosureGroup {
            details.padding(.vertical, 4)
        } label: {
            HStack(spacing: 6) {
                Text(title).lineLimit(1)
                Spacer(minLength: 4)
                if let n = batch.notInCatalog, n > 0 { WarnTag("\(n) not in catalog") }
                Text(CollectorPaneView.clock(batch.ts)).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    /// "logs · claude-code 2.1.316 · 12 records · 20 KB"
    private var title: String {
        var parts = [batch.signal ?? "?"]
        if let catalog = batch.catalog {
            parts.append(catalog)
        } else if let vendor = batch.vendor {
            parts.append(vendor)
        }
        if let records = batch.records { parts.append(records == 1 ? "1 record" : "\(records) records") }
        if let bytes = batch.bytes {
            parts.append(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file))
        }
        return parts.joined(separator: " · ")
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 8) {
            if batch.scanIncomplete == true {
                Text("The red-flag scan of this batch is incomplete.")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let identity = batch.summary?.identity, !identity.isEmpty {
                line("Identity (on every record)", identity)
            }
            if let resource = batch.summary?.resource, !resource.isEmpty {
                line("Resource", resource)
            }
            ForEach((batch.summary?.records ?? []).indices, id: \.self) { i in
                if let record = batch.summary?.records?[i] { recordView(record) }
            }
            if batch.resourcesOmitted == true {
                Text("Raw records left out: the batch was too large.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                DisclosureGroup("Raw records") { RawRecordsView(line: item.line) }
                    .font(.caption)
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func line(_ title: String, _ keys: [String]) -> some View {
        Text("\(title): \(keys.joined(separator: ", "))")
            .fixedSize(horizontal: false, vertical: true)
    }

    private func recordView(_ record: CollectorBatch.Record) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text("\(record.name ?? "?") ×\(record.count ?? 1)")
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                if let kind = record.kind { Tag(kind) }
                if record.known == false { WarnTag("not in catalog") }
            }
            if let what = record.what {
                Text(what).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ForEach((record.attrs ?? []).indices, id: \.self) { j in
                if let attr = record.attrs?[j] {
                    HStack(spacing: 6) {
                        Text(attr.key ?? "?").font(.system(.caption, design: .monospaced))
                        if let group = attr.group { Tag(group) }
                        if let flag = attr.flag { Tag(flag) }
                        if attr.known == false { WarnTag("not in catalog") }
                    }
                    .padding(.leading, 10)
                }
            }
        }
    }
}

/// The masked `resources`, built only when "Raw records" is open.
private struct RawRecordsView: View {
    let line: Data

    var body: some View {
        let text = CollectorBatch.rawResources(in: line) ?? "(none)"
        ScrollView(.horizontal) {
            Text(text)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .padding(6)
        }
        .frame(maxHeight: 240)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
    }
}

/// An orange tag: something to look at.
private struct WarnTag: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.caption2)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .overlay(Capsule().stroke(Color.orange.opacity(0.7)))
            .foregroundStyle(Color.orange)
            .fixedSize()
    }
}
