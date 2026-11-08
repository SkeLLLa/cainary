import AppKit
import SwiftUI

// "What it sends": what a telemetry export carries, drawn from the core's `payload`.
// Text, labels and the sample come from the core; nothing here is computed from the scan.

extension Sent {
    /// The chip's text. An unknown value shows its slug.
    var chipText: String {
        switch slug {
        case "yes": return "sent"
        case "redacted": return "redacted"
        case "generic": return "generic"
        case "no": return "not sent"
        case "local": return "local only"
        default: return slug
        }
    }

    /// Green when the real value leaves the machine, grey when nothing does.
    var chipColor: Color {
        switch slug {
        case "yes": return .green
        case "redacted", "generic", "local": return .orange
        default: return .secondary
        }
    }
}

/// A state chip: outlined, with the text always present so colour is never the only cue.
struct SentChip: View {
    let sent: Sent

    var body: some View {
        Text(sent.chipText)
            .font(.caption2.weight(.medium))
            .foregroundStyle(sent.chipColor)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .overlay(Capsule().stroke(sent.chipColor.opacity(0.7)))
            .fixedSize()
    }
}

/// Puts `text` on the general pasteboard.
@MainActor
func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

/// A selectable monospaced block with a Copy button.
struct CopyBlock: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Copy") { copyToPasteboard(text) }
                .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                .font(.caption)
        }
        .padding(6)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
    }
}

/// The collapsed "What it sends" section of an expanded finding row. Its open state is
/// `expanded` under `key` ("<findingKey>#payload"), so it survives the row being rebuilt.
struct PayloadView: View {
    let payload: Payload
    let key: String
    @Binding var expanded: Set<String>

    var body: some View {
        DisclosureGroup("What it sends", isExpanded: expandedBinding) {
            content.padding(.vertical, 4)
        }
        .font(.callout)
    }

    private var expandedBinding: Binding<Bool> {
        Binding(
            get: { expanded.contains(key) },
            set: { isOn in
                if isOn {
                    expanded.insert(key)
                } else {
                    expanded.remove(key)
                }
            })
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if !payload.gates.isEmpty { gates }
            if !payload.identity.isEmpty {
                attrs("Identity (on every record)", payload.identity)
            }
            if !payload.resource.isEmpty { attrs("Resource", payload.resource) }
            if !payload.records.isEmpty { records }
            if !payload.sample.isEmpty { sample }
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var header: some View {
        HStack(spacing: 6) {
            Text("\(payload.export.slug) · \(payload.catalog)")
                .foregroundStyle(.secondary)
            if payload.maybe { Tag("may") }
        }
    }

    private var gates: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(payload.gates.indices, id: \.self) { i in
                let gate = payload.gates[i]
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    SentChip(sent: gate.sent)
                    Text(gate.text).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func attrs(_ title: String, _ list: [PayloadAttr]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption.weight(.semibold))
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 8, verticalSpacing: 2) {
                ForEach(list.indices, id: \.self) { i in
                    GridRow {
                        Text(list[i].key).font(.system(.caption, design: .monospaced))
                        HStack(spacing: 6) {
                            Text(list[i].what).fixedSize(horizontal: false, vertical: true)
                            if list[i].maybe { Tag("may") }
                            if let sent = list[i].sent { SentChip(sent: sent) }
                        }
                    }
                }
            }
        }
    }

    private var records: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Records").font(.caption.weight(.semibold))
            ForEach(payload.records.indices, id: \.self) { i in
                record(payload.records[i])
            }
        }
    }

    private func record(_ record: PayloadRecord) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(record.name).font(.system(.caption, design: .monospaced).weight(.medium))
                if record.maybe { Tag("may") }
                if record.observed { Tag("seen") }
                if let unit = record.unit { Tag(unit) }
                if let sent = record.sent { SentChip(sent: sent) }
            }
            Text(record.what).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach(record.attrs.indices, id: \.self) { j in
                let attr = record.attrs[j]
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("\(attr.key) — \(attr.what)").fixedSize(horizontal: false, vertical: true)
                    if attr.maybe { Tag("may") }
                    if let sent = attr.sent { SentChip(sent: sent) }
                }
                .padding(.leading, 10)
            }
        }
    }

    private var sample: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Sample (descriptions in place of values)").font(.caption.weight(.semibold))
            CopyBlock(text: payload.sample.joined(separator: "\n"))
        }
    }
}
