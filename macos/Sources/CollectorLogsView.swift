import SwiftUI

/// The collector's Logs tab: what it reported itself (newest first) and the tail of its stderr.
/// Twin of linux/crates/cainary-tray/qml/CollectorLogs.qml.
struct CollectorLogsView: View {
    let errors: [CollectorError]
    let stderrTail: [String]
    /// Formats a timestamp (`formatClock` in the app, a UTC one in snapshots).
    let formatTime: (String) -> String
    /// Puts text on the pasteboard.
    let onCopy: (String) -> Void
    /// Snapshots only: ImageRenderer draws no ScrollView.
    var staticLayout = false

    private var empty: Bool { errors.isEmpty && stderrTail.isEmpty }

    var body: some View {
        Group {
            if staticLayout { content } else { ScrollView { content } }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 12) {
            if empty { emptyState }
            if !errors.isEmpty { messages }
            if !stderrTail.isEmpty { stderr }
        }
        .padding(10)
        .frame(
            maxWidth: .infinity, maxHeight: staticLayout ? .infinity : nil, alignment: .topLeading)
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: "text.alignleft").font(.largeTitle).foregroundStyle(.secondary)
            Text("No logs").fontWeight(.semibold)
            Text("The collector hasn't reported anything.")
                .font(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity).padding(.top, 40)
    }

    private var messages: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Collector messages").font(.headline)
            ForEach(Array(errors.enumerated()), id: \.offset) { _, error in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(error.ts.map(formatTime) ?? "")
                        .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    if let code = error.code {
                        Text(code).font(.system(.caption, design: .monospaced))
                            .padding(.horizontal, 4)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
                    }
                    Text(line(error)).font(.callout).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            copyButton("Copy messages", errors.map(copyLine).joined(separator: "\n"))
        }
    }

    private var stderr: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Collector listen error").font(.headline)
            Text(stderrTail.joined(separator: "\n"))
                .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            copyButton("Copy error details", stderrTail.joined(separator: "\n"))
        }
    }

    private func copyButton(_ title: String, _ text: String) -> some View {
        Button {
            onCopy(text)
        } label: {
            Label(title, systemImage: "doc.on.doc").font(.callout)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain).padding(.top, 2)
    }

    /// The message, falling back to what the line said about the request. Control characters shown
    /// as escapes.
    private func line(_ error: CollectorError) -> String {
        var text = (error.message ?? error.source ?? "error").plainText
        if let source = error.source, error.message != nil { text = "\(source): \(text)" }
        if let count = error.count, count > 1 { text += " (×\(count))" }
        return text
    }

    private func copyLine(_ error: CollectorError) -> String {
        let time = error.ts.map(formatTime).map { $0 + " " } ?? ""
        let code = error.code.map { "[\($0)] " } ?? ""
        return time + code + line(error)
    }
}
