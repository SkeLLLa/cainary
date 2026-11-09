import SwiftUI

/// The sheet before the one file edit: exactly what changes, where the backup goes, and what it
/// costs. Nothing is written until Confirm.
struct TrustConfirmView: View {
    let report: TrustReport
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Let Claude Code trust the collector?").font(.headline)
            if let message = report.message {
                Text(message).fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 4) {
                if let path = report.settingsPath { Text("File: \(path)") }
                Text(changeLine)
                Text(backupLine)
            }
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
            Text("Restart Claude Code afterwards: sessions already running keep the old setting.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Your org's collector receives nothing while the takeover is active.")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                Button("Confirm", action: onConfirm).keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 460)
    }

    var changeLine: String {
        let key = report.key ?? "NODE_EXTRA_CA_CERTS"
        return "Change: env.\(key): \(report.from ?? "(not set)") → \(report.to ?? "?")"
    }

    var backupLine: String {
        report.backupPath.map { "Backup: \($0)" } ?? "Backup: none (the file doesn't exist yet)"
    }
}
