import Foundation

// The state behind the "HTTPS takeover" buttons. Every action is one
// `cainary-otel-debug` call; nothing is written until the user confirms the previewed change.

@MainActor
final class TrustStore: ObservableObject {
    @Published private(set) var status: TrustStatus?
    @Published private(set) var busy = false
    /// The previewed Claude Code change, shown in the confirmation sheet.
    @Published private(set) var pending: TrustReport?
    /// The last result, one line.
    @Published private(set) var message: String?
    @Published private(set) var failed = false

    private let client: TrustClient

    init(client: TrustClient = TrustClient(helper: CollectorClient.locate())) {
        self.client = client
    }

    var claudeCodeApplied: Bool { status?.claudeCode?.state == "applied" }
    var codexCommand: String? {
        status?.codex?.state == "ready" ? status?.codex?.command : nil
    }
    /// The certificate is made when the takeover first starts.
    var caMissing: Bool { status?.caExists == false }
    var noWriteCommand: String? {
        caMissing ? nil : status?.caPath.map(nodeExtraCACommand(caPath:))
    }

    /// One line for the Claude Code state.
    var claudeCodeLine: String? {
        guard let state = status?.claudeCode?.state else { return nil }
        switch state {
        case "applied": return "Claude Code trusts the collector (restart it to pick this up)."
        case "absent": return "Claude Code doesn't trust the collector."
        case "other-value":
            return "Claude Code already has its own NODE_EXTRA_CA_CERTS; a combined bundle is used."
        case "managed": return "Your organization's managed settings set NODE_EXTRA_CA_CERTS."
        default: return state
        }
    }

    private var refreshSerial = 0

    /// Reads the status. A result that was asked for before a later `refresh` is dropped, so a slow
    /// answer from before a collector restart can not replace a newer one.
    func refresh() async {
        refreshSerial += 1
        let mine = refreshSerial
        let result = await client.status()
        guard mine == refreshSerial, case .status(let s) = result else { return }
        status = s
    }

    /// Previews the change; the sheet shows when there is something to confirm.
    func requestClaudeCodeTrust() async {
        await run {
            let outcome = await self.client.previewClaudeCode()
            if case .report(let r) = outcome, r.action == "preview" {
                self.pending = r
                self.message = nil
                self.failed = false
                return nil
            }
            return outcome
        }
    }

    func confirm() async {
        pending = nil
        await run { await self.client.applyClaudeCode() }
        await refresh()
    }

    func cancel() { pending = nil }

    func undoClaudeCode() async {
        await run { await self.client.undoClaudeCode() }
        await refresh()
    }

    func prepareCodex() async {
        await run { await self.client.prepareCodex() }
        await refresh()
    }

    func removeCodex() async {
        await run { await self.client.removeCodex() }
        await refresh()
    }

    /// Runs a call; a nil outcome means the closure handled the result itself.
    private func run(_ call: @MainActor () async -> TrustOutcome?) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        guard let outcome = await call() else { return }
        switch outcome {
        case .report(let r):
            failed = r.action == "refused"
            message = (r.message ?? r.action).plainText
        case .status(let s):
            status = s
        case .failed(let why):
            failed = true
            message = why
        }
    }
}

/// Endpoint host names a scan found in telemetry findings, for the takeover's host suggestions.
enum TelemetryHosts {
    /// Hosts from `http(s)://` URLs in the evidence of findings that carry a payload (the
    /// in-effect telemetry findings), in report order, without duplicates. Only names the
    /// collector would accept.
    static func suggestions(in report: Report) -> [String] {
        var seen: Set<String> = []
        var out: [String] = []
        for finding in report.entries.flatMap(\.findings) where finding.payload != nil {
            for line in finding.config.evidence {
                for host in hosts(in: line) where seen.insert(host).inserted {
                    out.append(host)
                }
            }
        }
        return out
    }

    private static func hosts(in line: String) -> [String] {
        var found: [String] = []
        var rest = Substring(line)
        while let range = rest.range(of: "http", options: .caseInsensitive) {
            let tail = rest[range.lowerBound...]
            let token = tail.prefix { !$0.isWhitespace && !"\"',".contains($0) }
            if let url = URL(string: String(token)),
                let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
                let host = url.host?.lowercased(), CollectorSettings.validHost(host)
            {
                found.append(host)
            }
            rest = tail.dropFirst(4)
        }
        return found
    }
}
