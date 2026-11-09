import SwiftUI

/// What the guide's buttons do. The caller maps each to a `TakeoverController` or `TrustStore`
/// call; the default does nothing, which is what the snapshots use.
struct TakeoverActions {
    /// Re-read /etc/hosts and look the names up again.
    var refresh: () -> Void = {}
    var addHosts: () -> Void = {}
    var removeHosts: () -> Void = {}
    var enableRedirect: () -> Void = {}
    var disableRedirect: () -> Void = {}
    var requestClaudeTrust: () -> Void = {}
    var undoClaudeTrust: () -> Void = {}
    var prepareCodex: () -> Void = {}
    var removeCodex: () -> Void = {}
    /// Switch back to "Point agents here".
    var switchOff: () -> Void = {}

    static var none: TakeoverActions { TakeoverActions() }
}

/// The numbered takeover steps, one collapsible card each, then the undo. The commands come from
/// the collector's own text (`guide`); the titles, the order of statuses and the one-click buttons
/// are the app's. Twin of linux/crates/cainary-tray/qml/TakeoverGuide.qml. Takes values and
/// closures only.
struct TakeoverGuideView: View {
    let guide: TakeoverGuide
    /// The collector's takeover text as sent, shown whole when it has no numbered step.
    let rawLines: [String]
    let state: TakeoverState
    let trust: TrustSnapshot
    /// Step key → whether the user opened (true) or closed (false) it. A missing key follows the
    /// default: open until the step is done.
    @Binding var openSteps: [String: Bool]
    var actions = TakeoverActions.none
    /// Only "Undo everything", open by default: what is left after the collector stopped or the
    /// takeover was switched off.
    var undoOnly = false

    static let aboutKey = "about"
    static let undoKey = "undo"

    private func key(_ step: GuideStep) -> String {
        step.kind == .other ? "other-\(step.number)" : step.kind.rawValue
    }

    private func isOpen(_ key: String, _ indicator: StepIndicator) -> Bool {
        if let chosen = openSteps[key] { return chosen }
        return indicator.status != .done && indicator.status != .off
    }

    private func toggle(_ key: String, _ open: Bool) {
        openSteps[key] = !open
    }

    private func step(_ kind: StepKind) -> GuideStep? { guide.steps.first { $0.kind == kind } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !undoOnly {
                warning
                if guide.steps.isEmpty {
                    rawBlock
                } else {
                    ForEach(guide.steps, id: \.number) { step in card(step) }
                }
            }
            undo
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: pieces

    private var warning: some View {
        let open = openSteps[Self.aboutKey] ?? false
        let more = Array(guide.warnings.dropFirst()) + guide.footer
        return VStack(alignment: .leading, spacing: 6) {
            Label {
                Text(
                    "While the takeover is on, your organization's collector gets nothing from this Mac."
                )
                .fontWeight(.semibold).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange)
            if !more.isEmpty {
                DisclosureRow(title: "More about what this changes", open: open) {
                    toggle(Self.aboutKey, open)
                }
                if open {
                    ForEach(Array(more.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.orange.opacity(0.4)))
    }

    private var rawBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Instructions from the collector").fontWeight(.semibold)
            SetupCommandBlock(lines: rawLines)
        }
    }

    @ViewBuilder
    private func card(_ step: GuideStep) -> some View {
        let indicator = state.indicator(step.kind, trust: trust)
        let k = key(step)
        let open = isOpen(k, indicator)
        VStack(alignment: .leading, spacing: 8) {
            Button {
                toggle(k, open)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption2).foregroundStyle(.secondary).frame(width: 10)
                    Text("\(step.number). \(title(step))").fontWeight(.semibold)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    StatusChip(indicator: indicator)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open {
                VStack(alignment: .leading, spacing: 8) { body(of: step) }
                    .padding(.leading, 18)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
    }

    private func title(_ step: GuideStep) -> String {
        switch step.kind {
        case .hosts: "Point the host names at this Mac"
        case .redirect: "Redirect port 443 to " + String(state.port)
        case .flush: "Flush the DNS cache"
        case .trust: "Let the agents trust the certificate"
        case .restart: "Restart Claude Code and Codex"
        case .other: step.title
        }
    }

    @ViewBuilder
    private func body(of step: GuideStep) -> some View {
        switch step.kind {
        case .hosts: hostsBody(step)
        case .redirect: redirectBody(step)
        case .flush: flushBody(step)
        case .trust: trustBody(step)
        case .restart: restartBody
        case .other:
            if !step.lines.isEmpty { SetupCommandBlock(lines: step.lines) }
        }
    }

    // MARK: hosts

    private func hostsBody(_ step: GuideStep) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Add these lines to /etc/hosts as root, or let cAInary do it:")
                .fixedSize(horizontal: false, vertical: true)
            SetupCommandBlock(lines: step.lines)
            HStack(spacing: 8) {
                SetupButton(
                    title: state.ownBlock ? "Update /etc/hosts" : "Add to /etc/hosts",
                    enabled: state.canAdd, action: actions.addHosts)
                if state.ownBlock {
                    SetupButton(
                        title: "Remove", enabled: state.canRemove, action: actions.removeHosts)
                }
                SetupButton(title: "Check again", enabled: !state.checking, action: actions.refresh)
                if state.busy == .hosts(.set) || state.busy == .hosts(.clear) {
                    Text("Enter your password in the system dialog.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if !state.canAdd, let reason = state.addReason {
                TakeoverNote(text: reason, tone: .warning)
            }
            if let message = state.hostsMessage {
                TakeoverNote(text: message.text, tone: message.tone)
            }
            ForEach(state.file?.analysis?.conflicts ?? [], id: \.line) { conflict in
                TakeoverNote(
                    text:
                        "/etc/hosts line \(conflict.line) sends \(conflict.host) to \(conflict.address), outside cAInary's block.",
                    tone: .warning)
            }
            ForEach(state.hosts, id: \.self) { host in lookupRow(host) }
            undoLine {
                if state.damagedBlock {
                    TakeoverNote(
                        text:
                            "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts.",
                        tone: .error)
                } else if state.ownBlock {
                    HStack(spacing: 8) {
                        SetupButton(
                            title: "Remove from /etc/hosts", enabled: state.canRemove,
                            action: actions.removeHosts)
                        if let reason = state.removeReason {
                            Text(reason).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } else {
                    Text("Remove the lines you added for these host names from /etc/hosts.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func lookupRow(_ host: String) -> some View {
        let result = state.lookups[host]
        let symbol: String
        let color: Color
        switch result {
        case .here: (symbol, color) = ("checkmark.circle.fill", .green)
        case .elsewhere: (symbol, color) = ("exclamationmark.triangle.fill", .orange)
        case .error: (symbol, color) = ("xmark.octagon.fill", .red)
        case nil: (symbol, color) = ("clock", .secondary)
        }
        return HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol).foregroundStyle(color).font(.caption)
            Text(host).font(.system(.callout, design: .monospaced))
            Text(state.lookupText(host)).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: redirect

    private func redirectBody(_ step: GuideStep) -> some View {
        let working = state.busy == .redirect(.set) || state.busy == .redirect(.clear)
        let off = step.lines.filter { !$0.contains("-F ") }
        return VStack(alignment: .leading, spacing: 8) {
            Text(
                verbatim: "macOS keeps the collector on port " + String(state.port)
                    + ", so port 443 needs a pf redirect. Run these in a terminal, or let cAInary do it. It lasts until you restart this Mac."
            )
            .fixedSize(horizontal: false, vertical: true)
            SetupCommandBlock(lines: off.isEmpty ? step.lines : off)
            HStack(spacing: 8) {
                SetupButton(
                    title: "Enable redirect", enabled: !working && state.busy == nil,
                    action: actions.enableRedirect)
                SetupButton(
                    title: "Disable", enabled: !working && state.busy == nil,
                    action: actions.disableRedirect)
                if working {
                    Text("Enter your password in the system dialog.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if let note = state.redirectStaleNote {
                TakeoverNote(text: note, tone: .warning)
            }
            if let message = state.redirectMessage {
                TakeoverNote(text: message.text, tone: message.tone)
            }
            undoLine {
                Text(
                    "Disable removes only cAInary's redirect. pf stays on until you restart this Mac. By hand:"
                )
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                SetupCommandBlock(lines: guide.undo.lines.filter { $0.contains("pfctl") })
            }
        }
    }

    // MARK: flush

    private func flushBody(_ step: GuideStep) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(
                "Run these so the host names resolve to this Mac right away. The one-click add in step 1 already does it."
            )
            .fixedSize(horizontal: false, vertical: true)
            SetupCommandBlock(lines: step.lines)
            undoLine {
                Text("Nothing to undo; the cache refills by itself.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: trust

    private func trustBody(_ step: GuideStep) -> some View {
        let sha = step.lines.first { $0.hasPrefix("Certificate SHA-256: ") }
            .map { String($0.dropFirst("Certificate SHA-256: ".count)) }
        let codexLine = step.lines.first { $0.hasPrefix("Codex: ") }
            .map { String($0.dropFirst("Codex: ".count)) }
        return VStack(alignment: .leading, spacing: 8) {
            trustRow(
                "Claude Code", status: claudeText, good: trust.claudeApplied,
                button: trust.claudeApplied ? "Undo" : "Let Claude Code trust…",
                action: trust.claudeApplied ? actions.undoClaudeTrust : actions.requestClaudeTrust)
            trustRow(
                "Codex", status: trust.codexReady ? "Bundle ready" : "Not set up",
                good: trust.codexReady,
                button: trust.codexReady ? "Remove" : "Prepare Codex bundle",
                action: trust.codexReady ? actions.removeCodex : actions.prepareCodex)
            if let command = trust.codexCommand {
                Text("Start Codex with:")
                SetupCommandBlock(lines: [command])
            }
            if trust.busy {
                Text("Working…").font(.callout).foregroundStyle(.secondary)
            } else if let message = trust.message {
                TakeoverNote(text: message, tone: trust.failed ? .error : .info)
            }
            if let note = trust.status?.note { TakeoverNote(text: note.plainText, tone: .info) }
            Text("Without changing any settings").fontWeight(.semibold).padding(.top, 4)
            if let command = trust.noWriteCommand {
                Text("Claude Code: start it with").font(.callout)
                SetupCommandBlock(lines: [command])
            } else if trust.caMissing {
                Text("Start the HTTPS takeover once to create the certificate.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            if let codexLine {
                Text("Codex: \(codexLine)").font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let sha {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("Certificate SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(sha).font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }
            undoLine {
                Text("Use Undo or Remove above. Undoing the takeover doesn't touch these.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var claudeText: String {
        guard let claude = trust.status?.claudeCode else { return "Checking…" }
        switch claude.state {
        case "applied": return "Trusted in \(claude.settingsPath ?? "your settings")"
        case "other-value": return "Uses another certificate (\(claude.value ?? ""))"
        case "managed": return "Set by your organization's managed settings"
        default: return "Not set up"
        }
    }

    private func trustRow(
        _ name: String, status: String, good: Bool, button: String, action: @escaping () -> Void
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(name).fontWeight(.semibold).frame(width: 90, alignment: .leading)
            Text(status).font(.callout).foregroundStyle(good ? Color.green : .secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            SetupButton(title: button, enabled: !trust.busy, action: action)
        }
    }

    // MARK: restart

    private var restartBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(
                "Restart your Claude Code and Codex sessions now, and again whenever the collector restarts: every run makes a new certificate. Sessions that are already running keep their old settings."
            )
            .fixedSize(horizontal: false, vertical: true)
            Text("cAInary doesn't restart the collector from here.")
                .font(.callout).foregroundStyle(.secondary)
            undoLine {
                Text("Nothing to undo.").font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: undo

    private var undo: some View {
        let open = openSteps[Self.undoKey] ?? undoOnly
        let hasRedirect =
            step(.redirect) != nil || !guide.undo.lines.isEmpty || state.redirect != .disabled
        let hostsLines = step(.hosts)?.lines ?? []
        let trustNumber = hasRedirect ? 4 : 3
        return VStack(alignment: .leading, spacing: 8) {
            Divider()
            DisclosureRow(title: undoOnly ? "Restore" : "Undo everything", open: open, bold: true) {
                toggle(Self.undoKey, open)
            }
            if open {
                VStack(alignment: .leading, spacing: 8) {
                    Text("1. Switch back to Point agents here, or turn the collector off.")
                    SetupButton(title: "Switch back", enabled: true, action: actions.switchOff)
                    Text(
                        state.ownBlock
                            ? "2. Remove cAInary's lines from /etc/hosts:"
                            : hostsLines.isEmpty
                                ? "2. Remove the lines you added for the host names from /etc/hosts."
                                : "2. Remove these lines from /etc/hosts:")
                    if state.ownBlock {
                        HStack(spacing: 8) {
                            SetupButton(
                                title: "Remove from /etc/hosts", enabled: state.canRemove,
                                action: actions.removeHosts)
                            if state.busy == .hosts(.clear) {
                                Text("Enter your password in the system dialog.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    if state.ownBlock, !hostsLines.isEmpty {
                        Text("or remove these lines yourself:").foregroundStyle(.secondary)
                    }
                    if state.damagedBlock {
                        TakeoverNote(
                            text:
                                "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts.",
                            tone: .error)
                    }
                    if !hostsLines.isEmpty { SetupCommandBlock(lines: hostsLines) }
                    if let message = state.hostsMessage {
                        TakeoverNote(text: message.text, tone: message.tone)
                    }
                    if hasRedirect {
                        Text("3. Remove the redirect:")
                        SetupButton(
                            title: "Disable redirect", enabled: state.busy == nil,
                            action: actions.disableRedirect)
                        if !guide.undo.lines.isEmpty { SetupCommandBlock(lines: guide.undo.lines) }
                    }
                    Text("\(trustNumber). Remove the trust:")
                    HStack(spacing: 8) {
                        SetupButton(
                            title: "Undo Claude Code trust",
                            enabled: !trust.busy && trust.claudeApplied,
                            action: actions.undoClaudeTrust)
                        SetupButton(
                            title: "Remove Codex bundle",
                            enabled: !trust.busy && trust.codexReady, action: actions.removeCodex)
                    }
                    Text(
                        "\(trustNumber + 1). Restart the agents. A process that already loaded the certificate keeps trusting it until it restarts."
                    )
                }
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 18)
            }
        }
    }

    private func undoLine<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            Text("Undo").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            content()
        }
    }
}

// MARK: - Shared pieces

/// One-line status next to a step title: a symbol and words, so colour is never the only cue.
struct StatusChip: View {
    let indicator: StepIndicator

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: symbol).foregroundStyle(color)
            if !indicator.text.isEmpty {
                Text(indicator.text).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var symbol: String {
        switch indicator.status {
        case .done: "checkmark.circle.fill"
        case .todo: "circle"
        case .waiting: "clock"
        case .unknown: "questionmark.circle"
        case .off: "minus.circle"
        }
    }

    private var color: Color {
        switch indicator.status {
        case .done: .green
        case .todo: .orange
        case .waiting, .unknown, .off: .secondary
        }
    }
}

/// A text button that draws the same in a snapshot (no AppKit control).
struct SetupButton: View {
    let title: String
    let enabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title).font(.callout)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain).disabled(!enabled).opacity(enabled ? 1 : 0.5)
    }
}

/// A caption line coloured by tone, with a symbol so the tone isn't colour alone.
struct TakeoverNote: View {
    let text: String
    let tone: TakeoverTone

    var body: some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: symbol)
        }
        .font(.callout).foregroundStyle(color)
    }

    private var symbol: String {
        switch tone {
        case .info: "info.circle"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "xmark.octagon.fill"
        }
    }

    private var color: Color {
        switch tone {
        case .info: .secondary
        case .warning: .orange
        case .error: .red
        }
    }
}

/// A chevron and a title that opens or closes what follows.
struct DisclosureRow: View {
    let title: String
    let open: Bool
    var bold = false
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack(spacing: 6) {
                Image(systemName: open ? "chevron.down" : "chevron.right")
                    .font(.caption2).foregroundStyle(.secondary).frame(width: 10)
                Text(title).fontWeight(bold ? .semibold : .regular)
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Monospaced lines in a box with one Copy button for the whole block.
struct SetupCommandBlock: View {
    let lines: [String]

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(lines.joined(separator: "\n"))
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                copyToPasteboard(lines.joined(separator: "\n"))
            } label: {
                Text("Copy").font(.caption).foregroundStyle(Color.accentColor)
            }
            .buttonStyle(.plain)
        }
        .padding(6)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
    }
}
