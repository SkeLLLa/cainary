import SwiftUI

/// The collector's Setup tab: how agents reach the collector (point them at it, or the HTTPS
/// takeover), the takeover's host names and port, and the step guide. Takes values and closures;
/// the caller owns the stores. Twin of linux/crates/cainary-tray/qml/CollectorSetup.qml. Every
/// settings edit goes out through `onChange` with the whole new settings.
struct CollectorSetupView: View {
    let settings: CollectorSettings
    let onChange: (CollectorSettings) -> Void
    /// `hello.setup.takeover`; nil until the collector has sent it.
    let takeoverLines: [String]?
    /// The takeover text from the last TLS run, for the undo commands once it has stopped.
    var lastTakeoverLines: [String]?
    /// `hello.setup`, for the lines that point an agent at the collector (plain mode).
    let setup: CollectorHello.Setup?
    /// `hello.endpoint`; nil before the collector listens.
    let endpoint: String?
    let collectorOn: Bool
    /// Hosts found in the latest scan's telemetry findings.
    var suggestions: [String] = []
    let state: TakeoverState
    let trust: TrustSnapshot
    /// The previewed Claude Code trust change, shown in a confirmation sheet.
    var trustPending: TrustReport?
    var onConfirmTrust: () -> Void = {}
    var onCancelTrust: () -> Void = {}
    @Binding var openSteps: [String: Bool]
    var actions = TakeoverActions.none
    /// Snapshots only: ImageRenderer draws no ScrollView, TextField or Toggle.
    var staticLayout = false

    @StateObject private var debounce = Debouncer()

    /// Looks the names up again once they stop changing: typing a host name changes the valid
    /// list many times, and each lookup re-reads /etc/hosts.
    private func scheduleRefresh() {
        debounce.run(after: .milliseconds(600), actions.refresh)
    }

    private func edit(_ change: (inout CollectorSettings) -> Void) {
        var new = settings
        change(&new)
        onChange(new)
    }

    var body: some View {
        if staticLayout {
            content
        } else {
            ScrollView { content }
                .onChange(of: settings.validHosts) { _, _ in scheduleRefresh() }
                .onDisappear { debounce.cancel() }
                .task { actions.refresh() }
                .sheet(
                    isPresented: Binding(
                        get: { trustPending != nil }, set: { if !$0 { onCancelTrust() } })
                ) {
                    if let report = trustPending {
                        TrustConfirmView(
                            report: report, onConfirm: onConfirmTrust, onCancel: onCancelTrust)
                    }
                }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("How agents reach the collector").font(.headline)
            modeToggle
            if let problem = settings.problem {
                TakeoverNote(text: problem.message, tone: .warning)
            }
            if settings.takeover {
                takeover
            } else {
                plain
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: mode

    private var modeToggle: some View {
        VStack(alignment: .leading, spacing: 4) {
            check(
                "HTTPS takeover",
                Binding(get: { settings.takeover }, set: { on in edit { $0.takeover = on } }))
            Text(
                settings.takeover
                    ? "The collector answers for your organization's collector host names, so agents keep their configured endpoint. Needs a few administrator steps."
                    : "Off: agents are pointed at this collector directly. Turn it on when your organization locks the agents' endpoint."
            )
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: plain mode

    private var plain: some View {
        let url = endpoint ?? "http://127.0.0.1:" + String(settings.port)
        return VStack(alignment: .leading, spacing: 10) {
            if leftovers {
                if state.ownBlock {
                    TakeoverNote(
                        text:
                            "/etc/hosts still sends the takeover host names to this Mac. Other programs can't reach those names until cAInary's lines are removed.",
                        tone: .warning)
                }
                undoPanel
            }
            Text("Point agents here").font(.headline)
            Text("Change each agent's OpenTelemetry endpoint to")
            SetupCommandBlock(lines: [url])
            Text(
                "Doesn't work when your organization locks the endpoint; use the HTTPS takeover then. Everything the collector receives stays on this Mac."
            )
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            if let lines = setup?.claudeCode, !lines.isEmpty {
                Text("Claude Code: start it from a shell with these variables set")
                SetupCommandBlock(lines: lines)
            }
            if let lines = setup?.codex, !lines.isEmpty {
                Text(
                    "Codex: add to ~/.codex/config.toml [otel], or pass each line as codex -c '<line>'"
                )
                .fixedSize(horizontal: false, vertical: true)
                SetupCommandBlock(lines: lines)
            }
            if setup == nil {
                Text(
                    collectorOn
                        ? "The lines for Claude Code and Codex appear once the collector is listening."
                        : "The collector is off. Turn it on to get the lines for Claude Code and Codex."
                )
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: takeover

    private var takeover: some View {
        VStack(alignment: .leading, spacing: 10) {
            hostRows
            HStack(spacing: 8) {
                Text("Port").font(.headline)
                numberField
            }
            Text(
                "The collector listens here; step \(redirectStepNumber) redirects port 443 to it. Ports below 1024 need administrator rights on macOS, so 443 itself isn't offered."
            )
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            if let problem = settings.hostsEditProblem {
                TakeoverNote(text: problem.message, tone: .warning)
            }
            if let lines = takeoverLines {
                TakeoverGuideView(
                    guide: TakeoverGuide.parse(lines), rawLines: lines, state: state,
                    trust: trust, openSteps: $openSteps, actions: actions)
            } else {
                Text(
                    collectorOn
                        ? "The steps appear once the collector is listening."
                        : "The collector is off. Turn it on to get the takeover steps."
                )
                .font(.callout).foregroundStyle(.secondary)
                if leftovers { undoPanel }
            }
        }
    }

    /// Something the takeover changed is still in place: the hosts block, a redirect that may be
    /// on, or the trust.
    private var leftovers: Bool {
        state.ownBlock || state.damagedBlock || state.redirect == .enabled || trust.claudeApplied
            || trust.codexReady
    }

    /// "Undo everything" on its own, from the last takeover text when there is one.
    private var undoPanel: some View {
        let lines = lastTakeoverLines ?? []
        return TakeoverGuideView(
            guide: TakeoverGuide.parse(lines), rawLines: lines, state: state, trust: trust,
            openSteps: $openSteps, actions: actions, undoOnly: true)
    }

    private var redirectStepNumber: String {
        let guide = takeoverLines.map(TakeoverGuide.parse)
        return guide?.steps.first { $0.kind == .redirect }.map { String($0.number) } ?? "2"
    }

    private var hostRows: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Host names").font(.headline)
            ForEach(settings.takeoverHosts.indices, id: \.self) { i in
                hostRow(i)
            }
            HStack {
                SetupButton(
                    title: "Add host name",
                    enabled: settings.takeoverHosts.count < CollectorSettings.maxHosts
                ) { edit { $0.takeoverHosts.append("") } }
                Spacer(minLength: 0)
            }
            let open = suggestions.filter { !settings.validHosts.contains($0) }
            if !open.isEmpty {
                Text("Found in your telemetry settings:")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(open, id: \.self) { host in
                    Button {
                        edit {
                            $0.takeoverHosts.removeAll { $0.isEmpty }
                            $0.takeoverHosts.append(host)
                        }
                    } label: {
                        Text("Add \(host)").font(.callout).foregroundStyle(Color.accentColor)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func hostRow(_ i: Int) -> some View {
        let text = Binding(
            get: { i < settings.takeoverHosts.count ? settings.takeoverHosts[i] : "" },
            set: { value in
                edit { if i < $0.takeoverHosts.count { $0.takeoverHosts[i] = value } }
            })
        let host = text.wrappedValue.trimmingCharacters(in: .whitespaces)
        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                field("host.example.com", text)
                Button {
                    edit { if i < $0.takeoverHosts.count { $0.takeoverHosts.remove(at: i) } }
                } label: {
                    Label("Remove", systemImage: "minus.circle").font(.callout)
                }
                .buttonStyle(.plain)
            }
            if !host.isEmpty && !CollectorSettings.validHost(host) {
                Text("Not a host name the collector accepts (no wildcard, no IP address).")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    // MARK: controls

    @ViewBuilder
    private func check(_ title: String, _ value: Binding<Bool>) -> some View {
        if staticLayout {
            Label(title, systemImage: value.wrappedValue ? "checkmark.square.fill" : "square")
                .font(.body.weight(.semibold))
        } else {
            Toggle(title, isOn: value).toggleStyle(.checkbox).fontWeight(.semibold)
        }
    }

    @ViewBuilder
    private func field(_ title: String, _ text: Binding<String>) -> some View {
        if staticLayout {
            Text(text.wrappedValue.isEmpty ? title : text.wrappedValue)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(text.wrappedValue.isEmpty ? .secondary : .primary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 6).padding(.vertical, 3)
                .background(.background, in: RoundedRectangle(cornerRadius: 4))
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(.quaternary))
        } else {
            TextField(title, text: text).font(.system(.body, design: .monospaced))
        }
    }

    @ViewBuilder
    private var numberField: some View {
        if staticLayout {
            Text(String(settings.takeoverPort))
                .font(.system(.body, design: .monospaced))
                .padding(.horizontal, 6).padding(.vertical, 3)
                .frame(minWidth: 70, alignment: .leading)
                .background(.background, in: RoundedRectangle(cornerRadius: 4))
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(.quaternary))
        } else {
            TextField(
                "Port",
                value: Binding(
                    get: { settings.takeoverPort },
                    set: { value in
                        edit {
                            let r = CollectorSettings.takeoverPortRange
                            $0.takeoverPort = min(max(value, r.lowerBound), r.upperBound)
                        }
                    }),
                format: .number.grouping(.never)
            )
            .frame(width: 80)
        }
    }
}

/// Runs the latest action once calls stop for a while. A class: the toolchain has no `@State`.
@MainActor
final class Debouncer: ObservableObject {
    private var task: Task<Void, Never>?

    func run(after delay: Duration, _ action: @escaping () -> Void) {
        task?.cancel()
        task = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            action()
        }
    }

    func cancel() {
        task?.cancel()
    }
}
