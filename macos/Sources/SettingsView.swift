import AppKit
import SwiftUI
import UserNotifications

/// The Settings window: a grouped form, 480 pt wide. Preferences live in `Prefs.defaults`;
/// `onRefreshChanged` lets the owner restart the scan timer.
struct SettingsView: View {
    var onRefreshChanged: () -> Void
    @ObservedObject var collector: CollectorStore
    @ObservedObject var trust: TrustStore
    /// Endpoint host names the last scan found, offered for the takeover.
    var hostSuggestions: [String]

    @ObservedObject private var loginItem = LoginItem.shared
    @AppStorage(PrefKey.notifyChanges, store: Prefs.defaults) private var notify = true
    @AppStorage(PrefKey.menuBarIconStyle, store: Prefs.defaults) private var style = IconStyle.color
        .rawValue
    @AppStorage(PrefKey.refreshMinutes, store: Prefs.defaults) private var storedRefresh = 0
    @StateObject private var authorization = NotificationAuthorization()

    init(
        onRefreshChanged: @escaping () -> Void = {}, collector: CollectorStore, trust: TrustStore,
        hostSuggestions: [String] = []
    ) {
        self.onRefreshChanged = onRefreshChanged
        _collector = ObservedObject(wrappedValue: collector)
        _trust = ObservedObject(wrappedValue: trust)
        self.hostSuggestions = hostSuggestions
    }

    private static let intervals = [5, 10, 30, 60, 1440]

    /// The effective interval, the same clamping as `KeyValueStore.refreshMinutes`.
    private var refresh: Int {
        storedRefresh == 0
            ? Prefs.defaultRefreshMinutes
            : min(max(storedRefresh, Prefs.refreshRange.lowerBound), Prefs.refreshRange.upperBound)
    }

    var body: some View {
        Form {
            Section("Notifications") {
                Toggle("Notify about changes", isOn: $notify)
                if authorization.denied {
                    HStack {
                        Text("Notifications are off for cAInary")
                            .foregroundStyle(.orange)
                        Spacer()
                        Button("Open System Settings") { Self.openNotificationSettings() }
                    }
                }
            }
            Section("Menu bar") {
                Picker("Menu bar icon", selection: $style) {
                    Text("Color").tag(IconStyle.color.rawValue)
                    Text("Monochrome").tag(IconStyle.monochrome.rawValue)
                }
                .pickerStyle(.segmented)
                Text(
                    style == IconStyle.monochrome.rawValue
                        ? "Black or white like other icons; the badge shows only the alert count."
                        : "The bird and badge are tinted by exposure."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
            }
            Section("Refresh") {
                Picker(
                    "Scan every",
                    selection: Binding(
                        get: { refresh },
                        set: {
                            storedRefresh = $0
                            onRefreshChanged()
                        })
                ) {
                    ForEach(intervals, id: \.self) { minutes in
                        Text(Self.title(minutes)).tag(minutes)
                    }
                }
            }
            Section("Startup") {
                Toggle(
                    "Launch at login",
                    isOn: Binding(get: { loginItem.isEnabled }, set: { loginItem.setEnabled($0) })
                )
                .disabled(!loginItem.isAvailable)
                if !loginItem.isAvailable {
                    Text("Open cAInary.app to enable.")
                        .foregroundStyle(.secondary)
                }
                if loginItem.requiresApproval {
                    HStack {
                        Text("Allow cAInary in System Settings → General → Login Items")
                            .foregroundStyle(.orange)
                        Spacer()
                        Button("Open System Settings") { loginItem.openSystemSettings() }
                    }
                }
                if let error = loginItem.error {
                    Text(error).foregroundStyle(.red)
                }
            }
            CollectorSettingsSection(collector: collector)
            TakeoverSettingsSection(
                collector: collector, trust: trust, suggestions: hostSuggestions)
            Section("Support Ukraine") {
                Text(SupportLinks.note)
                    .foregroundStyle(.secondary)
                HStack {
                    ForEach(SupportLinks.all) { link in
                        Link(link.title, destination: link.url)
                    }
                }
            }
            Section("Privacy tools") {
                Text(SupportLinks.protonNote)
                    .foregroundStyle(.secondary)
                Link(SupportLinks.proton.title, destination: SupportLinks.proton.url)
            }
            Section {
                LabeledContent("Version", value: About.versionLine)
                if let buildDate = About.buildDate {
                    LabeledContent("Built", value: buildDate)
                }
                HStack {
                    Link("Source code", destination: About.repository)
                    Spacer()
                    Button("About cAInary…") { About.show() }
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .onAppear(perform: refreshStatus)
        .onReceive(
            NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
        ) { _ in
            refreshStatus()
        }
    }

    private func refreshStatus() {
        loginItem.refresh()
        authorization.refresh()
    }

    private static func openNotificationSettings() {
        if let url = URL(
            string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")
        {
            NSWorkspace.shared.open(url)
        }
    }

    /// A stored non-standard value stays in the list.
    private var intervals: [Int] {
        Self.intervals.contains(refresh)
            ? Self.intervals : (Self.intervals + [refresh]).sorted()
    }

    private static func title(_ minutes: Int) -> String {
        switch minutes {
        case 1440: "Daily"
        case 60: "Hour"
        default: "\(minutes) minutes"
        }
    }
}

/// Whether the user denied notifications in System Settings.
@MainActor
private final class NotificationAuthorization: ObservableObject {
    @Published var denied = false

    func refresh() {
        // `UNUserNotificationCenter` crashes outside an app bundle.
        guard Bundle.main.bundleIdentifier != nil else { return }
        Task {
            let status = await UNUserNotificationCenter.current().notificationSettings()
                .authorizationStatus
            denied = status == .denied
        }
    }
}

/// The "OTel debug collector" section. Every change is saved through the store, which
/// restarts a running collector after a short pause.
private struct CollectorSettingsSection: View {
    @ObservedObject var collector: CollectorStore

    private func binding<T>(_ keyPath: WritableKeyPath<CollectorSettings, T>) -> Binding<T> {
        Binding(
            get: { collector.settings[keyPath: keyPath] },
            set: {
                var new = collector.settings
                new[keyPath: keyPath] = $0
                collector.apply(new)
            })
    }

    var body: some View {
        Section("OTel debug collector") {
            Toggle("Run the collector", isOn: binding(\.enabled))
            Text(
                "A local receiver on 127.0.0.1 and ::1 for what an AI tool's telemetry export contains. Off by default; it runs only while this is on and cAInary is open."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            TextField(
                "Port (1024–65535)",
                value: Binding(
                    get: { collector.settings.port },
                    set: {
                        var new = collector.settings
                        new.port = min(
                            max($0, CollectorSettings.portRange.lowerBound),
                            CollectorSettings.portRange.upperBound)
                        collector.apply(new)
                    }),
                format: .number.grouping(.never))
            Picker("Output", selection: binding(\.logToFile)) {
                Text("Show in UI only").tag(false)
                Text("Also save to:").tag(true)
            }
            .pickerStyle(.radioGroup)
            HStack {
                TextField(
                    "Log file", text: binding(\.logPath),
                    prompt: Text(CollectorSettings.defaultLogPath)
                )
                .disabled(!collector.settings.logToFile)
                Button("Choose…") { chooseLogFile() }
                    .disabled(!collector.settings.logToFile)
            }
            Text("The collector writes this file (private to you), not cAInary.")
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(CollectorPreset.all, id: \.name) { preset in
                Toggle(preset.title, isOn: presetBinding(preset.name))
            }
            Text("Your own red flags")
                .font(.headline)
            ForEach(collector.settings.patterns) { pattern in
                patternRow(pattern.id)
            }
            HStack {
                Button("Add pattern") {
                    var new = collector.settings
                    new.patterns.append(CollectorPattern())
                    collector.apply(new)
                }
                .disabled(collector.settings.patterns.count >= CollectorPattern.maxTotal)
                Spacer()
            }
            if collector.settings.overLimit {
                Text("The collector takes at most 64 red flags, presets included. None are used.")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Text(
                "Names use a–z, 0–9, - and _. Patterns reach the collector over a pipe, not its command line."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            Toggle("Notify about red flags", isOn: binding(\.notify))
        }
    }

    private func presetBinding(_ name: String) -> Binding<Bool> {
        Binding(
            get: { collector.settings.presets.contains(name) },
            set: { on in
                var new = collector.settings
                new.presets.removeAll { $0 == name }
                if on { new.presets.append(name) }
                collector.apply(new)
            })
    }

    private func patternBinding(_ id: UUID) -> Binding<CollectorPattern> {
        Binding(
            get: { collector.settings.patterns.first { $0.id == id } ?? CollectorPattern() },
            set: { updated in
                var new = collector.settings
                guard let i = new.patterns.firstIndex(where: { $0.id == id }) else { return }
                new.patterns[i] = updated
                collector.apply(new)
            })
    }

    private func patternRow(_ id: UUID) -> some View {
        let pattern = patternBinding(id)
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                TextField("Name", text: pattern.name).frame(width: 110)
                TextField("Pattern", text: pattern.pattern)
                    .font(.system(.body, design: .monospaced))
            }
            HStack {
                Toggle("Regex", isOn: pattern.isRegex)
                Toggle("Match case", isOn: pattern.caseSensitive)
                Spacer()
                Button("Remove") {
                    var new = collector.settings
                    new.patterns.removeAll { $0.id == id }
                    collector.apply(new)
                }
            }
            .toggleStyle(.checkbox)
            if let index = collector.settings.patterns.firstIndex(where: { $0.id == id }),
                let problem = collector.settings.problem(at: index)
            {
                Text("\(problem) This pattern is not used.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The path comes from a save panel, starting at `~/Library/Logs/cAInary/otel-debug.jsonl`.
    private func chooseLogFile() {
        let panel = NSSavePanel()
        let start = URL(
            fileURLWithPath: collector.settings.effectiveLogPath ?? CollectorSettings.defaultLogPath
        )
        panel.directoryURL = start.deletingLastPathComponent()
        panel.nameFieldStringValue = start.lastPathComponent
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url {
            var new = collector.settings
            new.logPath = url.path
            new.logToFile = true
            collector.apply(new)
        }
    }
}

/// The "HTTPS takeover" section. The takeover makes the collector answer for
/// the host names you list, so you must also point those names at this Mac yourself; the
/// collector prints the steps once it runs. The trust buttons run one-shot collector commands.
private struct TakeoverSettingsSection: View {
    @ObservedObject var collector: CollectorStore
    @ObservedObject var trust: TrustStore
    let suggestions: [String]

    private func update(_ edit: (inout CollectorSettings) -> Void) {
        var new = collector.settings
        edit(&new)
        collector.apply(new)
    }

    private var settings: CollectorSettings { collector.settings }

    var body: some View {
        Section("HTTPS takeover") {
            Toggle(
                "Use HTTPS takeover",
                isOn: Binding(
                    get: { settings.takeover }, set: { on in update { $0.takeover = on } }))
            Text(
                "For an agent whose managed settings pin its telemetry to an HTTPS host. The collector answers for the names below and forwards nothing: while it is on, your organization's collector receives nothing from this Mac for those names."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            hostRows
            TextField(
                "Port",
                value: Binding(
                    get: { settings.takeoverPort },
                    set: { value in
                        update {
                            let r = CollectorSettings.takeoverPortRange
                            $0.takeoverPort = min(max(value, r.lowerBound), r.upperBound)
                        }
                    }),
                format: .number.grouping(.never))
            if let problem = settings.takeoverProblem {
                Text(problem).font(.caption).foregroundStyle(.orange)
            }
            if collector.failureNote != nil, case .failed = collector.state {
                failureBox
            }
            trustButtons
            if let note = trust.status?.note {
                Text(note.plainText)
                    .font(.callout)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let line = trust.claudeCodeLine {
                Text(line).font(.caption).foregroundStyle(.secondary)
            }
            if let message = trust.message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(trust.failed ? Color.orange : .secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let command = trust.codexCommand {
                CopyBlock(text: command)
            }
            if trust.caMissing {
                Text("Start the HTTPS takeover once to create the certificate.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let command = trust.noWriteCommand {
                Text("Without changing any file, start Claude Code like this:").font(.caption)
                CopyBlock(text: command)
            }
        }
        .task { await trust.refresh() }
        .sheet(
            isPresented: Binding(
                get: { trust.pending != nil }, set: { if !$0 { trust.cancel() } })
        ) {
            if let report = trust.pending {
                TrustConfirmView(
                    report: report, onConfirm: { Task { await trust.confirm() } },
                    onCancel: { trust.cancel() })
            }
        }
    }

    private var hostRows: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Host names").font(.headline)
            ForEach(settings.takeoverHosts.indices, id: \.self) { i in
                HStack {
                    TextField(
                        "host.example.com",
                        text: Binding(
                            get: {
                                i < settings.takeoverHosts.count ? settings.takeoverHosts[i] : ""
                            },
                            set: { value in
                                update {
                                    if i < $0.takeoverHosts.count { $0.takeoverHosts[i] = value }
                                }
                            }))
                    Button("Remove") {
                        update { if i < $0.takeoverHosts.count { $0.takeoverHosts.remove(at: i) } }
                    }
                }
                let host = settings.takeoverHosts[i].trimmingCharacters(in: .whitespaces)
                if !host.isEmpty && !CollectorSettings.validHost(host) {
                    Text("Not a host name the collector accepts (no wildcard, no IP address).")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            HStack {
                Button("Add host name") { update { $0.takeoverHosts.append("") } }
                    .disabled(settings.takeoverHosts.count >= CollectorSettings.maxHosts)
                Spacer()
            }
            let open = suggestions.filter { !settings.validHosts.contains($0) }
            if !open.isEmpty {
                Text("Found in your telemetry settings:").font(.caption).foregroundStyle(.secondary)
                ForEach(open, id: \.self) { host in
                    Button("Add \(host)") {
                        update {
                            $0.takeoverHosts.removeAll { $0.isEmpty }
                            $0.takeoverHosts.append(host)
                        }
                    }
                    .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                }
            }
        }
    }

    /// The collector's note on getting a privileged port, in a selectable box.
    private var failureBox: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("The collector couldn't listen on that port").font(.caption.weight(.semibold))
            Text(collector.failureNote ?? "")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
        }
    }

    private var trustButtons: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button("Let Claude Code trust the collector…") {
                    Task { await trust.requestClaudeCodeTrust() }
                }
                Button("Undo Claude Code trust") { Task { await trust.undoClaudeCode() } }
                    .disabled(!trust.claudeCodeApplied)
            }
            HStack {
                Button("Prepare Codex bundle") { Task { await trust.prepareCodex() } }
                if trust.codexCommand != nil {
                    Button("Remove") { Task { await trust.removeCodex() } }
                }
            }
            if trust.busy { ProgressView().controlSize(.small) }
        }
        .disabled(trust.busy)
    }
}

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
