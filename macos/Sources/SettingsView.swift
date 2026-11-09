import AppKit
import SwiftUI
import UserNotifications

/// The Settings window: a grouped form, 480 pt wide. Preferences live in `Prefs.defaults`;
/// `onRefreshChanged` lets the owner restart the scan timer.
struct SettingsView: View {
    var onRefreshChanged: () -> Void
    @ObservedObject var collector: CollectorStore
    @ObservedObject var navigation: Navigation

    @ObservedObject private var loginItem = LoginItem.shared
    @AppStorage(PrefKey.notifyChanges, store: Prefs.defaults) private var notify = true
    @AppStorage(PrefKey.menuBarIconStyle, store: Prefs.defaults) private var style = IconStyle.color
        .rawValue
    @AppStorage(PrefKey.refreshMinutes, store: Prefs.defaults) private var storedRefresh = 0
    @StateObject private var authorization = NotificationAuthorization()

    init(
        onRefreshChanged: @escaping () -> Void = {}, collector: CollectorStore,
        navigation: Navigation
    ) {
        self.onRefreshChanged = onRefreshChanged
        _collector = ObservedObject(wrappedValue: collector)
        _navigation = ObservedObject(wrappedValue: navigation)
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
            CollectorSettingsSection(collector: collector, navigation: navigation)
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

/// The collector's switches. The red-flag rules and the HTTPS takeover live in the collector
/// window (Rules and Setup tabs); every change here is saved through the store, which restarts
/// a running collector after a short pause.
struct CollectorSettingsSection: View {
    @ObservedObject var collector: CollectorStore
    @ObservedObject var navigation: Navigation

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
            Toggle("Start when cAInary starts", isOn: binding(\.startAtLaunch))
            Text(
                "A local receiver on 127.0.0.1 and ::1 for what an AI tool's telemetry export contains. It runs only while cAInary is open."
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
            Toggle("Notify about red flags", isOn: binding(\.notify))
            HStack {
                Text("Rules, HTTPS takeover and logs are in the collector window.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Collector setup…") {
                    navigation.openCollector(.setup)
                    WindowOpener.shared.openDetails()
                }
            }
        }
    }

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
