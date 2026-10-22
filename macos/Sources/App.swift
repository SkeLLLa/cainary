import AppKit
import SwiftUI
import UserNotifications

/// No `@main`: `main.swift` starts it.
struct CainaryApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var store: ReportStore
    @StateObject private var navigation = Navigation()

    init() {
        let client = CoreClient()
        _store = StateObject(wrappedValue: ReportStore(client: client, defaults: Prefs.defaults))
    }

    var body: some Scene {
        MenuBarExtra {
            PopoverHost(store: store, navigation: navigation)
        } label: {
            LabelHost(store: store, navigation: navigation, delegate: delegate)
        }
        .menuBarExtraStyle(.window)

        Window("cAInary", id: WindowOpener.detailsID) {
            DetailsHost(store: store, navigation: navigation)
        }
        .defaultSize(width: 780, height: 560)
        .commandsRemoved()

        Settings {
            SettingsView(onRefreshChanged: { store.restartTimer() })
        }
    }
}

/// Receives notification clicks and shows banners while the app is frontmost.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    /// Opens Details at an entry; `LabelHost` installs it at launch.
    var openEntry: ((String) -> Void)? {
        didSet { flushPending() }
    }
    /// A click that arrived before `openEntry` was installed (the app was launched by it).
    private var pendingEntry: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // `UNUserNotificationCenter` crashes outside an app bundle.
        guard Bundle.main.bundleIdentifier != nil else { return }
        UNUserNotificationCenter.current().delegate = self
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler handler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        handler(.banner)
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler handler: @escaping () -> Void
    ) {
        let id = response.notification.request.identifier
        handler()
        Task { @MainActor in
            self.pendingEntry = id
            self.flushPending()
        }
    }

    private func flushPending() {
        guard let openEntry, let id = pendingEntry else { return }
        pendingEntry = nil
        openEntry(id)
    }
}

/// The menu bar image. Its `task` runs once at launch: it hands the window actions to
/// `WindowOpener`, installs the right-click menu and starts the scan timer.
private struct LabelHost: View {
    @ObservedObject var store: ReportStore
    @ObservedObject var navigation: Navigation
    let delegate: AppDelegate
    @AppStorage(PrefKey.menuBarIconStyle, store: Prefs.defaults) private var style = IconStyle.color
        .rawValue
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        MenuBarLabel(state: store.menuState, style: IconStyle(rawValue: style) ?? .color)
            .task {
                WindowOpener.shared.install(openWindow: openWindow, openSettings: openSettings)
                delegate.openEntry = { id in
                    navigation.select(.entry(id))
                    WindowOpener.shared.openDetails()
                }
                _ = ActivationPolicy.shared
                StatusItemMenu.shared.install(
                    actions: .live(store: store, navigation: navigation),
                    canCopy: { store.state.lastGood != nil })
                store.start()
            }
    }
}

/// The popover in a `ScrollView` capped at 640 pt, wired to the store.
private struct PopoverHost: View {
    @ObservedObject var store: ReportStore
    @ObservedObject var navigation: Navigation
    @AppStorage(PrefKey.notInstalledExpanded, store: Prefs.defaults) private var notInstalled =
        false

    var body: some View {
        ScrollView {
            PopoverView(
                state: store.state,
                notInstalledExpanded: $notInstalled,
                legendExpanded: $navigation.legendExpanded,
                trackingUnavailable: store.trackingUnavailable,
                actions: actions
            )
            .background(OverlayScrollers())
        }
        .frame(width: 360)
        .frame(maxHeight: 640)
        // MenuBarExtra sizes its window from a zero proposal, where a ScrollView collapses to
        // 0 pt. Ask for the ideal height instead: the content's, capped at 640 by the frame.
        .fixedSize(horizontal: false, vertical: true)
        // The window content is built when the popover opens; it is a cheap, idempotent trigger.
        .onAppear { store.popoverOpened() }
    }

    private var actions: PopoverActions { .live(store: store, navigation: navigation) }
}

extension PopoverActions {
    /// The real actions, shared by the popover and the right-click menu.
    @MainActor
    static func live(store: ReportStore, navigation: Navigation) -> PopoverActions {
        PopoverActions(
            refresh: { store.refresh() },
            openEntry: { id in
                navigation.select(.entry(id))
                WindowOpener.shared.openDetails()
            },
            openDetails: { WindowOpener.shared.openDetails() },
            openChanges: {
                navigation.select(.changes)
                WindowOpener.shared.openDetails()
            },
            markAsSeen: { store.markAsSeen() },
            copyReport: { copyReport(store) },
            openSettings: { WindowOpener.shared.openSettings() },
            showAbout: { About.show() },
            openSupport: { NSWorkspace.shared.open($0) },
            quit: { NSApplication.shared.terminate(nil) })
    }

    /// Asks the store for the plain-text report (serialized with scans) and puts it on the
    /// pasteboard.
    @MainActor
    private static func copyReport(_ store: ReportStore) {
        store.copyReport { text in
            guard let text else { return }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
    }
}

/// Forces overlay scrollers on the enclosing scroll view. With legacy scrollers (a mouse
/// attached, or "Show scroll bars: Always") the scroller takes 15 pt from the 360 pt content as
/// soon as it overflows, so expanding a section shifted everything left.
private struct OverlayScrollers: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { Probe() }
    func updateNSView(_ nsView: NSView, context: Context) { (nsView as? Probe)?.apply() }

    final class Probe: NSView {
        override init(frame: NSRect) {
            super.init(frame: frame)
            // AppKit resets every scroll view to the preferred style when it changes.
            // Selector observers are removed automatically when the view goes away.
            NotificationCenter.default.addObserver(
                self, selector: #selector(preferredStyleChanged),
                name: NSScroller.preferredScrollerStyleDidChangeNotification, object: nil)
        }

        required init?(coder: NSCoder) { fatalError("not used") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            apply()
        }

        @objc private func preferredStyleChanged() {
            // After AppKit's own reset, which runs for the same notification.
            DispatchQueue.main.async { [weak self] in self?.apply() }
        }

        func apply() {
            enclosingScrollView?.scrollerStyle = .overlay
        }
    }
}

/// The Details window, fed the scan state.
private struct DetailsHost: View {
    @ObservedObject var store: ReportStore
    @ObservedObject var navigation: Navigation

    var body: some View {
        DetailView(state: store.state, navigation: navigation, onRetry: { store.refresh() })
    }
}
