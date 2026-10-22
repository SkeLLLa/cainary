import AppKit
import SwiftUI

/// The one way to open the details and settings windows: promote the activation policy, ask
/// SwiftUI to open the scene, then activate and front the window.
@MainActor
final class WindowOpener {
    static let shared = WindowOpener()

    static let detailsID = "details"

    private var openWindowAction: OpenWindowAction?
    private var openSettingsAction: OpenSettingsAction?
    /// SwiftUI opens the first `Window` scene at launch. Only that first attach, and only within
    /// `launchGrace` of startup, is closed again; every later attach is left alone.
    private(set) var detailsRequested = false
    private var launchSuppressionSpent = false
    private let launchDate = Date()
    private static let launchGrace: TimeInterval = 5

    func install(openWindow: OpenWindowAction, openSettings: OpenSettingsAction) {
        openWindowAction = openWindow
        openSettingsAction = openSettings
    }

    func openDetails() {
        detailsRequested = true
        ActivationPolicy.shared.promote()
        openWindowAction?(id: Self.detailsID)
        front { $0.title == "cAInary" && !($0 is NSPanel) }
    }

    func openSettings() {
        ActivationPolicy.shared.promote()
        if let openSettingsAction {
            openSettingsAction()
        } else {
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        }
        front { $0.identifier?.rawValue.localizedCaseInsensitiveContains("settings") == true }
    }

    /// Called when the details window appears. Closes the window SwiftUI auto-opens at launch;
    /// this runs once, so a window the user opens later is never closed.
    func consumeDetailsRequest(window: NSWindow) {
        guard !launchSuppressionSpent else { return }
        launchSuppressionSpent = true
        if detailsRequested {
            detailsRequested = false
        } else if Date().timeIntervalSince(launchDate) < Self.launchGrace {
            window.close()
        }
    }

    private func front(_ matches: @escaping @MainActor (NSWindow) -> Bool) {
        NSApp.activate(ignoringOtherApps: true)
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(100))
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first { ActivationPolicy.isTracked($0) && matches($0) }?
                .makeKeyAndOrderFront(nil)
        }
    }
}
