import AppKit

/// The app is an accessory (no Dock icon) until a real window (details, settings) is open.
/// Tracks actual `NSWindow`s in an idempotent set: becoming key adds, `willClose` removes.
@MainActor
final class ActivationPolicy: NSObject {
    static let shared = ActivationPolicy()

    private var windows: Set<ObjectIdentifier> = []

    override private init() {
        super.init()
        let center = NotificationCenter.default
        center.addObserver(
            self, selector: #selector(windowDidBecomeKey(_:)),
            name: NSWindow.didBecomeKeyNotification, object: nil)
        center.addObserver(
            self, selector: #selector(windowWillClose(_:)),
            name: NSWindow.willCloseNotification, object: nil)
    }

    /// Titled, non-panel windows only: the menu bar popover and the About panel don't count.
    static func isTracked(_ window: NSWindow) -> Bool {
        window.styleMask.contains(.titled) && !(window is NSPanel)
    }

    /// Switches to `.regular` before a window is opened and activated. If no window shows up,
    /// the policy falls back to `.accessory`.
    func promote() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            demoteIfIdle()
        }
    }

    @objc private func windowDidBecomeKey(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, Self.isTracked(window) else { return }
        windows.insert(ObjectIdentifier(window))
        if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
    }

    @objc private func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        guard windows.remove(ObjectIdentifier(window)) != nil else { return }
        demoteIfIdle()
    }

    private func demoteIfIdle() {
        guard windows.isEmpty, NSApp.activationPolicy() != .accessory else { return }
        NSApp.setActivationPolicy(.accessory)
    }
}
