import AppKit

/// Right-click (or Control-click) on the menu bar icon shows a menu, as system items like
/// Battery do; a left click still opens the popover. MenuBarExtra has no API for it, so a local
/// event monitor takes the click on the status item's window before MenuBarExtra sees it.
@MainActor
final class StatusItemMenu: NSObject, NSMenuDelegate {
    static let shared = StatusItemMenu()

    private var monitor: Any?
    private var actions = PopoverActions()
    private var canCopy: () -> Bool = { false }

    /// The status item a native menu is attached to while it is open.
    private var attached: NSStatusItem?

    override private init() {}

    /// Idempotent; the latest actions win.
    func install(actions: PopoverActions, canCopy: @escaping () -> Bool) {
        self.actions = actions
        self.canCopy = canCopy
        guard monitor == nil else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) {
            [weak self] event in
            let shown = MainActor.assumeIsolated { self?.showMenu(for: event) ?? false }
            return shown ? nil : event
        }
    }

    /// Shows the menu for a secondary click on the status item; true when it did.
    private func showMenu(for event: NSEvent) -> Bool {
        let secondary = event.type == .rightMouseDown || event.modifierFlags.contains(.control)
        guard secondary, let window = event.window, Self.isStatusItem(window),
            let view = window.contentView
        else { return false }
        let menu = Self.menu(actions: actions, canCopy: canCopy())
        let button = Self.button(in: view)
        // Preferred: attach the menu to the status item for one click, so AppKit places and
        // highlights it exactly like any menu bar menu. Detached again in menuDidClose.
        if let item = Self.statusItem(of: window), item.menu == nil, let button = item.button {
            attached = item
            menu.delegate = self
            item.menu = menu
            button.performClick(nil)
            return true
        }
        // Fallback: pop it up by hand. Top-left of the menu at the bottom-left of the icon, but
        // no higher than the menu bar's bottom edge (a menu overlapping the bar opens scrolled).
        button?.highlight(true)
        let target = button ?? view
        let icon = window.convertToScreen(target.convert(target.bounds, to: nil))
        let barBottom = (window.screen ?? NSScreen.main)?.visibleFrame.maxY ?? icon.minY
        menu.popUp(
            positioning: nil, at: NSPoint(x: icon.minX, y: min(icon.minY, barBottom)),
            in: nil)
        button?.highlight(false)
        return true
    }

    func menuDidClose(_ menu: NSMenu) {
        // Left attached, the menu would replace the popover on the next left click.
        attached?.menu = nil
        attached = nil
    }

    /// The status item behind its window. AppKit doesn't expose it publicly, so check the
    /// private `statusItem` property exists before asking (KVC on a missing key throws).
    private static func statusItem(of window: NSWindow) -> NSStatusItem? {
        guard window.responds(to: NSSelectorFromString("statusItem")) else { return nil }
        return window.value(forKey: "statusItem") as? NSStatusItem
    }

    /// The window AppKit hosts a status item in. Only this app's events reach the monitor, and
    /// the popover's own window is a different class.
    private static func isStatusItem(_ window: NSWindow) -> Bool {
        NSStringFromClass(type(of: window)).contains("StatusBarWindow")
    }

    private static func button(in view: NSView) -> NSButton? {
        if let button = view as? NSButton { return button }
        return view.subviews.lazy.compactMap { button(in: $0) }.first
    }

    /// The popover's "More" menu plus Open details. Internal for tests.
    static func menu(actions: PopoverActions, canCopy: Bool) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.addItem(ActionItem("Open details", actions.openDetails))
        menu.addItem(ActionItem("Copy report", enabled: canCopy, actions.copyReport))
        menu.addItem(.separator())
        menu.addItem(ActionItem("Settings…", actions.openSettings))
        menu.addItem(ActionItem("About cAInary", actions.showAbout))
        let support = NSMenu()
        support.autoenablesItems = false
        for link in SupportLinks.all {
            support.addItem(ActionItem(link.title) { actions.openSupport(link.url) })
        }
        let supportItem = NSMenuItem(title: "Support Ukraine", action: nil, keyEquivalent: "")
        supportItem.submenu = support
        menu.addItem(supportItem)
        menu.addItem(.separator())
        menu.addItem(ActionItem("Quit cAInary", actions.quit))
        return menu
    }
}

/// A menu item that runs a closure.
private final class ActionItem: NSMenuItem {
    private let handler: () -> Void

    init(_ title: String, enabled: Bool = true, _ handler: @escaping () -> Void) {
        self.handler = handler
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        target = self
        isEnabled = enabled
    }

    required init(coder: NSCoder) { fatalError("not used") }

    @objc private func run() { handler() }
}
