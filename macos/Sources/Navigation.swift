import Foundation

/// The collector page's tabs, as the Linux tray lists them.
enum CollectorTab: String, CaseIterable, Hashable, Sendable {
    case feed, flags, rules, logs, setup

    var title: String {
        switch self {
        case .feed: "Feed"
        case .flags: "Red flags"
        case .rules: "Rules"
        case .logs: "Logs"
        case .setup: "Setup"
        }
    }
}

/// What the Details window shows, and which finding rows are open. Popover rows and notification
/// clicks call `select`; there is no `@State` in this toolchain, so the views read it from here.
@MainActor
final class Navigation: ObservableObject {
    @Published var selection: DetailSelection?
    /// Finding `key`s whose rows are expanded, and "<key>#payload" for an open "What it sends".
    @Published var expanded: Set<String> = []
    /// The popover's "What the levels mean" section.
    @Published var legendExpanded = false
    @Published var collectorTab: CollectorTab = .feed
    /// A red flag the Flags tab should scroll to and highlight (its pattern name).
    @Published var flagFocus: String?
    /// A pattern the Feed tab filters on, set when jumping from a flag.
    @Published var feedPattern: String?
    /// The sidebar's Scan and Live sections; both persist.
    @Published var scanCollapsed: Bool {
        didSet { store.set(scanCollapsed, forKey: PrefKey.scanCollapsed) }
    }
    @Published var liveCollapsed: Bool {
        didSet { store.set(liveCollapsed, forKey: PrefKey.liveCollapsed) }
    }

    private let store: any KeyValueStore

    init(store: any KeyValueStore = Prefs.defaults) {
        self.store = store
        scanCollapsed = store.bool(forKey: PrefKey.scanCollapsed)
        liveCollapsed = store.bool(forKey: PrefKey.liveCollapsed)
    }

    func select(_ selection: DetailSelection) {
        self.selection = selection
    }

    /// Open the collector page on a tab.
    func openCollector(_ tab: CollectorTab = .feed) {
        collectorTab = tab
        selection = .collector
    }
}
