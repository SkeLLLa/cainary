import Foundation

/// What the Details window shows, and which finding rows are open. Popover rows and notification
/// clicks call `select`; there is no `@State` in this toolchain, so the views read it from here.
@MainActor
final class Navigation: ObservableObject {
    @Published var selection: DetailSelection?
    /// Finding `key`s whose rows are expanded.
    @Published var expanded: Set<String> = []
    /// The popover's "What the levels mean" section.
    @Published var legendExpanded = false

    func select(_ selection: DetailSelection) {
        self.selection = selection
    }
}
