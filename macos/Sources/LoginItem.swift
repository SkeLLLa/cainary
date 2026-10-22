import Foundation
import ServiceManagement

/// "Launch at login" through `SMAppService`, which only works for a bundled app that was opened
/// as such. A symlink launch (`Bundle.main.bundleIdentifier == nil`) can't register.
@MainActor
final class LoginItem: ObservableObject {
    static let shared = LoginItem()

    @Published private(set) var isEnabled = false
    @Published private(set) var error: String?
    @Published private(set) var requiresApproval = false

    var isAvailable: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    init() {
        refresh()
    }

    func refresh() {
        let status = isAvailable ? SMAppService.mainApp.status : .notRegistered
        // A registered item waiting for approval counts as On, so turning it Off unregisters.
        isEnabled = status == .enabled || status == .requiresApproval
        requiresApproval = status == .requiresApproval
    }

    func openSystemSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    func setEnabled(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            error = nil
        } catch {
            self.error = "Failed to update login item: \(error.localizedDescription)"
        }
        refresh()
    }
}
