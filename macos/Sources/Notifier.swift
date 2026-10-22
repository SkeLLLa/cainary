import Foundation
import UserNotifications

// Turns due changes into notifications (macos.md §2.4): `plan` decides what to
// say, `UNNotifier` posts it.

/// One notification per entry, folding that entry's due changes. Changes with an unknown scope
/// or kind, the `report` scope, and entries missing from the report are skipped.
func plan(changes: [Change], report: Report, ids: Set<String>) -> [Planned] {
    var order: [String] = []
    var grouped: [String: [Change]] = [:]
    for change in changes
    where change.notifies && change.scope.slug != "report" && ids.contains(change.id) {
        guard let entry = change.entry, report.entries.contains(where: { $0.id == entry })
        else { continue }
        if grouped[entry] == nil { order.append(entry) }
        grouped[entry, default: []].append(change)
    }
    return order.compactMap { id in
        guard let entry = report.entries.first(where: { $0.id == id }),
            let list = grouped[id], let first = list.first
        else { return nil }
        let more = list.count > 1 ? " (+\(list.count - 1) more)" : ""
        return Planned(
            entryId: id, title: "\(entry.name) · \(entry.status.label)",
            body: first.text + more, changeIds: list.map(\.id))
    }
}

/// The slice of `UNUserNotificationCenter` that `UNNotifier` uses, so tests can fake it.
@MainActor
protocol NotificationCentering: AnyObject {
    func authorizationStatus() async -> UNAuthorizationStatus
    func requestAuthorization() async -> Bool
    func add(_ request: UNNotificationRequest) async throws
}

/// The real center.
@MainActor
final class SystemNotificationCenter: NotificationCentering {
    func authorizationStatus() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    func requestAuthorization() async -> Bool {
        (try? await UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound])) ?? false
    }

    func add(_ request: UNNotificationRequest) async throws {
        try await UNUserNotificationCenter.current().add(request)
    }
}

/// The real `NotificationPosting`. Outside an app bundle `UNUserNotificationCenter` crashes, so
/// without a bundle id (and no injected `center`) everything is treated as muted.
@MainActor
final class UNNotifier: NotificationPosting {
    private let defaults: KeyValueStore
    private let center: NotificationCentering?

    init(defaults: KeyValueStore, center: NotificationCentering? = nil) {
        self.defaults = defaults
        self.center =
            center ?? (Bundle.main.bundleIdentifier != nil ? SystemNotificationCenter() : nil)
    }

    func post(_ planned: [Planned], isCurrent: () -> Bool) async -> Set<String> {
        let all = Set(planned.flatMap(\.changeIds))
        guard let center, defaults.notifyChanges else { return all }
        // Authorization is asked on the first post, not at launch.
        let allowed = await authorized(center)
        guard isCurrent() else { return [] }
        guard allowed else { return all }
        var handled: Set<String> = []
        for item in planned {
            guard isCurrent() else { break }
            // Muting may have happened during the prompt or an earlier add: the rest count as
            // handled, so turning notifications back on doesn't replay them.
            guard defaults.notifyChanges else {
                handled.formUnion(item.changeIds)
                continue
            }
            let content = UNMutableNotificationContent()
            content.title = item.title
            content.body = item.body
            content.threadIdentifier = item.entryId
            let request = UNNotificationRequest(
                identifier: item.entryId, content: content, trigger: nil)
            do {
                try await center.add(request)
                handled.formUnion(item.changeIds)
            } catch {
                // Not handled: the ids stay due and the next scan tries again.
            }
        }
        return handled
    }

    /// Whether banners are allowed, asking once if the user hasn't decided.
    private func authorized(_ center: NotificationCentering) async -> Bool {
        switch await center.authorizationStatus() {
        case .notDetermined: return await center.requestAuthorization()
        case .denied: return false
        default: return true
        }
    }
}
