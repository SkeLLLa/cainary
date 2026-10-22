import Foundation
import UserNotifications

// Test doubles for the seams in AppState.swift and Preferences.swift.

/// An in-memory `KeyValueStore`: tests never touch the real defaults domain.
final class MemoryStore: KeyValueStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Any] = [:]

    func data(forKey key: String) -> Data? { object(forKey: key) as? Data }
    func string(forKey key: String) -> String? { object(forKey: key) as? String }
    func stringArray(forKey key: String) -> [String]? { object(forKey: key) as? [String] }
    func integer(forKey key: String) -> Int { object(forKey: key) as? Int ?? 0 }
    func bool(forKey key: String) -> Bool { object(forKey: key) as? Bool ?? false }

    func object(forKey key: String) -> Any? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    func set(_ value: Any?, forKey key: String) {
        lock.lock()
        defer { lock.unlock() }
        values[key] = value
    }

    func removeObject(forKey key: String) { set(nil, forKey: key) }
}

/// Records what would have been posted. It can be told to fail entries or to mute everything.
@MainActor
final class RecordingNotifier: NotificationPosting {
    /// Everything "added", in order.
    private(set) var posted: [Planned] = []
    /// How many times `post` was called.
    private(set) var calls = 0
    /// Entry ids or change ids whose `add` fails. Each fails once, then is removed.
    var failIds: Set<String> = []
    /// Treat every change as deliberately muted: handled, nothing recorded.
    var muted = false
    /// Runs inside `post`, after the "authorization" step: lets a test change state mid-post.
    var afterAuthorization: (() -> Void)?
    /// If set, `post` waits here (after the hook) until the test opens it: a slow notifier.
    var gate: Gate?

    func post(_ planned: [Planned], isCurrent: () -> Bool) async -> Set<String> {
        calls += 1
        afterAuthorization?()
        await gate?.wait()
        var handled: Set<String> = []
        guard isCurrent() else { return handled }
        for item in planned {
            guard isCurrent() else { break }
            if muted {
                handled.formUnion(item.changeIds)
                continue
            }
            let hit = failIds.intersection([item.entryId] + item.changeIds)
            if !hit.isEmpty {
                failIds.subtract(hit)
                continue
            }
            posted.append(item)
            handled.formUnion(item.changeIds)
        }
        return handled
    }
}

/// Holds a task until a test opens it.
@MainActor
final class Gate {
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var isOpen = false
    /// Someone is waiting at the gate.
    var hasWaiter: Bool { waiter != nil }

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiter = $0 }
    }

    func open() {
        isOpen = true
        waiter?.resume()
        waiter = nil
    }
}

/// A notification center that records what `UNNotifier` asks of it.
@MainActor
final class FakeCenter: NotificationCentering {
    var status: UNAuthorizationStatus = .authorized
    /// What the permission prompt answers.
    var grants = true
    /// How many times the prompt was shown.
    private(set) var prompts = 0
    /// Requests added, in order.
    private(set) var added: [UNNotificationRequest] = []
    /// Entry ids whose `add` throws.
    var failIds: Set<String> = []
    /// Runs when authorization has been answered, and after each successful add.
    var afterAuthorization: (() -> Void)?
    var afterAdd: (() -> Void)?

    func authorizationStatus() async -> UNAuthorizationStatus {
        if status != .notDetermined { afterAuthorization?() }
        return status
    }

    func requestAuthorization() async -> Bool {
        prompts += 1
        afterAuthorization?()
        return grants
    }

    func add(_ request: UNNotificationRequest) async throws {
        if failIds.contains(request.identifier) { throw CocoaError(.fileWriteUnknown) }
        added.append(request)
        afterAdd?()
    }
}
