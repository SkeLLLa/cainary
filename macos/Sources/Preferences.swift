import Foundation

// The app's own preferences: the only thing cAInary writes outside the repo (besides the login
// item). Everything reads and writes through `KeyValueStore`, so tests use `MemoryStore`.

/// The slice of `UserDefaults` the app uses. `UserDefaults` conforms; tests use `MemoryStore`.
protocol KeyValueStore: AnyObject, Sendable {
    func data(forKey key: String) -> Data?
    func string(forKey key: String) -> String?
    func stringArray(forKey key: String) -> [String]?
    func object(forKey key: String) -> Any?
    func integer(forKey key: String) -> Int
    func bool(forKey key: String) -> Bool
    func set(_ value: Any?, forKey key: String)
    func removeObject(forKey key: String)
}

extension UserDefaults: KeyValueStore {}

/// The preference keys. `paranoia` from the old app is left alone and never read.
enum PrefKey {
    /// The last report the user acknowledged: its JSON bytes.
    static let baseline = "baseline"
    /// Change ids already notified.
    static let notifiedChangeIds = "notifiedChangeIds"
    static let notifyChanges = "notifyChanges"
    static let menuBarIconStyle = "menuBarIconStyle"
    static let refreshMinutes = "refreshMinutes"
    static let notInstalledExpanded = "notInstalledExpanded"
}

enum Prefs {
    static let domain = "ua.SkeLLLa.cAInary"
    static let defaultRefreshMinutes = 10
    /// Daily, in minutes, is the longest interval offered.
    static let refreshRange = 1...1440

    /// `.standard` is the app's own domain when it runs from its bundle; asking for a suite with
    /// the bundle's own identifier makes NSUserDefaults warn.
    static var defaults: UserDefaults {
        if Bundle.main.bundleIdentifier == domain { return .standard }
        return UserDefaults(suiteName: domain) ?? .standard
    }
}

/// Typed access with the defaults in one place.
extension KeyValueStore {
    /// "Notify about changes", on unless the user turned it off.
    var notifyChanges: Bool {
        get {
            object(forKey: PrefKey.notifyChanges) == nil
                ? true : bool(forKey: PrefKey.notifyChanges)
        }
        set { set(newValue, forKey: PrefKey.notifyChanges) }
    }

    var iconStyle: IconStyle {
        get {
            string(forKey: PrefKey.menuBarIconStyle).flatMap(IconStyle.init(rawValue:)) ?? .color
        }
        set { set(newValue.rawValue, forKey: PrefKey.menuBarIconStyle) }
    }

    /// Minutes between background scans. A stored value outside 1...1440 is clamped; 0 or none
    /// means the default.
    var refreshMinutes: Int {
        get {
            let stored = integer(forKey: PrefKey.refreshMinutes)
            guard stored != 0 else { return Prefs.defaultRefreshMinutes }
            return min(max(stored, Prefs.refreshRange.lowerBound), Prefs.refreshRange.upperBound)
        }
        set { set(newValue, forKey: PrefKey.refreshMinutes) }
    }

    var notInstalledExpanded: Bool {
        get { bool(forKey: PrefKey.notInstalledExpanded) }
        set { set(newValue, forKey: PrefKey.notInstalledExpanded) }
    }
}
