import Foundation

// Collector preferences: the start-at-launch migration, problem codes, and Navigation persistence.

@MainActor
func prefsMigrationTests() {
    // Migration: an absent key copies `enabled`.
    let old = MemoryStore()
    old.set(true, forKey: PrefKey.otelCollectorEnabled)
    check("settings: startAtLaunch copies enabled", old.collectorSettings.startAtLaunch)
    let fresh = MemoryStore()
    check("settings: fresh store starts off", !fresh.collectorSettings.startAtLaunch)
    let explicit = MemoryStore()
    explicit.set(true, forKey: PrefKey.otelCollectorEnabled)
    explicit.set(false, forKey: PrefKey.otelCollectorStartAtLaunch)
    check("settings: explicit startAtLaunch wins", !explicit.collectorSettings.startAtLaunch)
    var saved = fresh.collectorSettings
    saved.startAtLaunch = true
    fresh.collectorSettings = saved
    check("settings: startAtLaunch round-trips", fresh.collectorSettings.startAtLaunch)

    check("settings: takeover port default is 8443", CollectorSettings().takeoverPort == 8443)

    // Problems.
    var s = CollectorSettings()
    check("settings: defaults have no problem", s.problem == nil)
    s.port = 80
    check("settings: low port", s.problem?.code == .portRange)
    s = CollectorSettings()
    s.takeover = true
    check("settings: no host", s.problem?.code == .tlsNoHost)
    s.takeoverHosts = ["api.example.com", "*.bad"]
    check("settings: bad host", s.problem?.code == .tlsBadHost)
    s.takeoverHosts = ["a.example.com", "A.example.com"]
    check("settings: duplicate host", s.problem?.code == .tlsBadHost)
    s.takeoverHosts = ["a.example.com"]
    check("settings: good host", s.problem == nil)
    s.takeoverPort = 0
    check("settings: https port range", s.problem?.code == .portRange)
    s = CollectorSettings()
    s.takeover = true
    s.takeoverHosts = (1...9).map { "h\($0).example.com" }
    check("settings: 9 hosts gate", s.hostsEditProblem?.code == .tlsTooManyHosts)
    s.takeoverHosts.removeLast()
    check("settings: 8 hosts pass", s.hostsEditProblem == nil)
    s = CollectorSettings()
    s.patterns = (0..<60).map { CollectorPattern(name: "p\($0)", pattern: "x") }
    check("settings: over the pattern limit", s.problem?.code == .patterns)

    // Navigation.
    let store = MemoryStore()
    let nav = Navigation(store: store)
    check("nav: defaults", nav.collectorTab == .feed && !nav.scanCollapsed && !nav.liveCollapsed)
    nav.scanCollapsed = true
    nav.liveCollapsed = true
    let again = Navigation(store: store)
    check("nav: collapse persists", again.scanCollapsed && again.liveCollapsed)
    check(
        "nav: tabs",
        CollectorTab.allCases.map(\.rawValue) == ["feed", "flags", "rules", "logs", "setup"])
}
