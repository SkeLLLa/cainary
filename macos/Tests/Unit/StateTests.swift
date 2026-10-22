import Foundation

// §5a: MenuState, plus the small shared pieces from AppState.swift and Preferences.swift.

private func golden(_ name: String) -> Report? {
    let url = repoRoot().appendingPathComponent("crates/cainary-core/tests/golden/\(name).json")
    return (try? Data(contentsOf: url)).flatMap { try? Report.decode($0) }
}

private func menu(_ report: Report) -> MenuState {
    MenuState(state: .ready(report, at: Date(timeIntervalSince1970: 0)))
}

@MainActor
func stateTests() async {
    let now = Date(timeIntervalSince1970: 0)

    // MenuState from goldens.
    if let empty = golden("empty-macos") {
        let m = menu(empty)
        check(
            "menu: empty-macos is a dimmed template", m.look == .templateDimmed && m.badge == .none)
        check("menu: empty-macos label", m.label.hasPrefix("cAInary · NOT INSTALLED · "))
    } else {
        check("menu: empty-macos loads", false)
    }
    if let proxy = golden("device-only-proxy") {
        let m = menu(proxy)
        check(
            "menu: device-only-proxy is orange with badge 1",
            m.look == .orange && m.badge == .count(1))
        check(
            "menu: label has the summary", m.label == "cAInary · MEDIUM · \(proxy.status.summary)")
    } else {
        check("menu: device-only-proxy loads", false)
    }
    if let org = golden("claude-code-org-macos") {
        let m = menu(org)
        check("menu: org-macos is red", m.look == .red)
        check(
            "menu: badge counts entries at low+",
            m.badge == .count(org.entries.filter { $0.status.level >= .low }.count))
    }

    // Synthetic levels.
    guard let base = golden("empty-macos") else { return }
    func with(_ level: Level, complete: Bool = true) -> Report {
        var r = base
        r.status.level = level
        r.status.label = level.slug.uppercased()
        r.complete = complete
        return r
    }
    check("menu: ok is green", menu(with(.ok)).look == .green && menu(with(.ok)).badge == .none)
    check("menu: opted-out is blue", menu(with(.optedOut)).look == .blue)
    check("menu: incomplete ok is ?", menu(with(.ok, complete: false)).badge == .unknown)
    check("menu: incomplete ok is a template", menu(with(.ok, complete: false)).look == .template)
    check(
        "menu: incomplete not-installed is ?",
        menu(with(.notInstalled, complete: false)).badge == .unknown)
    check(
        "menu: incomplete low keeps its colour", menu(with(.low, complete: false)).look == .yellow)
    check(
        "menu: unknown level is ?, never green",
        menu(with(.unknown("x"))).badge == .unknown && menu(with(.unknown("x"))).look == .template)
    check(
        "menu: incomplete unknown is ?",
        menu(with(.unknown("x"), complete: false)).badge == .unknown)

    // Badge cap: twelve entries at low+ show 9.
    var crowded = with(.high)
    let entry = Entry(
        id: "e", name: "E", kind: EntryKind(slug: "monitor"), installed: true,
        status: Status(level: .low, label: "LOW", summary: "s"), sends: [], surfaces: [],
        findings: [],
        notes: [])
    crowded.others = Array(repeating: entry, count: 12)
    check("menu: badge capped at 9", menu(crowded).badge == .count(9))
    // A level above low with no entry at low+ still has no count rather than "0".
    var lonely = with(.medium)
    lonely.apps = []
    lonely.others = []
    check("menu: no entries at low+ means no badge", menu(lonely).badge == .none)

    // Failed, scanning.
    let failed = MenuState(state: .failed(.timedOut, last: nil))
    check("menu: failed is a template with ?", failed.look == .template && failed.badge == .unknown)
    check(
        "menu: failed label",
        failed.label == "cAInary · Couldn't scan: \(CoreError.timedOut.reason)")
    let last = LastScan(report: with(.high), at: now)
    check(
        "menu: failed with last is still ?",
        MenuState(state: .failed(.helperMissing, last: last)).badge == .unknown)
    let scanning = MenuState(state: .scanning(last: nil))
    check(
        "menu: first scan is a plain template",
        scanning.look == .template && scanning.badge == .none)
    check(
        "menu: rescanning keeps the last look", MenuState(state: .scanning(last: last)).look == .red
    )

    // ScanState.
    check("state: lastGood of ready", ScanState.ready(base, at: now).lastGood?.at == now)
    check("state: lastGood of scanning(nil)", ScanState.scanning(last: nil).lastGood == nil)
    check("state: lastGood of failed", ScanState.failed(.timedOut, last: last).lastGood == last)

    // Core errors read as one line.
    check("error: exit shows stderr", CoreError.exit(1, "boom").reason.contains("boom"))
    check("error: schema shows n", CoreError.schema(4).reason.contains("4"))

    // Prefs defaults, through the in-memory store.
    let store = MemoryStore()
    check("prefs: notifyChanges defaults on", store.notifyChanges)
    store.notifyChanges = false
    check("prefs: notifyChanges off sticks", !store.notifyChanges)
    check("prefs: icon style defaults to color", store.iconStyle == .color)
    store.iconStyle = .monochrome
    check("prefs: icon style round-trips", store.iconStyle == .monochrome)
    check("prefs: refresh defaults to 10", store.refreshMinutes == 10)
    store.refreshMinutes = 45
    check("prefs: non-standard refresh kept", store.refreshMinutes == 45)
    store.refreshMinutes = 99999
    check("prefs: refresh clamped", store.refreshMinutes == 1440)
    check("prefs: notInstalledExpanded defaults off", !store.notInstalledExpanded)
    check(
        "prefs: keys",
        PrefKey.notifiedChangeIds == "notifiedChangeIds" && PrefKey.baseline == "baseline")

    // RecordingNotifier: records, fails once, mutes, honours isCurrent.
    let rec = RecordingNotifier()
    let a = Planned(entryId: "claude", title: "Claude · HIGH", body: "b", changeIds: ["c1", "c2"])
    let b = Planned(entryId: "openai", title: "t", body: "b", changeIds: ["c3"])
    rec.failIds = ["claude"]
    let first = await rec.post([a, b], isCurrent: { true })
    check("notifier: failed entry not handled", first == ["c3"] && rec.posted == [b])
    let second = await rec.post([a], isCurrent: { true })
    check("notifier: fails once, then posts", second == ["c1", "c2"] && rec.posted == [b, a])
    let stale = await rec.post([b], isCurrent: { false })
    check("notifier: stale handles nothing", stale.isEmpty && rec.posted.count == 2)
    rec.muted = true
    let muted = await rec.post([b], isCurrent: { true })
    check("notifier: muted is handled, not recorded", muted == ["c3"] && rec.posted.count == 2)
}
