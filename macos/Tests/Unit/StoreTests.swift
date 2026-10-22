import AppKit
import Foundation

// ReportStore against the real helper and stubs (macos.md §5b).

private let core = repoRoot().appendingPathComponent("target/debug/cainary")

private func fixture(_ name: String) -> String {
    repoRoot().appendingPathComponent("crates/cainary-core/tests/fixtures/\(name)").path
}

/// Polls until `condition` holds, for at most `seconds`.
@MainActor
private func wait(_ seconds: TimeInterval = 10, _ condition: () -> Bool) async {
    let end = Date().addingTimeInterval(seconds)
    while !condition(), Date() < end { try? await Task.sleep(nanoseconds: 20_000_000) }
}

@MainActor
func storeTests() async {
    // 1. A missing helper is a failed scan, never a green icon.
    do {
        let client = CoreClient(helper: URL(fileURLWithPath: "/nonexistent/cainary"), extraArgs: [])
        let store = ReportStore(client: client, defaults: MemoryStore())
        store.refresh()
        await wait { !store.inFlight }
        check("store: missing helper", store.state == .failed(.helperMissing, last: nil))
        check(
            "store: missing helper icon",
            store.menuState.look == .template && store.menuState.badge == .unknown)
    }

    // 2. Three requests during one scan make exactly one follow-up.
    do {
        let dir = scratchDirectory("store-count")
        let counter = dir.appendingPathComponent("count").path
        let stub = repoRoot().appendingPathComponent("macos/Tests/stubs/counting.sh")
        let report = repoRoot()
            .appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json").path
        let client = CoreClient(helper: stub, extraArgs: [counter, report])
        let store = ReportStore(client: client, defaults: MemoryStore())
        store.refresh()
        store.refresh()
        store.refresh()
        store.refresh()
        await wait { !store.inFlight }
        let runs = (try? String(contentsOfFile: counter, encoding: .utf8))?
            .split(separator: "\n").count
        check("store: coalesced to two scans (\(runs ?? -1))", runs == 2)
    }

    // 3. empty-macos, empty prefs: ready, and the icon is a template.
    do {
        let client = CoreClient(helper: core, extraArgs: ["--fixture", fixture("empty-macos")])
        let store = ReportStore(client: client, defaults: MemoryStore())
        check("store: starts scanning", store.state == .scanning(last: nil))
        store.refresh()
        check("store: scanning once requested", store.inFlight)
        await wait { !store.inFlight }
        if case .ready(let report, _) = store.state {
            check("store: ready", report.schema == 3)
        } else {
            check("store: ready (\(store.state))", false)
        }
        check("store: empty-macos is a dimmed template", store.menuState.look == .templateDimmed)
        check("store: lastFinished set", store.lastFinished != nil)
    }
}

// MARK: - Change tracking (cases 3–9, the A / B / A+B sequence, the flap)

private func realClient(_ fixtureDir: String) -> CoreClient {
    CoreClient(helper: core, extraArgs: ["--fixture", fixtureDir])
}

@MainActor
private func newStore(
    _ client: CoreClient, _ defaults: MemoryStore, _ notifier: RecordingNotifier
) -> ReportStore {
    ReportStore(client: client, defaults: defaults, notifier: notifier, confirmDelay: 0.05)
}

/// One scan, finished.
@MainActor
private func scanOnce(_ store: ReportStore) async {
    store.refresh()
    await wait { !store.inFlight }
}

/// Waits until nothing is scanning, posting or waiting for a confirm.
@MainActor
private func settle(_ store: ReportStore) async {
    try? await Task.sleep(nanoseconds: 300_000_000)
    await wait { !store.inFlight && store.tracker.posting.isEmpty }
}

@MainActor
private func readyReport(_ store: ReportStore) -> Report? {
    if case .ready(let report, _) = store.state { return report }
    return nil
}

/// The ids of the notifying changes of a ready report.
@MainActor
private func notifyingIds(_ report: Report?) -> Set<String> {
    Set((report?.notifyingChanges ?? []).map(\.id))
}

/// Copies fixture directories over each other into a scratch fixture.
private func mergedFixture(_ name: String, _ parts: [String]) -> String {
    let dir = scratchDirectory(name)
    for part in parts {
        let cp = Process()
        cp.executableURL = URL(fileURLWithPath: "/bin/cp")
        cp.arguments = ["-R", fixture(part) + "/.", dir.path]
        try? cp.run()
        cp.waitUntilExit()
    }
    return dir.path
}

@MainActor
func trackingStoreTests() async {
    let empty = fixture("empty-macos")
    let org = fixture("claude-code-org-macos")

    // 3. First scan: saved as the baseline, no --since, nothing posted.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let store = newStore(realClient(empty), defaults, notifier)
        await scanOnce(store)
        let report = readyReport(store)
        check("store 3: ready without a baseline", report != nil && report?.since == nil)
        check("store 3: baseline saved", defaults.data(forKey: PrefKey.baseline) != nil)
        check("store 3: nothing posted", notifier.calls == 0)
        check("store 3: tracking available", !store.trackingUnavailable)
        // The second scan passes the baseline.
        await scanOnce(store)
        check("store 3: second scan has a since", readyReport(store)?.since != nil)
    }

    // 4. A change is held until the confirm scan, then posted once; a rescan posts nothing.
    // 5. Mark as seen empties the changes.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let store = newStore(realClient(org), defaults, notifier)
        await scanOnce(store)
        let ids = notifyingIds(readyReport(store))
        check(
            "store 4: changes found", !(readyReport(store)?.changes ?? []).isEmpty && !ids.isEmpty)
        check("store 4: nothing posted before the confirm scan", notifier.calls == 0)
        await wait { notifier.posted.count == 1 }
        await settle(store)
        check("store 4: one notification", notifier.posted.count == 1)
        check("store 4: for claude", notifier.posted.first?.entryId == "claude")
        check("store 4: title", notifier.posted.first?.title == "Claude · HIGH")
        check(
            "store 4: ids recorded",
            BaselineStore(defaults: defaults).notifiedChangeIds == ids)
        await scanOnce(store)
        await settle(store)
        check("store 4: a rescan posts nothing", notifier.posted.count == 1)

        store.markAsSeen()
        await wait { !store.inFlight }
        await settle(store)
        let after = readyReport(store)
        check(
            "store 5: no changes after Mark as seen",
            after?.since != nil && (after?.changes ?? []).isEmpty)
        check(
            "store 5: notified ids cleared",
            BaselineStore(defaults: defaults).notifiedChangeIds.isEmpty)
        check("store 5: still one notification", notifier.posted.count == 1)
    }

    // 6. A baseline that isn't a report: since.error, a silent rebaseline.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let junk = Data("not json".utf8)
        defaults.set(junk, forKey: PrefKey.baseline)
        let store = newStore(realClient(org), defaults, notifier)
        await scanOnce(store)
        check("store 6: since.error", readyReport(store)?.since?.error != nil)
        check("store 6: rebaselined", defaults.data(forKey: PrefKey.baseline) != junk)
        await scanOnce(store)
        await settle(store)
        check("store 6: next scan is clean", readyReport(store)?.since?.error == nil)
        check("store 6: nothing posted", notifier.calls == 0)
    }

    // 7. Muted: nothing shown, but the ids are recorded so turning it on doesn't replay them.
    do {
        // The preference branch itself is tested in notifierCenterTests (UNNotifier, fake center).
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        notifier.muted = true
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let store = newStore(realClient(org), defaults, notifier)
        await scanOnce(store)
        let ids = notifyingIds(readyReport(store))
        await wait { !BaselineStore(defaults: defaults).notifiedChangeIds.isEmpty }
        await settle(store)
        check("store 7: nothing posted", notifier.posted.isEmpty)
        check("store 7: ids recorded", BaselineStore(defaults: defaults).notifiedChangeIds == ids)
    }

    // 8. A failed post isn't recorded; the next scan posts it.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        notifier.failIds = ["claude"]
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let store = newStore(realClient(org), defaults, notifier)
        await scanOnce(store)
        await wait { notifier.calls >= 1 }
        await settle(store)
        check("store 8: failed post not posted", notifier.posted.isEmpty)
        check(
            "store 8: failed post not recorded",
            BaselineStore(defaults: defaults).notifiedChangeIds.isEmpty)
        await scanOnce(store)
        await wait { notifier.posted.count == 1 }
        await settle(store)
        check("store 8: retried on the next scan", notifier.posted.count == 1)
        check(
            "store 8: recorded after the retry",
            BaselineStore(defaults: defaults).notifiedChangeIds == notifyingIds(readyReport(store)))
    }

    // 9. A baseline too big to keep: replace fails, the old one stays, tracking is unavailable.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let golden = repoRoot()
            .appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json")
        let dir = scratchDirectory("store-big")
        let file = dir.appendingPathComponent("since-error.json")
        if let data = try? Data(contentsOf: golden),
            var json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        {
            json["since"] = ["scannedAt": "2026-10-20T09:00:00Z", "error": "baseline unreadable"]
            try? JSONSerialization.data(withJSONObject: json).write(to: file)
        }
        let old = Data("not json".utf8)
        defaults.set(old, forKey: PrefKey.baseline)
        defaults.set(["old-id"], forKey: PrefKey.notifiedChangeIds)
        let stub = repoRoot().appendingPathComponent("macos/Tests/stubs/bigreport.sh")
        let client = CoreClient(helper: stub, extraArgs: [file.path])
        let store = newStore(client, defaults, notifier)
        await scanOnce(store)
        check("store 9: scan still ready", readyReport(store) != nil)
        check("store 9: old baseline kept", defaults.data(forKey: PrefKey.baseline) == old)
        check(
            "store 9: old ids kept",
            BaselineStore(defaults: defaults).notifiedChangeIds == ["old-id"])
        check("store 9: tracking unavailable", store.trackingUnavailable)
        check("store 9: failed replace keeps the tracker", store.tracker.epoch == 0)
    }

    // A / B / A+B: a change that went away notifies again when it returns.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let a = mergedFixture("fx-a", ["claude-code-org-macos"])
        let b = mergedFixture("fx-b", ["cursor-macos-managed"])
        let ab = mergedFixture("fx-ab", ["claude-code-org-macos", "cursor-macos-managed"])
        // The two descriptors don't merge by copying; write the union.
        let descriptor = """
            {"os": "macos", "user": "alice", "now": "2026-01-01T00:00:00Z",
             "tools": ["claude-code", "cursor"],
             "env": {"PATH": "/usr/bin:/bin", "OTEL_LOG_TOOL_DETAILS": "1"},
             "rootOwned": ["/Library/Application Support/AcmeCollector/bin/collect", "/usr/bin/afplay",
               "/usr/bin/curl", "/Library/Application Support/ClaudeCode/managed-settings.json",
               "/Library/Application Support/ClaudeCode/managed-mcp.json",
               "/opt/AcmeCollector/collect", "~/.cursor/cli-config.json"]}
            """
        try? Data(descriptor.utf8).write(to: URL(fileURLWithPath: ab + "/fixture.json"))
        await scanOnce(newStore(realClient(empty), defaults, notifier))

        let sa = newStore(realClient(a), defaults, notifier)
        await scanOnce(sa)
        await wait { notifier.posted.count == 1 }
        await settle(sa)
        check("store A: claude posted", notifier.posted.map(\.entryId) == ["claude"])

        let sb = newStore(realClient(b), defaults, notifier)
        await scanOnce(sb)
        await wait { notifier.posted.count == 2 }
        await settle(sb)
        check(
            "store B: only B posted next",
            notifier.posted.count == 2 && notifier.posted[1].entryId != "claude")

        let sab = newStore(realClient(ab), defaults, notifier)
        await scanOnce(sab)
        await wait { notifier.posted.count == 3 }
        await settle(sab)
        check(
            "store A+B: A notifies again, B doesn't",
            notifier.posted.count == 3 && notifier.posted[2].entryId == "claude")
    }

    // A flap: seen, gone by the confirm scan, nothing posted.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let fx = mergedFixture("fx-flap", ["claude-code-org-macos"])
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let store = ReportStore(
            client: realClient(fx), defaults: defaults, notifier: notifier, confirmDelay: 1)
        await scanOnce(store)
        check("store flap: change seen", !notifyingIds(readyReport(store)).isEmpty)
        // The files vanish before the confirm scan.
        try? FileManager.default.removeItem(atPath: fx)
        _ = mergedFixture("fx-flap", ["empty-macos"])
        try? await Task.sleep(nanoseconds: 1_600_000_000)
        await wait { !store.inFlight }
        check("store flap: gone at the confirm", notifyingIds(readyReport(store)).isEmpty)
        check("store flap: nothing posted", notifier.calls == 0)
        check("store flap: nothing waiting", store.tracker.nextConfirm == nil)
    }

    await postRaceTests()
    await lifecycleTests()
    await notifierCenterTests()
}

// Copy report goes through the scan gate, and duplicate requests share one run.
@MainActor
func copyReportStoreTests() async {
    let dir = scratchDirectory("store-copy")
    let counter = dir.appendingPathComponent("count").path
    let stub = repoRoot().appendingPathComponent("macos/Tests/stubs/counting.sh")
    let report = repoRoot()
        .appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json").path
    let store = ReportStore(
        client: CoreClient(helper: stub, extraArgs: [counter, report]), defaults: MemoryStore(),
        notifier: RecordingNotifier())
    var texts: [String?] = []
    store.refresh()
    for _ in 0..<3 { store.copyReport { texts.append($0) } }
    check("store copy: waits for the scan", texts.isEmpty && store.inFlight)
    await wait { texts.count == 3 && !store.inFlight }
    let runs = (try? String(contentsOfFile: counter, encoding: .utf8))?
        .split(separator: "\n").count
    check("store copy: one scan and one shared copy run (\(runs ?? -1))", runs == 2)
    check("store copy: every request answered", texts.count == 3 && texts.allSatisfy { $0 != nil })
}

// MARK: - Posts that finish late

/// The count of lines a counting stub wrote.
private func runCount(_ file: String) -> Int {
    (try? String(contentsOfFile: file, encoding: .utf8))?.split(separator: "\n").count ?? 0
}

@MainActor
private func postRaceTests() async {
    let empty = fixture("empty-macos")
    let org = fixture("claude-code-org-macos")

    // A post still in flight when a newer scan no longer sees its changes must not record them:
    // when they return they notify again.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let gate = Gate()
        notifier.gate = gate
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let fx = mergedFixture("fx-late", ["claude-code-org-macos"])
        let store = newStore(realClient(fx), defaults, notifier)
        await scanOnce(store)
        await wait { gate.hasWaiter }
        check(
            "late post: the notifier is suspended mid-post", gate.hasWaiter && notifier.calls == 1)
        _ = mergedFixture("fx-late", ["empty-macos"])
        await scanOnce(store)
        check("late post: a newer scan sees nothing", notifyingIds(readyReport(store)).isEmpty)
        gate.open()
        await wait { notifier.posted.count == 1 }
        await settle(store)
        check(
            "late post: removed ids aren't recorded",
            BaselineStore(defaults: defaults).notifiedChangeIds.isEmpty)
        _ = mergedFixture("fx-late", ["claude-code-org-macos"])
        await scanOnce(store)
        await wait { notifier.posted.count == 2 }
        await settle(store)
        check("late post: the returning change notifies again", notifier.posted.count == 2)
    }

    // A rebaseline (since.error) invalidates posts in flight: they record nothing.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        let gate = Gate()
        notifier.gate = gate
        await scanOnce(newStore(realClient(empty), defaults, notifier))
        let store = newStore(realClient(org), defaults, notifier)
        await scanOnce(store)
        await wait { gate.hasWaiter }
        let junk = Data("not json".utf8)
        defaults.set(junk, forKey: PrefKey.baseline)
        let epoch = store.tracker.epoch
        await scanOnce(store)
        check("rebaseline race: rebaselined", defaults.data(forKey: PrefKey.baseline) != junk)
        check("rebaseline race: new epoch", store.tracker.epoch == epoch + 1)
        gate.open()
        await wait { notifier.posted.count == 1 }
        await settle(store)
        check(
            "rebaseline race: the old post records nothing",
            BaselineStore(defaults: defaults).notifiedChangeIds.isEmpty)
        check("rebaseline race: nothing waiting", store.tracker.posting.isEmpty)
    }
}

// MARK: - start / stop

@MainActor
private func lifecycleTests() async {
    // stop() cancels the pending confirm scan.
    do {
        let defaults = MemoryStore()
        let notifier = RecordingNotifier()
        await scanOnce(newStore(realClient(fixture("empty-macos")), defaults, notifier))
        let store = ReportStore(
            client: realClient(fixture("claude-code-org-macos")), defaults: defaults,
            notifier: notifier, confirmDelay: 0.5)
        await scanOnce(store)
        let finished = store.lastFinished
        store.stop()
        try? await Task.sleep(nanoseconds: 900_000_000)
        check(
            "lifecycle: stop cancels the confirm scan",
            store.lastFinished == finished && !store.inFlight && notifier.calls == 0)
    }

    // Repeated start() leaves one wake observer, and stop() removes it.
    do {
        let dir = scratchDirectory("store-wake")
        let counter = dir.appendingPathComponent("count").path
        let stub = repoRoot().appendingPathComponent("macos/Tests/stubs/counting.sh")
        let report = repoRoot()
            .appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json").path
        let store = ReportStore(
            client: CoreClient(helper: stub, extraArgs: [counter, report]), defaults: MemoryStore(),
            notifier: RecordingNotifier())
        store.start()
        store.start()
        await wait { !store.inFlight }
        try? await Task.sleep(nanoseconds: 700_000_000)
        await wait { !store.inFlight }
        let wake = NSWorkspace.shared.notificationCenter
        let before = runCount(counter)
        wake.post(name: NSWorkspace.didWakeNotification, object: nil)
        try? await Task.sleep(nanoseconds: 200_000_000)
        await wait { !store.inFlight }
        check("lifecycle: one wake observer", runCount(counter) == before + 1)
        store.stop()
        store.stop()
        await wait { !store.inFlight }
        let stopped = runCount(counter)
        wake.post(name: NSWorkspace.didWakeNotification, object: nil)
        try? await Task.sleep(nanoseconds: 600_000_000)
        check("lifecycle: stop removes the observer", runCount(counter) == stopped)
    }
}
