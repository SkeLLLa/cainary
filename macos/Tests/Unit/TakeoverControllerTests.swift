import Foundation

// Tests for TakeoverController.swift on fakes: stale results are dropped (generation), edits run
// one at a time, an edit is followed by a re-read, and the state value gates the buttons. Nothing
// here runs osascript, sudo or pfctl or touches /etc/hosts.

private final class Calls: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    private var lastOps: [String: String] = [:]

    func bump(_ name: String, note: String = "") -> Int {
        lock.lock()
        defer { lock.unlock() }
        counts[name, default: 0] += 1
        lastOps[name] = note
        return counts[name] ?? 0
    }

    func count(_ name: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return counts[name] ?? 0
    }

    func note(_ name: String) -> String {
        lock.lock()
        defer { lock.unlock() }
        return lastOps[name] ?? ""
    }
}

/// A name list the test changes while an edit is pending.
private final class HostsBox: @unchecked Sendable {
    var value: [String]
    init(_ value: [String]) { self.value = value }
}

private let ready = HostsHelperStatus.ready(requirement: "req")
private let names = ["otel.example-corp.test"]

private func summary(_ state: BlockState, reserved: [String] = []) -> HostsFileSummary {
    HostsFileSummary(
        error: nil, analysis: HostsAnalysis(state: state, conflicts: [], reserved: reserved))
}

@MainActor
private func make(
    helper: HostsHelperStatus = ready,
    file: @escaping @Sendable () -> HostsFileSummary = { summary(.absent) },
    lookup: @escaping @Sendable ([String]) async -> [String: LookupResult] = { hosts in
        Dictionary(uniqueKeysWithValues: hosts.map { ($0, LookupResult.elsewhere(["10.0.0.9"])) })
    },
    editHosts: @escaping @Sendable (HostsOp, [String], String) async -> HostsEditOutcome = {
        _, _, _ in .done(changed: true, synced: true, message: "")
    },
    editRedirect: @escaping @Sendable (HostsOp, Int?) async -> RedirectOutcome = { _, _ in
        .done(message: "ok")
    },
    calls: Calls,
    loadRedirectPort: @escaping @Sendable () -> Int? = { nil },
    saveRedirectPort: @escaping @Sendable (Int?) -> Void = { _ in }
) -> TakeoverController {
    TakeoverController(
        dependencies: .init(
            checkHelper: {
                _ = calls.bump("helper")
                return helper
            },
            readHosts: { _ in
                _ = calls.bump("read")
                return file()
            },
            lookup: { hosts in
                _ = calls.bump("lookup")
                return await lookup(hosts)
            },
            editHosts: { op, hosts, requirement in
                _ = calls.bump("hosts", note: "\(op.rawValue):\(hosts.count):\(requirement)")
                return await editHosts(op, hosts, requirement)
            },
            editRedirect: { op, port in
                _ = calls.bump("redirect", note: "\(op.rawValue):\(port.map(String.init) ?? "-")")
                return await editRedirect(op, port)
            },
            loadRedirectPort: loadRedirectPort, saveRedirectPort: saveRedirectPort))
}

/// Waits (briefly) until the condition holds; the fake dependencies finish on other threads.
@MainActor
private func until(_ condition: () -> Bool) async {
    for _ in 0..<500 {
        if condition() { return }
        try? await Task.sleep(for: .milliseconds(10))
    }
}

@MainActor
func takeoverControllerTests() async {
    // refresh: helper once, file, lookups, only for the names shown.
    do {
        let calls = Calls()
        let c = make(calls: calls)
        await c.refresh(hosts: names)
        await c.refresh(hosts: names)
        check("takeover: helper checked once", calls.count("helper") == 1)
        check("takeover: read twice", calls.count("read") == 2)
        let s = c.state(hosts: names, port: 8443)
        check("takeover: file read", s.file == summary(.absent))
        check("takeover: lookup stored", s.lookups[names[0]] == .elsewhere(["10.0.0.9"]))
        check("takeover: not checking afterwards", !s.checking)
        check(
            "takeover: lookups of other names hidden",
            c.state(hosts: ["x.example-corp.test"], port: 8443).lookups.isEmpty)
        check("takeover: add enabled", s.canAdd && s.addReason == nil)
        check("takeover: remove needs a block", !s.canRemove)
        await c.refresh(hosts: names, recheckHelper: true)
        check("takeover: helper rechecked on demand", calls.count("helper") == 2)
        await c.refresh(hosts: [])
        check("takeover: no names, no lookups", c.state(hosts: [], port: 8443).lookups.isEmpty)
        check("takeover: no names, no lookup call", calls.count("lookup") == 3)
    }

    // A refresh that finishes after a newer one is dropped.
    do {
        let calls = Calls()
        let gate = Gate()
        let c = make(
            lookup: { hosts in
                if calls.count("lookup") == 1 {
                    await gate.wait()
                    return Dictionary(uniqueKeysWithValues: hosts.map { ($0, .error("old")) })
                }
                return Dictionary(uniqueKeysWithValues: hosts.map { ($0, .here) })
            }, calls: calls)
        let old = Task { await c.refresh(hosts: names) }
        await until { gate.hasWaiter }
        check("takeover: first lookup is held", gate.hasWaiter)
        await c.refresh(hosts: names)
        check(
            "takeover: newer result shown",
            c.state(hosts: names, port: 1).lookups[names[0]] == .here)
        gate.open()
        await old.value
        let s = c.state(hosts: names, port: 1)
        check("takeover: stale result dropped", s.lookups[names[0]] == .here)
        check("takeover: not left checking", !s.checking)
    }

    // An edit also drops a refresh that is still running.
    do {
        let calls = Calls()
        let gate = Gate()
        let c = make(
            lookup: { hosts in
                if calls.count("lookup") == 1 {
                    await gate.wait()
                    return Dictionary(
                        uniqueKeysWithValues: hosts.map { ($0, .error("before the edit")) })
                }
                return Dictionary(uniqueKeysWithValues: hosts.map { ($0, .here) })
            }, calls: calls)
        await c.refresh(hosts: [])  // fills in the helper
        let old = Task { await c.refresh(hosts: names) }
        await until { gate.hasWaiter }
        await c.addHosts(names)
        gate.open()
        await old.value
        check(
            "takeover: edit outranks an older refresh",
            c.state(hosts: names, port: 1).lookups[names[0]] == .here)
    }

    // One edit at a time, across hosts and redirect.
    do {
        let calls = Calls()
        let gate = Gate()
        let c = make(
            editHosts: { _, _, _ in
                await gate.wait()
                return .done(changed: true, synced: true, message: "")
            }, calls: calls)
        await c.refresh(hosts: names)
        let first = Task { await c.addHosts(names) }
        await until { gate.hasWaiter }
        check("takeover: busy during the edit", c.busy == .hosts(.set))
        check("takeover: busy blocks the button", !c.state(hosts: names, port: 1).canAdd)
        await c.addHosts(names)
        await c.removeHosts(hosts: names)
        await c.enableRedirect(port: 8443)
        await c.disableRedirect()
        check(
            "takeover: second edits ignored",
            calls.count("hosts") == 1 && calls.count("redirect") == 0)
        gate.open()
        await first.value
        check("takeover: idle again", c.busy == nil)
        check(
            "takeover: edit message",
            c.hostsMessage
                == TakeoverMessage(text: "Added cAInary's lines to /etc/hosts.", tone: .info))
        check("takeover: set sent names and requirement", calls.note("hosts") == "set:1:req")
    }

    // After an edit: re-read and re-look-up; never a retry.
    do {
        let calls = Calls()
        let c = make(calls: calls)
        await c.refresh(hosts: names)
        let reads = calls.count("read")
        let lookups = calls.count("lookup")
        await c.addHosts(names)
        check("takeover: re-read after add", calls.count("read") == reads + 1)
        check("takeover: re-lookup after add", calls.count("lookup") == lookups + 1)
        check("takeover: one add call", calls.count("hosts") == 1)
        await c.removeHosts(hosts: names)
        check("takeover: clear passes no names", calls.note("hosts") == "clear:0:req")
        check(
            "takeover: removal message",
            c.hostsMessage?.text == "Removed cAInary's lines.")
    }

    // An uncertain edit still re-reads, and warns.
    do {
        let calls = Calls()
        let c = make(
            editHosts: { _, _, _ in .uncertain(message: "unsure") }, calls: calls)
        await c.refresh(hosts: names)
        let reads = calls.count("read")
        await c.addHosts(names)
        check("takeover: uncertain re-reads", calls.count("read") == reads + 1)
        check(
            "takeover: uncertain is a warning",
            c.hostsMessage == TakeoverMessage(text: "unsure", tone: .warning))
    }

    // An unsigned build: no one-click, with the reason.
    do {
        let calls = Calls()
        let c = make(helper: .unavailable(HostsHelperCheck.unsignedReason), calls: calls)
        await c.refresh(hosts: names)
        await c.addHosts(names)
        await c.removeHosts(hosts: names)
        let s = c.state(hosts: names, port: 1)
        check("takeover: unsigned makes no edit", calls.count("hosts") == 0)
        check("takeover: unsigned disables add", !s.canAdd)
        check("takeover: unsigned says why", s.addReason == HostsHelperCheck.unsignedReason)
    }
    do {
        let calls = Calls()
        let c = make(
            helper: .unavailable(HostsHelperCheck.unsignedReason), file: { summary(.current) },
            calls: calls)
        await c.refresh(hosts: names)
        let s = c.state(hosts: names, port: 1)
        check("takeover: unsigned disables remove", s.gate.canRemove && !s.canRemove)
        check("takeover: unsigned remove reason", s.removeReason == HostsHelperCheck.unsignedReason)
    }

    // The gate (R9): damaged, reserved, too many names.
    do {
        let calls = Calls()
        let damaged = make(file: { summary(.damaged) }, calls: calls)
        await damaged.refresh(hosts: names)
        let d = damaged.state(hosts: names, port: 1)
        check(
            "takeover: damaged disables add", !d.canAdd && d.addReason?.contains("damaged") == true)
        check("takeover: damaged flagged", d.damagedBlock)
        let reserved = make(file: { summary(.absent, reserved: names) }, calls: calls)
        await reserved.refresh(hosts: names)
        let r = reserved.state(hosts: names, port: 1)
        check(
            "takeover: reserved disables add",
            !r.canAdd && r.addReason?.contains("reserved") == true)
        let many = (1...9).map { "h\($0).example-corp.test" }
        let wide = make(calls: calls)
        await wide.refresh(hosts: many)
        let w = wide.state(hosts: many, port: 1)
        check("takeover: more than 8 names", !w.canAdd && w.addReason?.contains("8") == true)
        let stale = make(file: { summary(.stale) }, calls: calls)
        await stale.refresh(hosts: names)
        let t = stale.state(hosts: names, port: 1)
        check("takeover: stale can update and remove", t.canAdd && t.canRemove && t.ownBlock)
    }

    // Redirect.
    do {
        let calls = Calls()
        let c = make(calls: calls)
        await c.enableRedirect(port: 8443)
        check(
            "takeover: redirect enabled",
            c.redirect == .enabled && calls.note("redirect") == "set:8443")
        await c.disableRedirect()
        check(
            "takeover: redirect disabled",
            c.redirect == .disabled && calls.note("redirect") == "clear:-")
        let failing = make(editRedirect: { _, _ in .failed(message: "pfctl failed") }, calls: calls)
        await failing.enableRedirect(port: 8443)
        check(
            "takeover: failed redirect is an error",
            failing.redirect == .unknown
                && failing.redirectMessage == TakeoverMessage(text: "pfctl failed", tone: .error))
        let unsure = make(editRedirect: { _, _ in .uncertain(message: "?") }, calls: calls)
        await unsure.enableRedirect(port: 8443)
        check(
            "takeover: uncertain redirect",
            unsure.redirect == .unknown && unsure.redirectMessage?.tone == .warning)
        let cancelled = make(editRedirect: { _, _ in .cancelled(message: "no") }, calls: calls)
        await cancelled.enableRedirect(port: 8443)
        check(
            "takeover: cancelled redirect changes nothing",
            cancelled.redirect == .unknown && cancelled.redirectMessage?.tone == .info)
    }

    // The redirect is remembered across launches, so Restore can offer to disable it.
    do {
        final class Memory: @unchecked Sendable { var port: Int? }
        let memory = Memory()
        func remembering() -> TakeoverController {
            make(
                calls: Calls(), loadRedirectPort: { memory.port },
                saveRedirectPort: { memory.port = $0 })
        }
        let first = remembering()
        check("takeover memory: nothing remembered", first.redirect == .unknown)
        await first.enableRedirect(port: 8443)
        check("takeover memory: enable is saved", memory.port == 8443)
        let next = remembering()
        check(
            "takeover memory: next launch knows it is on",
            next.redirect == .enabled && next.redirectPort == 8443)
        await next.disableRedirect()
        check("takeover memory: disable forgets it", memory.port == nil)
        check("takeover memory: and the launch after", remembering().redirect == .unknown)
    }

    // A redirect made for one port is pending once the collector's port changes.
    do {
        let calls = Calls()
        let c = make(calls: calls)
        await c.enableRedirect(port: 8443)
        let same = c.state(hosts: names, port: 8443)
        check(
            "redirect: done for the same port",
            same.indicator(.redirect, trust: TrustSnapshot()).status == .done
                && same.redirectStaleNote == nil)
        let moved = c.state(hosts: names, port: 9443)
        let i = moved.indicator(.redirect, trust: TrustSnapshot())
        check(
            "redirect: pending after the port changed",
            i.status == .todo && i.text == "Points at port 8443")
        check(
            "redirect: note names both ports",
            moved.redirectStaleNote
                == "The redirect points at port 8443; enable it again for 9443.")
        await c.enableRedirect(port: 9443)
        check(
            "redirect: enabling again is done",
            c.state(hosts: names, port: 9443).indicator(.redirect, trust: TrustSnapshot()).status
                == .done)
        await c.disableRedirect()
        check(
            "redirect: disabling forgets the port",
            c.redirectPort == nil && c.state(hosts: names, port: 9443).redirectStaleNote == nil)
    }

    // An enable that finishes after the port changed doesn't mark the new port done.
    do {
        let calls = Calls()
        let gate = Gate()
        let c = make(
            editRedirect: { _, _ in
                await gate.wait()
                return .done(message: "ok")
            }, calls: calls)
        let slow = Task { await c.enableRedirect(port: 8443) }
        await until { gate.hasWaiter }
        // The user moved the collector to 9443 while the prompt was open.
        gate.open()
        await slow.value
        let s = c.state(hosts: names, port: 9443)
        check(
            "redirect: late enable leaves the new port pending",
            s.indicator(.redirect, trust: TrustSnapshot()).status == .todo && c.redirectPort == 8443
        )
    }

    // An edit re-reads with the names configured when it ends, and results for other names hide.
    do {
        let calls = Calls()
        let gate = Gate()
        let other = ["b.example-corp.test"]
        let c = make(
            editHosts: { _, _, _ in
                await gate.wait()
                return .done(changed: true, synced: true, message: "")
            }, calls: calls)
        await c.refresh(hosts: names)
        let configured = HostsBox(names)
        let edit = Task { await c.addHosts(names, latest: { configured.value }) }
        await until { gate.hasWaiter }
        configured.value = other
        gate.open()
        await edit.value
        let s = c.state(hosts: other, port: 1)
        check(
            "takeover: edit refreshed for the latest names",
            s.lookups[other[0]] != nil && s.file != nil && !s.checking)
        check(
            "takeover: results for the old names are hidden",
            c.state(hosts: names, port: 1).file == nil
                && c.state(hosts: names, port: 1).lookups.isEmpty)
    }
    do {
        let calls = Calls()
        let c = make(calls: calls)
        await c.refresh(hosts: names)
        check(
            "takeover: a changed name list hides the old analysis",
            c.state(hosts: names + ["c.example-corp.test"], port: 1).file == nil)
        check("takeover: the same names keep it", c.state(hosts: names, port: 1).file != nil)
    }

    // An unsupported /etc/hosts disables add and remove.
    do {
        let calls = Calls()
        let c = make(
            file: {
                HostsFileSummary(
                    error: nil,
                    analysis: HostsAnalysis(state: .current, conflicts: [], reserved: []),
                    unsupported: .hardlinked)
            }, calls: calls)
        await c.refresh(hosts: names)
        let s = c.state(hosts: names, port: 1)
        check(
            "takeover: unsupported file disables both",
            !s.canAdd && !s.canRemove && s.addReason == HostsUnsupported.hardlinked.reason)
    }

    // Outcome wording and tone.
    do {
        let m = TakeoverController.message
        check(
            "takeover: unchanged",
            m(.done(changed: false, synced: true, message: ""), .set).text == "Already up to date.")
        check(
            "takeover: unsynced is a warning",
            m(.done(changed: true, synced: false, message: "x"), .set).tone == .warning)
        check("takeover: cancelled is info", m(.cancelled(message: "c"), .set).tone == .info)
        check(
            "takeover: refused is an error",
            m(.refused(token: "busy", message: "b"), .set).tone == .error)
        check("takeover: not run is an error", m(.notRun(message: "n"), .clear).tone == .error)
    }

    // Step indicators.
    do {
        var s = TakeoverState(hosts: names)
        let none = TrustSnapshot()
        check(
            "indicator: hosts not checked",
            s.indicator(.hosts, trust: none) == StepIndicator(status: .unknown, text: "Not checked")
        )
        s.lookups = [names[0]: .here]
        check(
            "indicator: hosts done",
            s.indicator(.hosts, trust: none) == StepIndicator(status: .done, text: "Points here"))
        check("indicator: flush follows", s.indicator(.flush, trust: none).status == .done)
        s.lookups = [names[0]: .elsewhere(["10.0.0.9"])]
        s.file = summary(.current)
        check(
            "indicator: still elsewhere",
            s.indicator(.hosts, trust: none).text == "Still points elsewhere")
        s.file = summary(.stale)
        check("indicator: out of date", s.indicator(.hosts, trust: none).text == "Out of date")
        s.file = summary(.absent)
        check("indicator: elsewhere", s.indicator(.hosts, trust: none).text == "Points elsewhere")
        s.lookups = [names[0]: .error("No address found")]
        check(
            "indicator: doesn't resolve", s.indicator(.hosts, trust: none).text == "Doesn't resolve"
        )
        s.checking = true
        check("indicator: checking", s.indicator(.hosts, trust: none).status == .waiting)
        s.checking = false
        s.busy = .hosts(.set)
        check(
            "indicator: waiting for permission",
            s.indicator(.hosts, trust: none).text == "Waiting for permission")
        check(
            "indicator: empty hosts",
            TakeoverState().indicator(.hosts, trust: none).text == "Add a host name")
        s.busy = nil
        check(
            "indicator: redirect can't check",
            s.indicator(.redirect, trust: none).text == "Can't check")
        s.redirect = .enabled
        check("indicator: redirect enabled", s.indicator(.redirect, trust: none).status == .done)
        s.redirect = .disabled
        check("indicator: redirect disabled", s.indicator(.redirect, trust: none).status == .todo)
        check("indicator: restart off", s.indicator(.restart, trust: none).status == .off)
        s.listening = true
        check("indicator: restart waiting", s.indicator(.restart, trust: none).status == .waiting)
        s.batchCount = 3
        check(
            "indicator: restart receiving",
            s.indicator(.restart, trust: none).text == "Receiving · 3 batches")
        s.batchCount = 1
        check(
            "indicator: restart one batch",
            s.indicator(.restart, trust: none).text == "Receiving · 1 batch")

        func trust(_ claude: String, _ codex: String, ca: Bool = true) -> TrustSnapshot {
            TrustSnapshot(
                status: TrustStatus(
                    claudeCode: .init(state: claude), codex: .init(state: codex), caPath: "/x",
                    caExists: ca))
        }
        check("indicator: trust unknown", s.indicator(.trust, trust: none).status == .off)
        check(
            "indicator: trust no CA",
            s.indicator(.trust, trust: trust("applied", "ready", ca: false)).status == .off)
        check(
            "indicator: trust both",
            s.indicator(.trust, trust: trust("applied", "ready")).text == "Both ready")
        check(
            "indicator: trust claude",
            s.indicator(.trust, trust: trust("applied", "absent")).text == "Claude Code trusted")
        check(
            "indicator: trust codex",
            s.indicator(.trust, trust: trust("absent", "ready")).text == "Codex ready")
        check(
            "indicator: trust other",
            s.indicator(.trust, trust: trust("other-value", "absent")).status == .todo)
        check(
            "indicator: trust none",
            s.indicator(.trust, trust: trust("absent", "absent")).text == "Not done")
    }

    // Lookup wording.
    do {
        var s = TakeoverState(hosts: names)
        s.lookups = [names[0]: .here]
        check("lookup text: here", s.lookupText(names[0]) == "resolves to 127.0.0.1")
        s.lookups = [names[0]: .elsewhere(["10.0.0.9"])]
        check("lookup text: elsewhere", s.lookupText(names[0]) == "not yet: resolves to 10.0.0.9")
        s.lookups = [:]
        check("lookup text: unchecked", s.lookupText(names[0]) == "not checked")
        s.checking = true
        check("lookup text: checking", s.lookupText(names[0]) == "checking…")
    }
}
