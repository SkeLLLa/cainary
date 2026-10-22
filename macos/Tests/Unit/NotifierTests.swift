import Foundation

// plan(): what each notification says (macos.md §2.4, §5b).

private func org() -> Report? {
    let url = repoRoot()
        .appendingPathComponent("crates/cainary-core/tests/golden/claude-code-org-macos.json")
    return (try? Data(contentsOf: url)).flatMap { try? Report.decode($0) }
}

private func change(
    _ id: String, entry: String?, scope: String = "finding", kind: String = "added",
    notify: Bool = true, text: String
) -> Change {
    Change(
        id: id, scope: ChangeScope(slug: scope), entry: entry, key: nil,
        kind: ChangeKind(slug: kind), from: nil, to: "high", notify: notify, text: text)
}

@MainActor
func notifierTests() {
    guard let report = org(), let claude = report.entries.first(where: { $0.id == "claude" })
    else {
        check("notifier: golden decodes", false)
        return
    }
    let cursor = report.entries.first(where: { $0.id != "claude" })?.id
    let changes = [
        change("c1", entry: "claude", text: "first"),
        change("x1", entry: cursor, text: "other entry"),
        change("c2", entry: "claude", text: "second"),
        change("c3", entry: "claude", text: "third"),
    ]
    let ids: Set<String> = ["c1", "c2", "c3", "x1"]

    // One notification per entry, in order of first change, folding the rest.
    let planned = plan(changes: changes, report: report, ids: ids)
    check("plan: one per entry", planned.map(\.entryId) == ["claude", cursor ?? ""])
    if let first = planned.first {
        check(
            "plan: title uses the current label",
            first.title == "\(claude.name) · \(claude.status.label)")
        check("plan: body folds the rest", first.body == "first (+2 more)")
        check("plan: change ids", first.changeIds == ["c1", "c2", "c3"])
    }
    check("plan: a single change has no suffix", planned.last?.body == "other entry")

    // Only ids that are due.
    let some = plan(changes: changes, report: report, ids: ["c2"])
    check("plan: only due ids", some.count == 1 && some[0].body == "second")
    check("plan: nothing due", plan(changes: changes, report: report, ids: []).isEmpty)

    // Skipped: report scope, unknown scope or kind, notify false, an entry that isn't there.
    let skipped = [
        change("s1", entry: nil, scope: "report", text: "scan"),
        change("s2", entry: "claude", scope: "report", text: "scan too"),
        change("s3", entry: "claude", scope: "galaxy", text: "unknown scope"),
        change("s4", entry: "claude", kind: "teleported", text: "unknown kind"),
        change("s5", entry: "claude", notify: false, text: "quiet"),
        change("s6", entry: "no-such-entry", text: "missing entry"),
    ]
    check(
        "plan: skips report scope, unknown scope or kind, quiet changes and missing entries",
        plan(changes: skipped, report: report, ids: Set(skipped.map(\.id))).isEmpty)
}

// UNNotifier against a fake center: the preference and authorization branches (macos.md §2.4).

private func item(_ entry: String, _ ids: [String]) -> Planned {
    Planned(entryId: entry, title: "\(entry) · HIGH", body: ids[0], changeIds: ids)
}

@MainActor
func notifierCenterTests() async {
    let two = [item("claude", ["c1", "c2"]), item("cursor", ["x1"])]
    let all: Set<String> = ["c1", "c2", "x1"]

    func make(_ configure: (MemoryStore, FakeCenter) -> Void = { _, _ in })
        -> (UNNotifier, MemoryStore, FakeCenter)
    {
        let defaults = MemoryStore()
        defaults.notifyChanges = true
        let center = FakeCenter()
        configure(defaults, center)
        return (UNNotifier(defaults: defaults, center: center), defaults, center)
    }

    // Authorized: everything is added, one request per entry.
    do {
        let (notifier, _, center) = make()
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: posts all",
            handled == all && center.added.map(\.identifier) == ["claude", "cursor"])
        check("center: no prompt when decided", center.prompts == 0)
    }

    // The preference is off: nothing is asked or added, and every id counts as handled.
    do {
        let (notifier, _, center) = make { defaults, center in
            defaults.notifyChanges = false
            center.status = .notDetermined
        }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: muted by preference",
            handled == all && center.added.isEmpty && center.prompts == 0)
    }

    // Not determined: the prompt is shown once; granted posts, refused mutes.
    do {
        let (notifier, _, center) = make { $1.status = .notDetermined }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: prompt granted",
            handled == all && center.prompts == 1 && center.added.count == 2)
    }
    do {
        let (notifier, _, center) = make { _, center in
            center.status = .notDetermined
            center.grants = false
        }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: prompt refused", handled == all && center.prompts == 1 && center.added.isEmpty)
    }

    // Denied in System Settings: handled without a prompt.
    do {
        let (notifier, _, center) = make { $1.status = .denied }
        let handled = await notifier.post(two, isCurrent: { true })
        check("center: denied", handled == all && center.prompts == 0 && center.added.isEmpty)
    }

    // Muted while the prompt (or authorization check) is open: nothing is added, all handled.
    do {
        let (notifier, defaults, center) = make { $1.status = .notDetermined }
        center.afterAuthorization = { defaults.notifyChanges = false }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: muted during the prompt",
            !defaults.notifyChanges && handled == all && center.added.isEmpty)
    }

    // Muted between two adds: the first is shown, the remaining ones count as handled.
    do {
        let (notifier, defaults, center) = make()
        center.afterAdd = { defaults.notifyChanges = false }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: muted between adds",
            handled == all && center.added.map(\.identifier) == ["claude"])
    }

    // The generation changed during authorization: nothing is added or handled.
    do {
        let (notifier, _, center) = make()
        let handled = await notifier.post(two, isCurrent: { false })
        check("center: stale post handles nothing", handled.isEmpty && center.added.isEmpty)
    }

    // A failed add isn't handled; the other one is.
    do {
        let (notifier, _, center) = make { $1.failIds = ["claude"] }
        let handled = await notifier.post(two, isCurrent: { true })
        check(
            "center: failed add stays due",
            handled == ["x1"] && center.added.map(\.identifier) == ["cursor"])
    }
}
