import Foundation

// §5a: the Swift model against the Rust goldens, plus forward-compatibility cases.

/// The golden reports: every `.json` in the core and CLI golden directories.
private func goldenReports() -> [URL] {
    let dirs = ["crates/cainary-core/tests/golden", "crates/cainary-cli/tests/golden"]
    var found: [URL] = []
    for dir in dirs {
        let url = repoRoot().appendingPathComponent(dir)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        found += names.filter { $0.hasSuffix(".json") }.sorted().map {
            url.appendingPathComponent($0)
        }
    }
    return found
}

/// A golden report as a mutable JSON object, to build variants from.
private func baseObject() -> [String: Any] {
    let url = repoRoot().appendingPathComponent(
        "crates/cainary-core/tests/golden/claude-code-org-macos.json")
    let data = (try? Data(contentsOf: url)) ?? Data()
    return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
}

/// Writes `object` to `$TMPDIR`, reads it back and decodes it, so the whole path is exercised.
private func decode(_ object: [String: Any], _ name: String) throws -> Report {
    let file = scratchDirectory("decode").appendingPathComponent("\(name).json")
    try JSONSerialization.data(withJSONObject: object).write(to: file)
    return try Report.decode(Data(contentsOf: file))
}

/// Edits the first finding of the first app that has one.
private func editFirstFinding(_ o: inout [String: Any], _ edit: (inout [String: Any]) -> Void) {
    var apps = o["apps"] as? [[String: Any]] ?? []
    for i in apps.indices {
        var findings = apps[i]["findings"] as? [[String: Any]] ?? []
        if findings.isEmpty { continue }
        edit(&findings[0])
        apps[i]["findings"] = findings
        break
    }
    o["apps"] = apps
}

private func sampleChange(scope: String, kind: String, notify: Bool = true) -> [String: Any] {
    [
        "id": "\(scope):claude:-:\(kind):high", "scope": scope, "entry": "claude", "key": NSNull(),
        "kind": kind, "from": "low", "to": "high", "notify": notify, "text": "Claude is now HIGH",
    ]
}

@MainActor
func decodeTests() {
    // Goldens.
    let goldens = goldenReports()
    check("decode: found goldens", goldens.count >= 30)
    for url in goldens {
        let name = url.lastPathComponent
        do {
            let report = try Report.decode(Data(contentsOf: url))
            check("decode: \(name) is schema 3", report.schema == 3)
            check("decode: \(name) has four apps", report.apps.count == 4)
            check("decode: \(name) status level is known", !report.status.level.isUnknown)
            let all = report.entries.flatMap(\.findings)
            check(
                "decode: \(name) all slugs known",
                all.allSatisfy {
                    $0.sends.allSatisfy(\.isKnown) && $0.setBy.isKnown && $0.surface.isKnown
                })
        } catch {
            check("decode: \(name) (\(error))", false)
        }
    }

    // Values come through.
    if let report = try? Report.decode(
        Data(
            contentsOf: repoRoot().appendingPathComponent(
                "crates/cainary-core/tests/golden/claude-code-org-macos.json")))
    {
        check("values: overall level is high", report.status.level == .high)
        check("values: first app is claude", report.apps.first?.id == "claude")
        let f = report.apps.first?.findings.first
        check("values: finding key", f?.key == "61844d1a58abfc42")
        check("values: finding setBy mdm", f?.setBy.slug == "mdm")
        check("values: finding docs", f?.docs == "https://code.claude.com/docs/en/hooks")
        check("values: no since on a plain scan", report.since == nil && report.changes == nil)
    } else {
        check("values: org-macos decodes", false)
    }

    // Level order: the worst wins, unknown is below everything.
    check("level: order", Level.notInstalled < .ok && Level.ok < .optedOut && Level.optedOut < .low)
    check("level: order top", Level.low < .medium && Level.medium < .high)
    check("level: unknown below not-installed", Level.unknown("x") < .notInstalled)
    check("level: max", [Level.low, .high, .ok].max() == .high)

    // Forward compatibility: an unknown slug per open enum decodes.
    var o = baseObject()
    o["status"] = ["level": "catastrophic", "label": "?", "summary": "s"]
    check("fwd: unknown level", (try? decode(o, "level"))?.status.level == .unknown("catastrophic"))

    o = baseObject()
    editFirstFinding(&o) {
        $0["level"] = "extreme"
        $0["sends"] = ["prompts", "holograms"]
        $0["setBy"] = "aliens"
        $0["surface"] = "claude-vr"
        var c = $0["config"] as? [String: Any] ?? [:]
        c["kind"] = "carrier-pigeon"
        $0["config"] = c
    }
    let f = (try? decode(o, "finding"))?.apps.first?.findings.first
    check("fwd: unknown finding level", f?.level == .unknown("extreme"))
    check(
        "fwd: unknown signal", f?.sends.last?.slug == "holograms" && f?.sends.last?.isKnown == false
    )
    check("fwd: unknown origin", f?.setBy.slug == "aliens" && f?.setBy.isKnown == false)
    check("fwd: unknown surface", f?.surface.slug == "claude-vr")
    check("fwd: unknown config kind", f?.config.kind.slug == "carrier-pigeon")

    o = baseObject()
    var apps = o["apps"] as? [[String: Any]] ?? []
    apps[0]["kind"] = "hologram"
    o["apps"] = apps
    check(
        "fwd: unknown entry kind",
        (try? decode(o, "entrykind"))?.apps.first?.kind.slug == "hologram")

    o = baseObject()
    var sources = o["sources"] as? [[String: Any]] ?? []
    if !sources.isEmpty { sources[0]["state"] = "haunted" }
    o["sources"] = sources
    let r = try? decode(o, "sourcestate")
    check("fwd: unknown source state", r?.sources.first?.state.slug == "haunted")
    check("fwd: unknown state is not a problem", r?.sources.first?.state.isProblem == false)

    o = baseObject()
    o["since"] = ["scannedAt": "2026-01-01T00:00:00Z", "error": NSNull()]
    o["changes"] = [
        sampleChange(scope: "entry", kind: "raised"),
        sampleChange(scope: "galaxy", kind: "raised"),
        sampleChange(scope: "entry", kind: "exploded"),
        sampleChange(scope: "entry", kind: "raised", notify: false),
    ]
    let c = try? decode(o, "changes")
    check(
        "fwd: since decodes",
        c?.since?.scannedAt == "2026-01-01T00:00:00Z" && c?.since?.error == nil)
    check("fwd: changes decode", c?.changes?.count == 4)
    check("fwd: unknown scope slug kept", c?.changes?[1].scope.slug == "galaxy")
    check("fwd: unknown kind slug kept", c?.changes?[2].kind.slug == "exploded")
    check(
        "fwd: only known notifying changes notify",
        c?.notifyingChanges.map(\.id) == ["entry:claude:-:raised:high"])

    o = baseObject()
    o["since"] = ["scannedAt": "2026-01-01T00:00:00Z", "error": "baseline is not JSON"]
    o["changes"] = [Any]()
    check(
        "fwd: since.error", (try? decode(o, "sinceerror"))?.since?.error == "baseline is not JSON")

    // Extra keys are ignored; alert and counts are optional.
    o = baseObject()
    o["futureField"] = ["nested": [1, 2, 3]]
    o["alert"] = nil
    var s = o["status"] as? [String: Any] ?? [:]
    s["extra"] = true
    o["status"] = s
    editFirstFinding(&o) {
        $0["extra"] = "x"
        $0["counts"] = nil
    }
    check("fwd: extra keys ignored, alert/counts optional", (try? decode(o, "extra")) != nil)

    // A missing required key and a wrong type both fail.
    for key in [
        "schema", "generator", "scannedAt", "os", "envKind", "complete", "status", "apps", "others",
        "sources",
    ] {
        o = baseObject()
        o[key] = nil
        check("fail: missing \(key)", (try? decode(o, "missing")) == nil)
    }
    o = baseObject()
    editFirstFinding(&o) { $0["key"] = nil }
    check("fail: missing finding key", (try? decode(o, "missing-key")) == nil)
    o = baseObject()
    o["complete"] = "yes"
    check("fail: wrong type complete", (try? decode(o, "wrong-bool")) == nil)
    o = baseObject()
    o["schema"] = "3"
    check("fail: wrong type schema", (try? decode(o, "wrong-schema")) == nil)
    o = baseObject()
    editFirstFinding(&o) { $0["sends"] = "prompts" }
    check("fail: wrong type sends", (try? decode(o, "wrong-sends")) == nil)

    checkThrows("fail: not JSON") { _ = try Report.decode(Data("not json".utf8)) }

    try? FileManager.default.removeItem(at: scratchDirectory("decode"))
}
