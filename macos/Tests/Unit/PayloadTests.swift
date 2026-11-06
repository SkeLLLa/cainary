import Foundation

// The `payload` of a finding (design §2, §7): every core golden decodes with it, and a payload
// that is malformed or from a newer core never breaks the report.

private func goldenURLs() -> [URL] {
    let dirs = ["crates/cainary-core/tests/golden", "crates/cainary-cli/tests/golden"]
    return dirs.flatMap { dir -> [URL] in
        let url = repoRoot().appendingPathComponent(dir)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        return names.filter { $0.hasSuffix(".json") }.sorted().map { url.appendingPathComponent($0) }
    }
}

/// `payload` keys in a report's JSON, by entry id and finding key.
private func payloadKeys(_ object: [String: Any]) -> Set<String> {
    var found: Set<String> = []
    for group in ["apps", "others"] {
        for entry in object[group] as? [[String: Any]] ?? [] {
            for finding in entry["findings"] as? [[String: Any]] ?? [] where finding["payload"] != nil {
                found.insert("\(entry["id"] as? String ?? "?")/\(finding["key"] as? String ?? "?")")
            }
        }
    }
    return found
}

private func base() -> [String: Any] {
    let url = repoRoot().appendingPathComponent(
        "crates/cainary-core/tests/golden/claude-code-org-macos.json")
    let data = (try? Data(contentsOf: url)) ?? Data()
    return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
}

/// Edits the first finding that has a payload, in `apps`.
private func editPayloadFinding(
    _ o: inout [String: Any], _ edit: (inout [String: Any]) -> Void
) {
    var apps = o["apps"] as? [[String: Any]] ?? []
    for i in apps.indices {
        var findings = apps[i]["findings"] as? [[String: Any]] ?? []
        guard let j = findings.firstIndex(where: { $0["payload"] != nil }) else { continue }
        edit(&findings[j])
        apps[i]["findings"] = findings
        break
    }
    o["apps"] = apps
}

private func decode(_ object: [String: Any]) -> Report? {
    (try? JSONSerialization.data(withJSONObject: object)).flatMap { try? Report.decode($0) }
}

@MainActor
func payloadTests() {
    // Every golden decodes, and exactly the findings with a `payload` key get one.
    var withPayload = 0
    for url in goldenURLs() {
        let name = url.lastPathComponent
        guard let data = try? Data(contentsOf: url),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let report = try? Report.decode(data)
        else {
            check("payload: \(name) decodes", false)
            continue
        }
        let expected = payloadKeys(object)
        let decoded = Set(
            (report.apps + report.others).flatMap { entry in
                entry.findings.filter { $0.payload != nil }.map { "\(entry.id)/\($0.key)" }
            })
        check("payload: \(name) payloads decode", expected == decoded)
        withPayload += expected.count
    }
    check("payload: goldens with payloads found", withPayload >= 5)

    // Values come through.
    if let report = try? Report.decode(
        Data(
            contentsOf: repoRoot().appendingPathComponent(
                "crates/cainary-core/tests/golden/claude-code-org-macos.json"))),
        let payload = report.entries.flatMap(\.findings).compactMap(\.payload).first
    {
        check("payload: export", payload.export.slug == "logs")
        check("payload: catalog named", payload.catalog.hasPrefix("claude-code"))
        check("payload: gates", !payload.gates.isEmpty && !payload.gates[0].text.isEmpty)
        check("payload: gate sent", payload.gates.contains { $0.sent.slug == "redacted" })
        check("payload: records", !payload.records.isEmpty && !payload.sample.isEmpty)
        check("payload: attr group", payload.records.flatMap(\.attrs).allSatisfy { !$0.group.isEmpty })
        check("payload: optional gate fields", payload.gates.contains { $0.setBy == nil })
    } else {
        check("payload: claude-code-org-macos has one", false)
    }

    // Malformed payloads hide the preview and nothing else.
    var o = base()
    var oopsKey = ""
    editPayloadFinding(&o) {
        oopsKey = $0["key"] as? String ?? ""
        $0["payload"] = "oops"
    }
    if let report = decode(o), let f = report.entries.flatMap(\.findings).first(where: { $0.key == oopsKey }) {
        check("payload: string payload is nil", f.payload == nil)
        check("payload: string payload keeps the finding", !f.title.isEmpty)
    } else {
        check("payload: string payload still decodes the report", false)
    }

    var o2 = base()
    var targetKey = ""
    editPayloadFinding(&o2) {
        targetKey = $0["key"] as? String ?? ""
        var p = $0["payload"] as? [String: Any] ?? [:]
        p["export"] = nil
        $0["payload"] = p
    }
    if let report = decode(o2), let f = report.entries.flatMap(\.findings).first(where: { $0.key == targetKey }) {
        check("payload: missing export hides it", f.payload == nil)
        check("payload: finding itself intact", !f.title.isEmpty && f.key == targetKey)
    } else {
        check("payload: missing export still decodes the report", false)
    }

    var o3 = base()
    editPayloadFinding(&o3) { $0["payload"] = NSNull() }
    check("payload: null payload decodes", decode(o3) != nil)

    // Newer cores: unknown slugs, unknown keys and an absent `maybe` are fine.
    var o4 = base()
    var key4 = ""
    editPayloadFinding(&o4) {
        key4 = $0["key"] as? String ?? ""
        var p = $0["payload"] as? [String: Any] ?? [:]
        p["futureKey"] = ["a": 1]
        p["export"] = "spans"
        p["maybe"] = nil
        var gates = p["gates"] as? [[String: Any]] ?? []
        if !gates.isEmpty {
            gates[0]["sent"] = "from-the-future"
            gates[0]["extra"] = true
        }
        p["gates"] = gates
        var records = p["records"] as? [[String: Any]] ?? []
        if !records.isEmpty { records[0]["kind"] = "profile" }
        p["records"] = records
        $0["payload"] = p
    }
    if let report = decode(o4),
        let payload = report.entries.flatMap(\.findings).first(where: { $0.key == key4 })?.payload
    {
        check("payload: unknown export slug kept", payload.export.slug == "spans")
        check("payload: unknown sent slug kept", payload.gates.first?.sent.slug == "from-the-future")
        check("payload: unknown kind slug kept", payload.records.first?.kind.slug == "profile")
        check("payload: absent maybe is false", !payload.maybe)
    } else {
        check("payload: newer core payload decodes", false)
    }
}
