import Foundation

// The HTTPS takeover: its settings and argv, the one-shot trust calls against
// stub scripts, the confirm-before-write flow, host suggestions and the listen-error note.

private func stub(_ name: String) -> URL {
    repoRoot().appendingPathComponent("macos/Tests/stubs/\(name)")
}

private func argsLog(_ dir: URL) -> [String] {
    ((try? String(contentsOf: dir.appendingPathComponent("args"), encoding: .utf8)) ?? "")
        .split(separator: "\n").map(String.init)
}

@MainActor
func trustTests() async {
    settingsChecks()
    hostChecks()
    await oneShotChecks()
    await flowChecks()
    listenNoteChecks()
    realOutputChecks()
    realOutputV2Checks()
    await codexRefusalCheck()
}

@MainActor
private func settingsChecks() {
    var s = CollectorSettings()
    check(
        "takeover: off by default", !s.takeover && s.takeoverPort == 8443 && s.takeoverHosts.isEmpty
    )
    check("takeover: off argv has no tls", !s.arguments.contains("--tls"))
    s.takeover = true
    check("takeover: needs a host", s.problem?.code == .tlsNoHost)
    s.takeoverHosts = [
        "Otel.Example-Corp.com", "bad host", "otel.example-corp.com", "1.2.3.4", "*.x.com",
        "localhost", "",
    ]
    check("takeover: valid hosts only, lowercased, once", s.validHosts == ["otel.example-corp.com"])
    check("takeover: bad names are reported, argv skips them", s.problem?.code == .tlsBadHost)
    let mixed = s.takeoverHosts
    s.takeoverHosts = ["Otel.Example-Corp.com"]
    check("takeover: no problem with a host", s.problem == nil)
    s.takeoverHosts = mixed
    check(
        "takeover: argv",
        s.arguments == [
            "--json", "--config-stdin", "--port", "8443", "--tls", "--tls-host",
            "otel.example-corp.com",
        ])
    s.logToFile = true
    s.logPath = "/tmp/x.jsonl"
    check("takeover: log file after tls", s.arguments.suffix(2) == ["--log-file", "/tmp/x.jsonl"])
    s.patterns = [CollectorPattern(name: "customer", pattern: "acme-internal")]
    check(
        "takeover: patterns stay out of argv", !s.arguments.joined(separator: " ").contains("acme"))
    check(
        "takeover: patterns still in the config line",
        s.configLine.map { String(decoding: $0, as: UTF8.self).contains("acme-internal") } == true)

    let mem = MemoryStore()
    mem.collectorSettings = s
    let back = mem.collectorSettings
    check(
        "takeover: prefs round trip",
        back.takeover && back.takeoverHosts == s.takeoverHosts && back.takeoverPort == 8443)
    mem.set(70000, forKey: PrefKey.otelCollectorTlsPort)
    check("takeover: port clamped", mem.collectorSettings.takeoverPort == 65535)
    mem.set(80, forKey: PrefKey.otelCollectorTlsPort)
    check("takeover: low port clamped", mem.collectorSettings.takeoverPort == 1024)
    check("takeover: prefs keys", PrefKey.otelCollectorTls == "otelCollectorTls")

    // A takeover without a usable host doesn't start.
    var empty = CollectorSettings()
    empty.takeover = true
    let store = CollectorStore(defaults: MemoryStore(), helper: stub("collector-hello.sh"))
    store.apply(empty)
    store.apply(
        {
            var e = empty; e.enabled = true; return e
        }())
    check(
        "takeover: store refuses to start without a host",
        store.state == .failed("Add at least one host name for the HTTPS takeover."))
}

@MainActor
private func hostChecks() {
    check("hosts: accepts a dotted name", CollectorSettings.validHost("otel.example-corp.com"))
    for bad in [
        "localhost", "-a.com", "a..com", "a.com.", "1.2.3.4", "*.a.com", "a b.com",
        String(repeating: "a", count: 64) + ".com",
    ] {
        check("hosts: rejects \(bad)", !CollectorSettings.validHost(bad))
    }
    let url = repoRoot().appendingPathComponent(
        "crates/cainary-core/tests/golden/claude-code-org-macos.json")
    if let report = (try? Data(contentsOf: url)).flatMap({ try? Report.decode($0) }) {
        check(
            "hosts: suggested from telemetry findings",
            TelemetryHosts.suggestions(in: report) == ["otel.example-corp.com"])
    } else {
        check("hosts: golden decodes", false)
    }
}

@MainActor
private func oneShotChecks() async {
    let dir = scratchDirectory("trust-oneshot")
    setenv("CAINARY_STUB_DIR", dir.path, 1)
    defer { unsetenv("CAINARY_STUB_DIR") }

    let status = await TrustClient(helper: stub("trust.sh")).status()
    if case .status(let s) = status {
        check("trust: status", s.claudeCode?.state == "absent" && s.codex?.state == "absent")
        check("trust: caPath keeps its space", s.caPath?.contains("Application Support") == true)
    } else {
        check("trust: status decodes", false)
    }
    check(
        "trust: the no-write command quotes the path",
        nodeExtraCACommand(caPath: "/Users/u/Library/Application Support/cainary/ca.pem")
            == "env NODE_EXTRA_CA_CERTS='/Users/u/Library/Application Support/cainary/ca.pem' claude"
    )
    check(
        "trust: plain path unquoted",
        nodeExtraCACommand(caPath: "/tmp/ca.pem") == "env NODE_EXTRA_CA_CERTS=/tmp/ca.pem claude")
    check("trust: quote in path", nodeExtraCACommand(caPath: "/a'b").contains("'/a'\\''b'"))

    // A refusal exits 1 and is still a report.
    FileManager.default.createFile(
        atPath: dir.appendingPathComponent("refuse").path, contents: Data())
    if case .report(let r) = await TrustClient(helper: stub("trust.sh")).previewClaudeCode() {
        check(
            "trust: refused is a report",
            r.action == "refused" && r.message?.contains("managed") == true)
    } else {
        check("trust: refused decodes", false)
    }
    try? FileManager.default.removeItem(at: dir.appendingPathComponent("refuse"))

    // Failures are outcomes, not crashes.
    let missing = await TrustClient(helper: URL(fileURLWithPath: "/nonexistent/x")).status()
    check("trust: missing helper", missing == .failed("the collector is missing from the app"))
    let t0 = Date()
    let hung = await TrustClient(helper: stub("trust-hang.sh"), timeout: 0.5).status()
    check(
        "trust: timeout kills the child (\(Date().timeIntervalSince(t0)) s)",
        hung == .failed("the collector took too long") && Date().timeIntervalSince(t0) < 5)
    let big = await TrustClient(helper: stub("trust-big.sh")).status()
    check("trust: output over 1 MiB", big == .failed("the collector printed too much"))
    let bad = await TrustClient(helper: stub("trust.sh")).call(["--bogus"])
    check(
        "trust: stderr line on bad args",
        bad == .failed("cainary-otel-debug: unexpected arguments: --bogus"))
    check(
        "trust: another v is refused",
        TrustClient.outcome(
            OneShotResult(status: 0, stdout: Data(#"{"v":2,"type":"trust"}"#.utf8), stderr: ""))
            == .failed("Update cAInary: this collector speaks a newer format."))
}

@MainActor
private func flowChecks() async {
    let dir = scratchDirectory("trust-flow")
    setenv("CAINARY_STUB_DIR", dir.path, 1)
    defer { unsetenv("CAINARY_STUB_DIR") }
    let store = TrustStore(client: TrustClient(helper: stub("trust.sh")))

    await store.refresh()
    check("trust flow: not applied at first", !store.claudeCodeApplied && store.codexCommand == nil)
    check(
        "trust flow: no-write command shown",
        store.noWriteCommand?.hasPrefix("env NODE_EXTRA_CA_CERTS=") == true && !store.caMissing)
    FileManager.default.createFile(
        atPath: dir.appendingPathComponent("noca").path, contents: Data())
    await store.refresh()
    check(
        "trust flow: no certificate yet hides the command",
        store.caMissing && store.noWriteCommand == nil)
    try? FileManager.default.removeItem(at: dir.appendingPathComponent("noca"))
    await store.refresh()
    check("trust flow: certificate back", !store.caMissing && store.noWriteCommand != nil)

    // The sheet shows the helper's preview message as it is.
    let note = "Close Claude Code first; restart it afterwards."
    check(
        "trust flow: sheet carries the message",
        TrustConfirmView(
            report: TrustReport(action: "preview", message: note), onConfirm: {}, onCancel: {}
        ).report.message == note)

    // Preview shows the sheet and writes nothing.
    await store.requestClaudeCodeTrust()
    check("trust flow: preview sets pending", store.pending?.action == "preview")
    check(
        "trust flow: only a dry run so far",
        argsLog(dir).filter { $0.contains("claude-code") } == [
            "--trust claude-code --dry-run --json"
        ])
    check(
        "trust flow: the sheet has the change",
        store.pending?.backupPath?.hasSuffix(".bak") == true
            && store.pending?.to == "/home/u/ca.pem")
    let sheet = TrustConfirmView(
        report: store.pending ?? TrustReport(action: "preview"), onConfirm: {}, onCancel: {})
    check(
        "trust flow: change line",
        sheet.changeLine == "Change: env.NODE_EXTRA_CA_CERTS: (not set) → /home/u/ca.pem")
    check(
        "trust flow: backup line",
        sheet.backupLine.hasPrefix("Backup: /home/u/.claude/settings.json.cainary-"))

    // Cancel applies nothing.
    store.cancel()
    check("trust flow: cancel clears", store.pending == nil && !store.claudeCodeApplied)
    check("trust flow: cancel wrote nothing", !argsLog(dir).contains("--trust claude-code --json"))

    // Confirm applies, then refreshes the status.
    await store.requestClaudeCodeTrust()
    await store.confirm()
    check(
        "trust flow: applied",
        argsLog(dir).contains("--trust claude-code --json") && store.pending == nil)
    check(
        "trust flow: result message",
        store.message == "Set env.NODE_EXTRA_CA_CERTS" && !store.failed)
    check("trust flow: status says applied, undo enabled", store.claudeCodeApplied)
    await store.undoClaudeCode()
    check(
        "trust flow: undone",
        argsLog(dir).contains("--trust claude-code --undo --json") && !store.claudeCodeApplied)

    // Codex: a copyable command, then Remove.
    await store.prepareCodex()
    check(
        "trust flow: codex command",
        store.codexCommand == "env CODEX_CA_CERTIFICATE=/home/u/bundle.pem codex")
    await store.removeCodex()
    check("trust flow: codex removed", store.codexCommand == nil)

    // A refusal never opens the sheet.
    FileManager.default.createFile(
        atPath: dir.appendingPathComponent("refuse").path, contents: Data())
    await store.requestClaudeCodeTrust()
    check(
        "trust flow: refusal has no sheet, says why",
        store.pending == nil && store.failed && store.message?.contains("managed") == true)
}

@MainActor
private func listenNoteChecks() {
    let hello =
        #"{"v":1,"type":"hello","ts":"T","mode":"tls-receiver","endpoint":"https://127.0.0.1:8443","tls":{"hosts":["otel.example-corp.com"],"ca":{"path":"/p/ca.pem","sha256":"ab"}},"setup":{"claudeCode":[],"codex":[],"notes":[],"takeover":["step one","step two"]}}"#
    if case .hello(let h) = CollectorEvent.decode(CollectorSamples.data(hello)) {
        check(
            "takeover hello: mode and tls",
            h.mode == "tls-receiver" && h.tls?.hosts == ["otel.example-corp.com"]
                && h.tls?.ca?.sha256 == "ab")
        check("takeover hello: steps", h.setup?.takeover == ["step one", "step two"])
    } else {
        check("takeover hello: decodes", false)
    }

    let store = CollectorStore(defaults: MemoryStore(), helper: stub("collector-hello.sh"))
    let error =
        #"{"v":1,"type":"error","ts":"T","source":"listen","message":"can't listen on 127.0.0.1:443: permission denied"}"#
    store.handle(.line(CollectorSamples.data(error)), generation: store.generation)
    store.handle(
        .exited(
            1,
            stderr:
                "cainary-otel-debug: can't listen on 127.0.0.1:443: permission denied\n  try: sudo setcap\n\u{1B}[31mx"
        ),
        generation: store.generation)
    check(
        "listen note: reason is the first line",
        store.state
            == .failed(
                "Stopped: cainary-otel-debug: can't listen on 127.0.0.1:443: permission denied"))
    check(
        "listen note: kept with its lines, escaped",
        store.failureNote
            == "cainary-otel-debug: can't listen on 127.0.0.1:443: permission denied\n  try: sudo setcap\n\\u{1B}[31mx"
    )

    let other = CollectorStore(defaults: MemoryStore(), helper: stub("collector-hello.sh"))
    other.handle(.exited(1, stderr: "boom\nmore"), generation: other.generation)
    check("listen note: only after a listen error", other.failureNote == nil)
}

/// Every real line decodes to the expected outcome, exit 1 (refused) included.
@MainActor
private func realOutputChecks() {
    var reports: [TrustReport] = []
    var statuses: [TrustStatus] = []
    for (i, sample) in TrustSamples.all.enumerated() {
        let result = OneShotResult(
            status: sample.exit, stdout: Data((sample.line + "\n").utf8), stderr: "")
        switch TrustClient.outcome(result) {
        case .report(let r): reports.append(r)
        case .status(let s): statuses.append(s)
        case .failed(let why): check("trust real: line \(i) decodes (\(why))", false)
        }
    }
    check("trust real: older status has no caExists", statuses.allSatisfy { $0.caExists == nil })
    for (exists, line) in [
        (true, TrustSamples.statusCaExists), (false, TrustSamples.statusCaMissing),
    ] {
        if case .status(let s) = TrustClient.outcome(
            OneShotResult(status: 0, stdout: Data(line.utf8), stderr: ""))
        {
            check("trust real: caExists \(exists)", s.caExists == exists)
        } else {
            check("trust real: caExists \(exists) decodes", false)
        }
    }
    check("trust real: 2 statuses and 7 reports", statuses.count == 2 && reports.count == 7)
    check(
        "trust real: actions in order",
        reports.map(\.action) == [
            "preview", "applied", "already", "refused", "undone", "nothing-to-undo",
            "nothing-to-undo",
        ])
    check(
        "trust real: absent status with nulls",
        statuses.first?.claudeCode?.state == "absent" && statuses.first?.claudeCode?.value == nil
            && statuses.first?.codex?.command == nil
            && statuses.first?.caPath == "/home/u/.local/state/cainary/otel-debug-ca.pem")
    check(
        "trust real: applied status",
        statuses.last?.claudeCode?.state == "applied" && statuses.last?.claudeCode?.value != nil)
    check(
        "trust real: preview fields",
        reports[0].from == nil && reports[0].to?.hasSuffix("otel-debug-ca.pem") == true
            && reports[0].backupPath?.hasSuffix(".bak") == true)
    check(
        "trust real: already has no backup",
        reports[2].backupPath == nil && reports[2].from == reports[2].to)
    check(
        "trust real: codex refusal has nothing else",
        reports[3].target == "codex" && reports[3].settingsPath == nil
            && reports[3].message?.contains("Start the takeover") == true)
    check("trust real: undo restores", reports[4].to == nil && reports[4].from != nil)
}

/// The Codex refusal before any takeover ran tells the user what to do, and offers no command.
@MainActor
private func codexRefusalCheck() async {
    let dir = scratchDirectory("trust-codex")
    setenv("CAINARY_STUB_DIR", dir.path, 1)
    defer { unsetenv("CAINARY_STUB_DIR") }
    FileManager.default.createFile(
        atPath: dir.appendingPathComponent("codex-refuse").path, contents: Data())
    let store = TrustStore(client: TrustClient(helper: stub("trust.sh")))
    await store.prepareCodex()
    check(
        "trust codex: refusal is shown",
        store.failed && store.message?.hasPrefix("Start the takeover once") == true)
    check("trust codex: no command offered", store.codexCommand == nil)
}

/// The fixed helper output: `caExists` and `note` are present, null notes decode.
@MainActor
private func realOutputV2Checks() {
    var statuses: [TrustStatus] = []
    var reports: [TrustReport] = []
    for (i, sample) in TrustSamples.v2.enumerated() {
        let result = OneShotResult(
            status: sample.exit, stdout: Data((sample.line + "\n").utf8), stderr: "")
        switch TrustClient.outcome(result) {
        case .report(let r): reports.append(r)
        case .status(let s): statuses.append(s)
        case .failed(let why): check("trust v2: line \(i) decodes (\(why))", false)
        }
    }
    check(
        "trust v2: statuses carry caExists and a null note",
        statuses.count == 2 && statuses.allSatisfy { $0.caExists == false && $0.note == nil })
    check(
        "trust v2: actions", reports.map(\.action) == ["preview", "applied", "undone", "refused"])
    check(
        "trust v2: preview message kept verbatim",
        reports.first?.message?.contains(
            "Close Claude Code before applying this, and restart it afterwards.") == true)
    if case .status(let s) = TrustClient.outcome(
        OneShotResult(status: 0, stdout: Data(TrustSamples.statusWithNote.utf8), stderr: ""))
    {
        check(
            "trust v2: a note decodes",
            s.note == "A previous change was interrupted; it has been cleared."
                && s.caExists == true)
    } else {
        check("trust v2: a note decodes", false)
    }
}
