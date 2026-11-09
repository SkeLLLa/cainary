import Foundation

// The opt-in OTel debug collector: the line contract, the settings it
// turns into argv and a stdin config, the child process client with stub collectors, and the
// store's retention, throttle and failure handling.

private func stub(_ name: String) -> URL {
    repoRoot().appendingPathComponent("macos/Tests/stubs/\(name)")
}

/// True once `pid` is gone: a zombie would still answer `kill(pid, 0)`.
private func gone(pidFile: URL) -> Bool {
    guard let text = try? String(contentsOf: pidFile, encoding: .utf8),
        let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
    else { return false }
    return kill(pid, 0) == -1 && errno == ESRCH
}

/// Waits for `condition`, then records the check.
@MainActor
private func eventually(_ name: String, _ condition: () -> Bool) async {
    let ok = await waitFor(5, condition)
    check(name, ok)
}

@MainActor
private func waitFor(_ seconds: TimeInterval = 5, _ condition: () -> Bool) async -> Bool {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(20))
    }
    return condition()
}

private final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [CollectorClient.Event] = []

    func add(_ event: CollectorClient.Event) {
        lock.lock()
        items.append(event)
        lock.unlock()
    }

    var all: [CollectorClient.Event] {
        lock.lock()
        defer { lock.unlock() }
        return items
    }

    var lines: [String] {
        all.compactMap {
            if case .line(let data) = $0 { return String(decoding: data, as: UTF8.self) }
            return nil
        }
    }
}

@MainActor
private final class RecordingPoster: AlertPosting {
    private(set) var posted: [(title: String, body: String, id: String)] = []

    func post(title: String, body: String, identifier: String) async {
        posted.append((title, body, identifier))
    }
}

private func lines(_ path: URL) -> [String] {
    ((try? String(contentsOf: path, encoding: .utf8)) ?? "")
        .split(separator: "\n").map(String.init)
}

@MainActor
func collectorTests() async {
    decodingTests()
    settingsTests()
    await clientTests2()
    await storeRetentionTests()
    await storeProcessTests()
    await storeStateTests()
}

// MARK: - Line contract

@MainActor
private func decodingTests() {
    if case .hello(let hello) = CollectorEvent.decode(CollectorSamples.data(CollectorSamples.hello))
    {
        check("collector: hello endpoint", hello.endpoint == "http://127.0.0.1:4318")
        check("collector: hello setup", hello.setup?.claudeCode?.count == 4)
        check(
            "collector: hello codex line keeps quotes",
            hello.setup?.codex?.first?.contains("\"json\"") == true)
        check("collector: hello logFile null", hello.logFile == nil)
    } else {
        check("collector: hello decodes", false)
    }

    if case .batch(let batch) = CollectorEvent.decode(CollectorSamples.data(CollectorSamples.batch))
    {
        check(
            "collector: batch fields",
            batch.signal == "logs" && batch.records == 12 && batch.notInCatalog == 1)
        check("collector: batch service", batch.service?.version == "2.1.316")
        let record = batch.summary?.records?.first
        check(
            "collector: batch record",
            record?.name == "claude_code.tool_result" && record?.count == 3)
        check(
            "collector: batch attr group and flag",
            record?.attrs?.first?.flag == "OTEL_LOG_TOOL_DETAILS")
        check(
            "collector: unknown attr",
            record?.attrs?.last?.known == false && record?.attrs?.last?.group == nil)
        let raw = CollectorBatch.rawResources(in: CollectorSamples.data(CollectorSamples.batch))
        check("collector: raw resources", raw?.contains("<string, 5 chars>") == true)
    } else {
        check("collector: batch decodes", false)
    }

    if case .alert(let alert) = CollectorEvent.decode(CollectorSamples.data(CollectorSamples.alert))
    {
        check(
            "collector: alert",
            alert.pattern == "aws-access-key" && alert.place == "value" && alert.count == 2)
        check("collector: alert match", alert.match == "AKI…(20 chars)")
    } else {
        check("collector: alert decodes", false)
    }

    if case .error(let error) = CollectorEvent.decode(CollectorSamples.data(CollectorSamples.error))
    {
        check("collector: error", error.source == "http" && error.status == 415)
    } else {
        check("collector: error decodes", false)
    }

    // Unknown error.source, unknown keys and unknown types are tolerated.
    let future =
        #"{"v":1,"type":"error","ts":"T","source":"red-flags","message":"m","extra":[1,2]}"#
    if case .error(let error) = CollectorEvent.decode(CollectorSamples.data(future)) {
        check("collector: unknown error.source", error.source == "red-flags")
    } else {
        check("collector: unknown error.source decodes", false)
    }
    check(
        "collector: unknown type ignored",
        CollectorEvent.decode(CollectorSamples.data(CollectorSamples.future)) == .ignored)
    check(
        "collector: v 2 refused",
        CollectorEvent.decode(CollectorSamples.data(CollectorSamples.version2))
            == .unsupported(version: 2))
    check("collector: garbage ignored", CollectorEvent.decode(Data("not json".utf8)) == .ignored)
    check(
        "collector: no v ignored",
        CollectorEvent.decode(Data(#"{"type":"hello"}"#.utf8)) == .ignored)
    check(
        "collector: sparse batch decodes",
        CollectorEvent.decode(Data(#"{"v":1,"type":"batch"}"#.utf8))
            == .batch(CollectorBatch()))

    check(
        "collector: plainText escapes ESC",
        "a\u{1B}]52;c;x\u{7}b".plainText == "a\\u{1B}]52;c;x\\u{7}b")
    check(
        "collector: plainText escapes bidi and CR",
        "x\u{202E}y\rz".plainText == "x\\u{202E}y\\u{D}z")
    check("collector: plainText keeps text", "Red flag: café ✓".plainText == "Red flag: café ✓")
}

// MARK: - Settings

@MainActor
private func settingsTests() {
    let mem = MemoryStore()
    let defaults = mem.collectorSettings
    check("collector settings: off by default", !defaults.enabled)
    check("collector settings: default port", defaults.port == 4318)
    check("collector settings: default presets", defaults.presets == CollectorPreset.defaultOnNames)
    check("collector settings: ipv4 off by default", !defaults.presets.contains("ipv4"))
    check("collector settings: notify on by default", defaults.notify)
    check("collector settings: no log file by default", defaults.effectiveLogPath == nil)

    var s = CollectorSettings()
    s.enabled = true
    s.port = 4400
    s.logToFile = true
    s.logPath = "~/logs/otel.jsonl"
    s.presets = ["email", "ipv4"]
    s.patterns = [
        CollectorPattern(
            name: "customer", kind: "text", pattern: "acme-internal", caseSensitive: false),
        CollectorPattern(
            name: "db", kind: "regex", pattern: #"\bdb-[0-9]+\b"#, caseSensitive: true),
        CollectorPattern(name: "", kind: "text", pattern: "half typed"),
    ]
    mem.collectorSettings = s
    let back = mem.collectorSettings
    check("collector settings: round trip", back.enabled && back.port == 4400 && back.logToFile)
    check("collector settings: presets round trip", back.presets == ["email", "ipv4"])
    check(
        "collector settings: patterns round trip",
        back.patterns.map(\.name) == ["customer", "db", ""] && back.patterns[1].isRegex
            && back.patterns[1].caseSensitive)
    mem.set(70000, forKey: PrefKey.otelCollectorPort)
    check("collector settings: port clamped", mem.collectorSettings.port == 65535)
    mem.set(80, forKey: PrefKey.otelCollectorPort)
    check("collector settings: low port clamped", mem.collectorSettings.port == 1024)

    // argv has no pattern text; the config line has it.
    let args = s.arguments
    check(
        "collector settings: argv",
        Array(args.prefix(4)) == ["--json", "--config-stdin", "--port", "4400"])
    check(
        "collector settings: argv log file expanded",
        args.suffix(2).first == "--log-file" && !(args.last ?? "~").hasPrefix("~"))
    check(
        "collector settings: no pattern in argv",
        !args.joined(separator: " ").contains("acme-internal"))
    if let line = s.configLine,
        let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any]
    {
        check("collector settings: one line", !line.contains(0x0A))
        check("collector settings: config v", object["v"] as? Int == 1)
        let flags = object["redFlags"] as? [[String: Any]] ?? []
        check("collector settings: half-typed row skipped", flags.count == 2)
        check(
            "collector settings: flag fields",
            flags.first?["pattern"] as? String == "acme-internal"
                && flags.first?["kind"] as? String == "text"
                && flags.last?["caseSensitive"] as? Bool == true)
        let presets = object["presets"] as? [String: Bool] ?? [:]
        check(
            "collector settings: presets map",
            presets["email"] == true && presets["jwt"] == false
                && presets["ipv4"] == true && presets.count == CollectorPreset.all.count)
    } else {
        check("collector settings: config line parses", false)
    }
    validationTests()
}

@MainActor
private func validationTests() {
    func row(_ name: String, _ pattern: String = "x") -> CollectorPattern {
        CollectorPattern(name: name, pattern: pattern)
    }
    var s = CollectorSettings()
    s.patterns = [
        row("good"), row("good"), row("Bad"), row("-bad"), row("email"), row("empty", ""),
        row("long", String(repeating: "x", count: 1025)),
        row("max", String(repeating: "x", count: 1024)),
        row(String(repeating: "a", count: 65)), row(String(repeating: "a", count: 64)),
        row("", ""), row("", "pattern without name"),
    ]
    let problems = s.patterns.indices.map { s.problem(at: $0) != nil }
    check(
        "collector validation: which rows are invalid",
        problems == [false, true, true, true, true, true, true, false, true, false, false, true])
    check("collector validation: blank row is not an error", s.problem(at: 10) == nil)
    check(
        "collector validation: only valid rows are sent",
        s.validPatterns.map(\.name) == ["good", "max", String(repeating: "a", count: 64)])
    if let line = s.configLine,
        let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any]
    {
        check(
            "collector validation: config skips invalid rows",
            (object["redFlags"] as? [Any])?.count == 3)
    } else {
        check("collector validation: config still built", false)
    }
    check(
        "collector validation: name rule",
        CollectorPattern.validName("a_b-9") && !CollectorPattern.validName("_a")
            && !CollectorPattern.validName("a.b") && !CollectorPattern.validName("é"))

    // 64 flags in all, presets included.
    var t = CollectorSettings()
    t.presets = ["email", "jwt"]
    t.patterns = (0..<62).map { row("p\($0)") }
    check("collector validation: 64 is allowed", !t.overLimit && t.configLine != nil)
    t.patterns.append(row("one-more"))
    check("collector validation: 65 is refused", t.overLimit && t.configLine == nil)
}

// MARK: - Client

@MainActor
private func clientTests2() async {
    let dir = scratchDirectory("collector-client")
    let pidFile = dir.appendingPathComponent("pid")
    let configFile = dir.appendingPathComponent("config")
    setenv("CAINARY_STUB_PIDFILE", pidFile.path, 1)
    setenv("CAINARY_STUB_CONFIG", configFile.path, 1)
    setenv("CAINARY_STUB_ARGS", dir.appendingPathComponent("args").path, 1)

    // Lines arrive in order, the config arrives on stdin, stop closes stdin and reaps.
    let events = Events()
    let config = Data(#"{"v":1,"redFlags":[],"presets":{}}"#.utf8)
    let client = CollectorClient(
        helper: stub("collector-hello.sh"), args: ["--json", "--config-stdin"], config: config,
        onEvent: { events.add($0) })
    client.start()
    await eventually("collector client: lines arrive") { events.lines.count == 2 }
    check("collector client: hello first", events.lines.first?.contains("\"hello\"") == true)
    check(
        "collector client: config on stdin",
        lines(configFile) == [String(decoding: config, as: UTF8.self)])
    check(
        "collector client: argv",
        lines(dir.appendingPathComponent("args")) == ["--json --config-stdin"])
    check("collector client: still running", !gone(pidFile: pidFile))
    let started = Date()
    await Task.detached { client.stop(grace: 2) }.value
    check(
        "collector client: stop is quick (\(Date().timeIntervalSince(started)) s)",
        Date().timeIntervalSince(started) < 1.5)
    check("collector client: stop reaps", gone(pidFile: pidFile))
    try? await Task.sleep(for: .milliseconds(200))
    check(
        "collector client: stop is not reported as an exit",
        !events.all.contains { if case .exited = $0 { return true } else { return false } })
    await Task.detached { client.stop(grace: 1) }.value  // twice is fine

    // A child that ignores SIGTERM and stdin EOF is killed after the grace.
    let stubborn = Events()
    let pid2 = dir.appendingPathComponent("pid2")
    setenv("CAINARY_STUB_PIDFILE", pid2.path, 1)
    let hard = CollectorClient(
        helper: stub("collector-ignore-term.sh"), args: [], config: config,
        onEvent: { stubborn.add($0) })
    hard.start()
    await eventually("collector client: stubborn starts") { stubborn.lines.count == 1 }
    let t0 = Date()
    await Task.detached { hard.stop(grace: 0.3) }.value
    check(
        "collector client: SIGKILL after the grace (\(Date().timeIntervalSince(t0)) s)",
        Date().timeIntervalSince(t0) < 3)
    check("collector client: stubborn child reaped", gone(pidFile: pid2))

    // An oversize line kills the child and says so; no exit follows.
    let big = Events()
    let pid3 = dir.appendingPathComponent("pid3")
    setenv("CAINARY_STUB_PIDFILE", pid3.path, 1)
    let wide = CollectorClient(
        helper: stub("collector-big.sh"), args: [], config: config, maxLine: 1024,
        onEvent: { big.add($0) })
    wide.start()
    await eventually("collector client: oversize reported") { big.all.contains(.oversize) }
    await eventually("collector client: oversize kills the child") { gone(pidFile: pid3) }
    check("collector client: no giant line delivered", big.lines.count == 1)
    await Task.detached { wide.stop(grace: 1) }.value

    // An exit on its own carries the stderr.
    let exited = Events()
    let quitter = CollectorClient(
        helper: stub("collector-exit.sh"), args: [], config: config, onEvent: { exited.add($0) })
    quitter.start()
    await eventually("collector client: exit with stderr") {
        exited.all.contains {
            if case .exited(1, let err) = $0 { return err.contains("address in use") }
            return false
        }
    }

    // A missing helper never starts.
    let missing = Events()
    CollectorClient(
        helper: URL(fileURLWithPath: "/nonexistent/cainary-otel-debug"), args: [], config: config,
        onEvent: { missing.add($0) }
    ).start()
    check(
        "collector client: missing helper",
        missing.all.contains { if case .failed = $0 { return true } else { return false } })
    unsetenv("CAINARY_STUB_PIDFILE")
    unsetenv("CAINARY_STUB_CONFIG")
    unsetenv("CAINARY_STUB_ARGS")
}

// MARK: - Store, fed events directly

@MainActor
private func storeRetentionTests() async {
    let poster = RecordingPoster()
    var clock = Date(timeIntervalSince1970: 1_000_000)
    let store = CollectorStore(
        defaults: MemoryStore(), poster: poster, helper: stub("collector-hello.sh"), now: { clock })
    func feed(_ line: String) {
        store.handle(.line(CollectorSamples.data(line)), generation: store.generation)
    }

    feed(CollectorSamples.hello)
    if case .listening(let hello) = store.state {
        check("collector store: listening", hello.endpoint == "http://127.0.0.1:4318")
    } else {
        check("collector store: listening", false)
    }
    feed(CollectorSamples.future)
    feed("garbage")
    feed(CollectorSamples.error)
    check("collector store: unknown lines skipped", store.batches.isEmpty && store.alerts.isEmpty)
    check(
        "collector store: error message kept",
        store.errors.first?.message?.plainText == "protobuf is not supported")

    for _ in 0..<60 { feed(CollectorSamples.batch) }
    check("collector store: last 50 batches", store.batches.count == 50 && store.batchTotal == 60)
    check(
        "collector store: batch ids grow",
        (store.batches.last?.id ?? 0) > (store.batches.first?.id ?? 0))
    for _ in 0..<250 { feed(CollectorSamples.alert) }
    check("collector store: last 200 alerts", store.alerts.count == 200 && store.alertTotal == 250)

    // The 16 MiB bound: 2 MiB lines.
    let pad = String(repeating: "x", count: 2 << 20)
    let fat = CollectorSamples.batch.replacingOccurrences(
        of: #""type":"batch""#, with: #""type":"batch","pad":"\#(pad)""#)
    for _ in 0..<12 { feed(fat) }
    let bytes =
        store.batches.reduce(0) { $0 + $1.line.count }
        + store.alerts.reduce(0) { $0 + $1.lineBytes }
    check(
        "collector store: under 16 MiB (\(bytes))",
        bytes <= CollectorStore.maxRetainedBytes && store.batches.count >= 1)

    // Throttle: one notification per pattern per 60 s.
    func notified() async -> Int {
        try? await Task.sleep(for: .milliseconds(50))
        return poster.posted.count
    }
    func checkCount(_ name: String, _ expected: Int) async {
        let n = await notified()
        check("\(name) (\(n))", n == expected)
    }
    let before = await notified()
    clock = Date(timeIntervalSince1970: 2_000_000)
    feed(CollectorSamples.alert)
    feed(CollectorSamples.alert)
    await checkCount("collector store: one notification per pattern", before + 1)
    let other = CollectorSamples.alert.replacingOccurrences(of: "aws-access-key", with: "customer")
    feed(other)
    await checkCount("collector store: another pattern notifies", before + 2)
    clock = clock.addingTimeInterval(30)
    feed(CollectorSamples.alert)
    await checkCount("collector store: still throttled at 30 s", before + 2)
    clock = clock.addingTimeInterval(31)
    feed(CollectorSamples.alert)
    await checkCount("collector store: notifies again after 60 s", before + 3)
    if let last = poster.posted.first {
        check("collector store: notification title", last.title == "Red flag: aws-access-key")
        check(
            "collector store: notification body",
            last.body == "claude_code.tool_result · tool_input (AKI…(20 chars))")
        check(
            "collector store: notification opens the pane",
            last.id.hasPrefix(CollectorStore.notificationPrefix))
    } else {
        check("collector store: notification posted", false)
    }

    // Failures.
    feed(CollectorSamples.version2)
    if case .failed(let reason) = store.state {
        check("collector store: v 2 says update", reason.contains("Update cAInary"))
    } else {
        check("collector store: v 2 fails", false)
    }
    store.handle(.oversize, generation: store.generation)
    check("collector store: oversize", store.state == .failed("Stopped: output too large."))

    let other2 = CollectorStore(
        defaults: MemoryStore(), poster: poster, helper: stub("collector-hello.sh"))
    other2.handle(.exited(1, stderr: "bind: address in use\nsecond"), generation: other2.generation)
    check(
        "collector store: exit shows the first stderr line",
        other2.state == .failed("Stopped: bind: address in use"))
    let third = CollectorStore(
        defaults: MemoryStore(), poster: poster, helper: stub("collector-hello.sh"))
    third.handle(.exited(3, stderr: "\u{1B}[31mred"), generation: third.generation)
    check("collector store: stderr is escaped", third.state == .failed("Stopped: \\u{1B}[31mred"))
    third.handle(
        .line(CollectorSamples.data(CollectorSamples.hello)), generation: third.generation + 1)
    check(
        "collector store: late events from an old child are dropped",
        third.state == .failed("Stopped: \\u{1B}[31mred"))

    // Notifications can be switched off.
    let quiet = MemoryStore()
    var qs = CollectorSettings()
    qs.notify = false
    quiet.collectorSettings = qs
    let silent = RecordingPoster()
    let q = CollectorStore(defaults: quiet, poster: silent, helper: stub("collector-hello.sh"))
    q.handle(.line(CollectorSamples.data(CollectorSamples.alert)), generation: q.generation)
    try? await Task.sleep(for: .milliseconds(50))
    check("collector store: notify off posts nothing", silent.posted.isEmpty && q.alertTotal == 1)
}

// MARK: - Store with a real child

@MainActor
private func storeProcessTests() async {
    let dir = scratchDirectory("collector-store")
    let pidFile = dir.appendingPathComponent("pid")
    let argsFile = dir.appendingPathComponent("args")
    let configFile = dir.appendingPathComponent("config")
    setenv("CAINARY_STUB_PIDFILE", pidFile.path, 1)
    setenv("CAINARY_STUB_ARGS", argsFile.path, 1)
    setenv("CAINARY_STUB_CONFIG", configFile.path, 1)

    let mem = MemoryStore()
    var s = CollectorSettings()
    s.enabled = true
    s.startAtLaunch = true
    s.patterns = [CollectorPattern(name: "customer", pattern: "acme-internal")]
    mem.collectorSettings = s
    let store = CollectorStore(
        defaults: mem, poster: nil, helper: stub("collector-hello.sh"),
        restartDelay: .milliseconds(30))
    func listening() -> Bool {
        if case .listening = store.state { return true }
        return false
    }

    store.launchAtStartIfWanted()
    await eventually("collector store: starts when enabled") { listening() }
    check(
        "collector store: argv has no pattern",
        lines(argsFile) == ["--json --config-stdin --port 4318"])
    check(
        "collector store: config has the pattern",
        lines(configFile).first?.contains("acme-internal") == true)

    // Changing the port restarts it; typing in several fields restarts once.
    var moved = store.settings
    moved.port = 4400
    store.apply(moved)
    moved.port = 4401
    store.apply(moved)
    await eventually("collector store: restart on a setting change") {
        lines(argsFile).count == 2 && listening()
    }
    check(
        "collector store: restart uses the new port",
        lines(argsFile).last == "--json --config-stdin --port 4401")
    try? await Task.sleep(for: .milliseconds(200))
    check("collector store: one restart for two edits", lines(argsFile).count == 2)

    // A change that doesn't reach the child doesn't restart it.
    var quiet = store.settings
    quiet.notify = false
    store.apply(quiet)
    try? await Task.sleep(for: .milliseconds(200))
    check(
        "collector store: notify change keeps the child", lines(argsFile).count == 2 && listening())

    // Off stops and reaps.
    var off = store.settings
    off.enabled = false
    store.apply(off)
    check("collector store: off", store.state == .off)
    await eventually("collector store: off reaps the child") { gone(pidFile: pidFile) }
    check("collector store: the toggle is saved", !mem.collectorSettings.enabled)

    // Retry after a failure.
    let crashed = CollectorStore(
        defaults: mem, poster: nil, helper: stub("collector-exit.sh"),
        restartDelay: .milliseconds(30))
    var on = CollectorSettings()
    on.enabled = true
    crashed.apply(on)
    await eventually("collector store: crash shows stderr") {
        crashed.state == .failed("Stopped: cainary-otel-debug: bind 127.0.0.1:4318: address in use")
    }
    crashed.retry()
    check("collector store: retry starts again", crashed.state == .starting)
    crashed.stopForQuit()
    check("collector store: quit stops", crashed.state == .off)

    // Quit stops synchronously, within the 1 s budget.
    let again = CollectorStore(
        defaults: mem, poster: nil, helper: stub("collector-hello.sh"),
        restartDelay: .milliseconds(30))
    again.start()
    await eventually("collector store: listens again") {
        if case .listening = again.state { return true }
        return false
    }
    let t0 = Date()
    again.stopForQuit()
    check(
        "collector store: quit within the budget (\(Date().timeIntervalSince(t0)) s)",
        Date().timeIntervalSince(t0) < 1.5)
    check("collector store: quit reaps", gone(pidFile: pidFile))

    unsetenv("CAINARY_STUB_PIDFILE")
    unsetenv("CAINARY_STUB_ARGS")
    unsetenv("CAINARY_STUB_CONFIG")
}

// MARK: - Errors, failure, flags, pause

/// A store with no real child: events are fed by hand. `start()` leaves it `.starting` until the
/// test stops it, so nothing is spawned.
@MainActor
private func fedStore(
    settings: CollectorSettings = CollectorSettings(), defaults: MemoryStore = MemoryStore()
) -> CollectorStore {
    defaults.collectorSettings = settings
    return CollectorStore(
        defaults: defaults, helper: URL(fileURLWithPath: "/nonexistent/collector"))
}

@MainActor
private func storeStateTests() async {
    func feed(_ store: CollectorStore, _ line: String) {
        store.handle(.line(CollectorSamples.data(line)), generation: store.generation)
    }

    // Errors: newest 20, newest first, with the new fields.
    let errs = fedStore()
    feed(errs, CollectorSamples.hello)
    for _ in 0..<25 { feed(errs, CollectorSamples.error) }
    feed(errs, CollectorSamples.errorTLSCount)
    check("collector state: errors capped at 20", errs.errors.count == 20)
    check("collector state: newest error first", errs.errors.first?.count == 3)

    // A startup error with a code becomes the failure when the child exits.
    let port = fedStore()
    port.start()
    feed(port, CollectorSamples.errorPortInUse)
    port.handle(
        .exited(1, stderr: "cainary-otel-debug: listen failed\nsecond\u{1b}[31m line\n"),
        generation: port.generation)
    check(
        "collector state: port-in-use failure",
        port.failure
            == CollectorFailure(
                code: "port-in-use", port: 4318, message: "127.0.0.1:4318 is already in use"))
    var isFailed = false
    if case .failed = port.state { isFailed = true }
    check("collector state: failed state", isFailed)
    check(
        "collector state: stderr tail is safe",
        port.stderrTail == ["cainary-otel-debug: listen failed", "second\\u{001B}[31m line"])
    port.stop()

    let host = fedStore()
    host.start()
    feed(host, CollectorSamples.errorTLSNoHost)
    host.handle(.exited(2, stderr: ""), generation: host.generation)
    check(
        "collector state: tls-no-host failure",
        host.failure?.code == "tls-no-host" && host.failure?.port == nil)
    host.stop()

    // Without a startup error the first stderr line, then the exit status, is the message.
    let bare = fedStore()
    bare.start()
    bare.handle(.exited(3, stderr: "boom\n"), generation: bare.generation)
    check(
        "collector state: stderr line is the message",
        bare.failure == CollectorFailure(code: nil, port: nil, message: "boom"))
    bare.stop()
    let status = fedStore()
    status.start()
    status.handle(.exited(3, stderr: ""), generation: status.generation)
    check(
        "collector state: exit status is the message",
        status.failure?.message == "exited with code 3.")
    status.stop()

    // An error after hello is not a startup error.
    let late = fedStore()
    late.start()
    feed(late, CollectorSamples.hello)
    feed(late, CollectorSamples.errorPortInUse)
    late.handle(.exited(1, stderr: "gone"), generation: late.generation)
    check("collector state: late error is no startup error", late.failure?.code == nil)
    late.stop()

    // A new start clears the failure, errors and stderr; hello clears it too.
    let again = fedStore()
    again.start()
    feed(again, CollectorSamples.errorPortInUse)
    again.handle(.exited(1, stderr: "x"), generation: again.generation)
    check("collector state: failure set", again.failure != nil && !again.stderrTail.isEmpty)
    again.retry()
    check(
        "collector state: start clears failure",
        again.failure == nil && again.errors.isEmpty && again.stderrTail.isEmpty)
    feed(again, CollectorSamples.hello)
    check("collector state: listening after retry", again.failure == nil)
    again.stop()

    // The stderr tail keeps the last 50 lines.
    let many = fedStore()
    many.start()
    many.handle(
        .exited(1, stderr: (1...80).map { "line \($0)" }.joined(separator: "\n")),
        generation: many.generation)
    check(
        "collector state: stderr tail is 50 lines",
        many.stderrTail.count == 50 && many.stderrTail.first == "line 31"
            && many.stderrTail.last == "line 80")
    many.stop()

    // Settings that can't run fail with the settings code.
    var bad = CollectorSettings()
    bad.takeover = true
    let blocked = fedStore(settings: bad)
    blocked.start()
    check(
        "collector state: settings problem is a failure",
        blocked.failure?.code == "tls-no-host" && blocked.failure?.port == nil)

    // Unseen flags.
    let flags = fedStore()
    feed(flags, CollectorSamples.hello)
    check("collector flags: none yet", flags.flagCount == 0 && flags.unseenFlagCount == 0)
    for _ in 0..<3 { feed(flags, CollectorSamples.alert) }
    check("collector flags: unseen counts", flags.flagCount == 3 && flags.unseenFlagCount == 3)
    flags.markFlagsSeen()
    check("collector flags: marked seen", flags.unseenFlagCount == 0 && flags.flagCount == 3)
    feed(flags, CollectorSamples.alert)
    check("collector flags: new one is unseen", flags.unseenFlagCount == 1)
    flags.clearFeed()
    check(
        "collector flags: clear leaves nothing unseen",
        flags.unseenFlagCount == 0 && flags.alerts.isEmpty && flags.flagCount == 4)
    flags.stop()
    flags.start()
    check("collector flags: start resets", flags.flagCount == 0 && flags.unseenFlagCount == 0)
    flags.stop()

    // Pause holds rows; resume merges them; clear empties everything.
    let feedStore = fedStore()
    feed(feedStore, CollectorSamples.hello)
    feed(feedStore, CollectorSamples.batch)
    check(
        "collector pause: live before the pause",
        feedStore.feedBatches.count == 1 && feedStore.heldCount == 0)
    feedStore.pause()
    check("collector pause: paused", feedStore.paused)
    feed(feedStore, CollectorSamples.batchProtobufGzip)
    feed(feedStore, CollectorSamples.alert)
    check(
        "collector pause: rows held",
        feedStore.feedBatches.count == 1 && feedStore.feedAlerts.isEmpty
            && feedStore.heldCount == 2)
    check(
        "collector pause: data and counts keep coming",
        feedStore.batches.count == 2 && feedStore.alerts.count == 1
            && feedStore.unseenFlagCount == 1)
    feedStore.pause()
    check("collector pause: pausing twice keeps the cut", feedStore.heldCount == 2)
    feedStore.resume()
    check(
        "collector pause: resume merges",
        !feedStore.paused && feedStore.feedBatches.count == 2 && feedStore.feedAlerts.count == 1
            && feedStore.heldCount == 0)
    feedStore.togglePause()
    feed(feedStore, CollectorSamples.batch)
    check("collector pause: toggle pauses", feedStore.paused && feedStore.heldCount == 1)
    feedStore.clearFeed()
    check(
        "collector pause: clear empties held rows too",
        feedStore.feedBatches.isEmpty && feedStore.heldCount == 0 && feedStore.paused)
    feed(feedStore, CollectorSamples.batch)
    check("collector pause: still paused after clear", feedStore.heldCount == 1)
    feedStore.togglePause()
    check("collector pause: toggle resumes", feedStore.feedBatches.count == 1)

    // Launch at start.
    var wanted = CollectorSettings()
    wanted.startAtLaunch = true
    let launch = fedStore(settings: wanted)
    launch.launchAtStartIfWanted()
    check(
        "collector launch: starts and turns on",
        launch.state == .starting && launch.settings.enabled)
    check("collector launch: persists enabled", launch.settings.enabled)
    launch.stop()

    let off = fedStore()
    off.launchAtStartIfWanted()
    check("collector launch: not wanted stays off", off.state == .off)

    var broken = wanted
    broken.takeover = true
    let problem = fedStore(settings: broken)
    problem.launchAtStartIfWanted()

    // Not wanted at launch: a saved "enabled" is cleared and persisted, so a later change
    // doesn't start it through the restart path.
    var stale = CollectorSettings()
    stale.enabled = true
    let staleDefaults = MemoryStore()
    let staleStore = fedStore(settings: stale, defaults: staleDefaults)
    staleStore.launchAtStartIfWanted()
    check(
        "collector launch: not wanted clears enabled",
        !staleStore.settings.enabled && staleStore.state == .off)
    check(
        "collector launch: cleared enabled is persisted",
        !staleDefaults.collectorSettings.enabled)
    var edited = staleStore.settings
    edited.port = 4500
    staleStore.apply(edited)
    check("collector launch: a later edit stays off", staleStore.state == .off)

    // A settings problem is shown, not swallowed.
    check(
        "collector launch: a settings problem is a failure",
        problem.failure?.code == "tls-no-host" && problem.state != .off)

    // The takeover port can't be below 1024 on macOS.
    check(
        "takeover port: range starts at 1024",
        CollectorSettings.takeoverPortRange == 1024...65535)
    var lowPort = CollectorSettings()
    lowPort.takeover = true
    lowPort.takeoverHosts = ["otel.example-corp.com"]
    lowPort.takeoverPort = 443
    check(
        "takeover port: 443 is a problem",
        lowPort.problem?.code == .portRange && lowPort.problem?.message.contains("1024") == true)
    lowPort.takeoverPort = 1024
    check("takeover port: 1024 is fine", lowPort.problem == nil)
    var atTop = lowPort
    atTop.takeoverPort = 65535
    check(
        "takeover port: no next port past 65535",
        FailureAdvice.tryNextPort(
            CollectorFailure(code: "port-in-use", port: 65535, message: "x"), in: atTop) == nil)
    check(
        "takeover port: next port within range",
        FailureAdvice.tryNextPort(
            CollectorFailure(code: "port-in-use", port: 1024, message: "x"), in: lowPort)?.port
            == 1025)

    // A failure without a port falls back to the effective port.
    let noPort = CollectorFailure(code: "port-in-use", port: nil, message: "x")
    check(
        "try port: HTTP port when no takeover",
        FailureAdvice.tryNextPort(noPort, in: CollectorSettings())?.settings.port == 4319)
    check(
        "try port: takeover port in takeover mode",
        FailureAdvice.tryNextPort(noPort, in: lowPort)?.settings.takeoverPort == 1025)

    // Where each failure's fix lives.
    let patterns = CollectorFailure(code: "patterns", port: nil, message: "Too many.")
    check(
        "failure advice: patterns go to Rules",
        FailureAdvice(patterns).fix == .rules && FailureAdvice(patterns).message.contains("Rules")
            && !FailureAdvice(patterns).message.contains("Red flags"))
    let inUse = CollectorFailure(code: "port-in-use", port: 8443, message: "x")
    check(
        "failure advice: takeover port goes to Setup",
        FailureAdvice(inUse, takeover: true).fix == .setup
            && FailureAdvice(inUse, takeover: true).message.contains("Setup")
            && FailureAdvice(inUse).fix == .settings)

    // A TLS hello is counted (the trust status refreshes on each); a plain one isn't.
    let tlsHello = fedStore()
    feed(tlsHello, CollectorSamples.hello)
    check("collector tls hello: plain hello not counted", tlsHello.tlsHelloCount == 0)
    feed(
        tlsHello,
        #"{"v":1,"type":"hello","ts":"T","mode":"tls-receiver","endpoint":"https://127.0.0.1:8443"}"#
    )
    feed(
        tlsHello,
        #"{"v":1,"type":"hello","ts":"T","mode":"tls-receiver","endpoint":"https://127.0.0.1:8443"}"#
    )
    check("collector tls hello: each one counted", tlsHello.tlsHelloCount == 2)
}
