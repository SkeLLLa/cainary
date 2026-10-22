import Foundation

// CoreClient against the stub helpers in Tests/stubs (macos.md §5b).

private func stub(_ name: String) -> URL {
    repoRoot().appendingPathComponent("macos/Tests/stubs/\(name)")
}

private func golden() -> String {
    repoRoot().appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json").path
}

/// A client for a stub; scan-driven stubs get the report path as the last argument.
private func client(_ name: String, deadline: TimeInterval = 20, extra: [String] = []) -> CoreClient
{
    CoreClient(helper: stub(name), extraArgs: extra, deadline: deadline)
}

/// True once `pid` is gone: a zombie would still answer `kill(pid, 0)`.
private func reaped(pidFile: URL) -> Bool {
    guard let text = try? String(contentsOf: pidFile, encoding: .utf8),
        let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
    else { return false }
    return kill(pid, 0) == -1 && errno == ESRCH
}

@MainActor
func clientTests() async {
    let dir = scratchDirectory("client")
    let isoGolden = try? Data(contentsOf: URL(fileURLWithPath: golden()))

    // A valid report decodes, and its bytes come back untouched.
    switch await client("report.sh", extra: [golden()]).scan(baseline: nil) {
    case .success(let scan):
        check("client: valid report", scan.report.schema == 3)
        check("client: raw bytes kept", scan.raw == isoGolden)
    case .failure(let error): check("client: valid report (\(error))", false)
    }

    let missing = await CoreClient(
        helper: URL(fileURLWithPath: "/nonexistent/cainary"), extraArgs: []
    )
    .scan(baseline: nil)
    check("client: missing helper", missing.failureValue == .helperMissing)

    let failed = await client("fail.sh").scan(baseline: nil)
    check("client: exit 1 with stderr", failed.failureValue == .exit(1, "boom: the scanner broke"))
    let future = await client("schema4.sh").scan(baseline: nil)
    check("client: schema 4", future.failureValue == .schema(4))
    let bigOut = await client("bigout.sh").scan(baseline: nil)
    check("client: 9 MiB of stdout", bigOut.failureValue == .outputTooLarge)
    let bigErr = await client("bigerr.sh").scan(baseline: nil)
    check("client: 1 MiB of stderr", bigErr.failureValue == .outputTooLarge)

    // Draining the pipes one after the other would deadlock on these.
    for name in ["err-before.sh", "err-after.sh"] {
        switch await client(name, extra: [golden()]).scan(baseline: nil) {
        case .success(let scan): check("client: \(name) decodes", scan.report.schema == 3)
        case .failure(let error): check("client: \(name) decodes (\(error))", false)
        }
    }

    // The helper exits without reading 200 KiB of stdin: no hang, no SIGPIPE.
    let big = Data(repeating: 0x20, count: 200 << 10)
    switch await client("exit-noread.sh", extra: [golden()]).scan(baseline: big) {
    case .success(let scan): check("client: unread stdin", scan.report.schema == 3)
    case .failure(let error): check("client: unread stdin (\(error))", false)
    }

    // The baseline arrives intact.
    let baseline = Data((0..<300_000).map { UInt8($0 % 251) })
    switch await client("stdin-count.sh").run([], stdin: baseline) {
    case .success(let output):
        check(
            "client: stdin byte count",
            String(decoding: output.stdout, as: UTF8.self) == "\(baseline.count)")
    case .failure(let error): check("client: stdin byte count (\(error))", false)
    }

    // One second of deadline, each case done and reaped well inside 4 s.
    for name in ["trap-term.sh", "descendant.sh", "exit-open.sh"] {
        let pidFile = dir.appendingPathComponent("\(name).pid")
        let started = Date()
        let result = await client(name, deadline: 1).run([pidFile.path], stdin: nil)
        let elapsed = Date().timeIntervalSince(started)
        check("client: \(name) timed out", result.failureValue == .timedOut)
        check("client: \(name) elapsed \(elapsed)", elapsed < 4)
        check("client: \(name) reaped", reaped(pidFile: pidFile))
    }
}

extension Result {
    /// The error, if it failed.
    var failureValue: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
