import Foundation

// One-shot `cainary-otel-debug --trust …` and `--trust-status` calls (design §17). Each prints one
// JSON line (v1). The only file the helper edits is `env.NODE_EXTRA_CA_CERTS` in the user's
// `~/.claude/settings.json`, after a backup, and only when the user confirms.

/// A `{"type":"trust"}` line. Every field but `action` may be absent.
struct TrustReport: Codable, Equatable, Sendable {
    var target: String?
    /// `preview`, `applied`, `already`, `undone`, `nothing-to-undo` or `refused`; open.
    var action: String
    var message: String?
    var settingsPath: String?
    var backupPath: String?
    var key: String?
    var from: String?
    var to: String?
    var bundlePath: String?
    var command: String?
}

/// A `{"type":"trust-status"}` line.
struct TrustStatus: Codable, Equatable, Sendable {
    struct ClaudeCode: Codable, Equatable, Sendable {
        /// `applied`, `absent`, `other-value` or `managed`; open.
        var state: String
        var settingsPath: String?
        var value: String?
    }
    struct Codex: Codable, Equatable, Sendable {
        /// `ready` or `absent`; open.
        var state: String
        var bundlePath: String?
        var command: String?
    }
    var claudeCode: ClaudeCode?
    var codex: Codex?
    var caPath: String?
}

enum TrustOutcome: Equatable, Sendable {
    case report(TrustReport)
    case status(TrustStatus)
    /// Couldn't run it, or it printed nothing readable.
    case failed(String)
}

/// What a bounded one-shot child did.
struct OneShotResult: Equatable, Sendable {
    var status: Int32
    var stdout: Data
    var stderr: String
    var timedOut = false
    var truncated = false
}

enum OneShot {
    static let stdoutCap = 1 << 20
    static let stderrCap = 8 << 10

    /// Runs `helper` and waits, at most `timeout` seconds, then SIGKILLs it. Output is bounded:
    /// more than `stdoutCap` bytes kills it too. Blocks; call it off the main thread. stdin is
    /// /dev/null, and every pipe fd is close-on-exec before the launch.
    static func run(helper: URL, args: [String], timeout: TimeInterval) -> OneShotResult? {
        let out = Pipe()
        let err = Pipe()
        let child = Process()
        child.executableURL = helper
        child.arguments = args
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = out
        child.standardError = err
        for handle in [
            out.fileHandleForReading, out.fileHandleForWriting, err.fileHandleForReading,
            err.fileHandleForWriting,
        ] {
            _ = fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC)
        }
        do { try child.run() } catch { return nil }
        try? out.fileHandleForWriting.close()
        try? err.fileHandleForWriting.close()

        let box = Box()
        let done = DispatchGroup()
        let outFD = out.fileHandleForReading.fileDescriptor
        let errFD = err.fileHandleForReading.fileDescriptor
        let pid = child.processIdentifier
        done.enter()
        Thread.detachNewThread {
            var chunk = [UInt8](repeating: 0, count: 16 << 10)
            while true {
                let n = chunk.withUnsafeMutableBytes { read(outFD, $0.baseAddress, $0.count) }
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                if !box.addOut(chunk[0..<n], cap: stdoutCap) {
                    kill(pid, SIGKILL)
                    break
                }
            }
            done.leave()
        }
        done.enter()
        Thread.detachNewThread {
            var chunk = [UInt8](repeating: 0, count: 4 << 10)
            while true {
                let n = chunk.withUnsafeMutableBytes { read(errFD, $0.baseAddress, $0.count) }
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                box.addErr(chunk[0..<n], cap: stderrCap)
            }
            done.leave()
        }
        let deadline = Date().addingTimeInterval(timeout)
        var timedOut = false
        while child.isRunning {
            if Date() >= deadline {
                timedOut = true
                kill(pid, SIGKILL)
                break
            }
            usleep(10_000)
        }
        child.waitUntilExit()
        // The readers end at EOF; a descendant holding a pipe can't hold us past this.
        _ = done.wait(timeout: .now() + 1)
        try? out.fileHandleForReading.close()
        try? err.fileHandleForReading.close()
        let (stdout, stderr, truncated) = box.snapshot()
        return OneShotResult(
            status: child.terminationStatus, stdout: stdout, stderr: stderr, timedOut: timedOut,
            truncated: truncated)
    }

    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var out = Data()
        private var err = Data()
        private var over = false

        /// False once the cap is exceeded.
        func addOut(_ bytes: ArraySlice<UInt8>, cap: Int) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            out.append(contentsOf: bytes)
            if out.count > cap {
                over = true
                return false
            }
            return true
        }

        func addErr(_ bytes: ArraySlice<UInt8>, cap: Int) {
            lock.lock()
            defer { lock.unlock() }
            err.append(contentsOf: bytes)
            if err.count > cap { err = err.suffix(cap) }
        }

        func snapshot() -> (Data, String, Bool) {
            lock.lock()
            defer { lock.unlock() }
            return (out, String(decoding: err, as: UTF8.self), over)
        }
    }
}

/// The trust calls. Stateless: `helper` is `CollectorClient.locate()` in the app.
struct TrustClient: Sendable {
    var helper: URL
    var timeout: TimeInterval = 15

    func status() async -> TrustOutcome { await call(["--trust-status", "--json"]) }
    func previewClaudeCode() async -> TrustOutcome {
        await call(["--trust", "claude-code", "--dry-run", "--json"])
    }
    func applyClaudeCode() async -> TrustOutcome { await call(["--trust", "claude-code", "--json"]) }
    func undoClaudeCode() async -> TrustOutcome {
        await call(["--trust", "claude-code", "--undo", "--json"])
    }
    func prepareCodex() async -> TrustOutcome { await call(["--trust", "codex", "--json"]) }
    func removeCodex() async -> TrustOutcome {
        await call(["--trust", "codex", "--undo", "--json"])
    }

    func call(_ args: [String]) async -> TrustOutcome {
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            return .failed("the collector is missing from the app")
        }
        let helper = helper
        let timeout = timeout
        let result = await withCheckedContinuation { (k: CheckedContinuation<OneShotResult?, Never>) in
            DispatchQueue.global().async {
                k.resume(returning: OneShot.run(helper: helper, args: args, timeout: timeout))
            }
        }
        return Self.outcome(result)
    }

    /// The first line that is a v1 `trust` or `trust-status` object. Exit 1 with a `refused`
    /// report is an outcome, not a failure.
    static func outcome(_ result: OneShotResult?) -> TrustOutcome {
        guard let result else { return .failed("couldn't start the collector") }
        if result.timedOut { return .failed("the collector took too long") }
        if result.truncated { return .failed("the collector printed too much") }
        let decoder = JSONDecoder()
        for line in result.stdout.split(separator: 0x0A) {
            struct Probe: Decodable {
                var v: Int?
                var type: String?
            }
            let data = Data(line)
            guard let probe = try? decoder.decode(Probe.self, from: data) else { continue }
            guard probe.v == 1 else {
                return .failed("Update cAInary: this collector speaks a newer format.")
            }
            if probe.type == "trust", let report = try? decoder.decode(TrustReport.self, from: data) {
                return .report(report)
            }
            if probe.type == "trust-status",
                let status = try? decoder.decode(TrustStatus.self, from: data)
            {
                return .status(status)
            }
        }
        let first = result.stderr.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        return .failed(
            first.isEmpty ? "the collector exited with code \(result.status)" : first.plainText)
    }
}

/// `env NODE_EXTRA_CA_CERTS=<path> claude`: the no-write alternative to the settings change.
/// The path is single-quoted when it needs it (the macOS state directory has a space); the
/// quoting is the same in fish and POSIX shells.
func nodeExtraCACommand(caPath: String) -> String {
    let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+-@%,")
    let quoted =
        caPath.unicodeScalars.allSatisfy(safe.contains)
        ? caPath : "'" + caPath.replacingOccurrences(of: "'", with: "'\\''") + "'"
    return "env NODE_EXTRA_CA_CERTS=\(quoted) claude"
}
