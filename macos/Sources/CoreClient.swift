import Foundation

// Runs the Rust helper and decodes its report (macos.md §1). The runner never blocks a thread in
// read/write and never trusts EOF: one deadline bounds the whole run.

/// What a helper that exited 0 printed.
struct CoreOutput: Equatable, Sendable {
    var stdout: Data
    var stderr: Data
}

/// A decoded report and the exact bytes it came from; the bytes become the baseline.
struct Scan: Sendable {
    var report: Report
    var raw: Data
}

final class CoreClient: Sendable {
    static let stdoutCap = 8 << 20
    static let stderrCap = 64 << 10
    /// The only report schema this app reads.
    static let schema = 3

    let helper: URL
    /// Appended to every scan's arguments (DEBUG builds: `CAINARY_SCAN_ARGS`; tests: `--fixture`).
    let extraArgs: [String]
    /// One bound for the stdin write, the exit, and EOF on both pipes.
    let deadline: TimeInterval
    /// SIGTERM to SIGKILL.
    let killGrace: TimeInterval

    init(
        helper: URL = CoreClient.locate(),
        extraArgs: [String] = CoreClient.debugScanArgs(),
        deadline: TimeInterval = 20,
        killGrace: TimeInterval = 2
    ) {
        self.helper = helper
        self.extraArgs = extraArgs
        self.deadline = deadline
        self.killGrace = killGrace
    }

    /// `Contents/Helpers/cainary`, kept out of `Contents/MacOS` so the names can't collide on a
    /// case-insensitive disk. DEBUG builds honour `CAINARY_CORE`.
    static func locate() -> URL {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["CAINARY_CORE"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        #endif
        return Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/cainary")
    }

    /// DEBUG builds split `CAINARY_SCAN_ARGS` on spaces; release builds ignore it.
    static func debugScanArgs() -> [String] {
        #if DEBUG
        let raw = ProcessInfo.processInfo.environment["CAINARY_SCAN_ARGS"] ?? ""
        return raw.split(separator: " ").map(String.init)
        #else
        return []
        #endif
    }

    // MARK: Calls

    /// A scan, with the previous report's bytes as the baseline when there is one.
    func scan(baseline: Data?) async -> Result<Scan, CoreError> {
        let args = ["scan", "--json", "--env-kind", "launchd"] + sinceArgs(baseline) + extraArgs
        switch await run(args, stdin: baseline) {
        case .failure(let error): return .failure(error)
        case .success(let output): return Self.decode(output.stdout)
        }
    }

    /// The text for "Copy report": the same scan, rendered for people.
    func copyReport(baseline: Data?) async -> Result<String, CoreError> {
        let args =
            ["scan", "--no-color", "--env-kind", "launchd"] + sinceArgs(baseline) + extraArgs
        switch await run(args, stdin: baseline) {
        case .failure(let error): return .failure(error)
        case .success(let output): return .success(String(decoding: output.stdout, as: UTF8.self))
        }
    }

    private func sinceArgs(_ baseline: Data?) -> [String] {
        baseline == nil ? [] : ["--since", "-"]
    }

    /// The checks after a clean exit, in order: schema alone, then the full decode.
    static func decode(_ data: Data) -> Result<Scan, CoreError> {
        struct Probe: Decodable { var schema: Int }
        do {
            let probe = try JSONDecoder().decode(Probe.self, from: data)
            guard probe.schema == schema else { return .failure(.schema(probe.schema)) }
        } catch {
            return .failure(.decode("\(error)"))
        }
        do {
            return .success(Scan(report: try Report.decode(data), raw: data))
        } catch {
            return .failure(.decode("\(error)"))
        }
    }

    /// Runs the helper. A non-zero exit is `.exit(code, first stderr line)`; the I/O limits and
    /// the deadline give `.timedOut` and `.outputTooLarge`.
    func run(
        _ args: [String], stdin: Data?, timeout: TimeInterval? = nil
    ) async -> Result<CoreOutput, CoreError> {
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            return .failure(.helperMissing)
        }
        let job = Job(
            helper: helper, args: args, stdin: stdin, deadline: timeout ?? deadline,
            grace: killGrace)
        return await withCheckedContinuation { job.start($0) }
    }
}

// MARK: - One helper run

/// All state lives on `queue`: handlers, timers and the termination callback hop onto it.
private final class Job: @unchecked Sendable {
    private let queue = DispatchQueue(label: "ua.SkeLLLa.cAInary.core")
    private let helper: URL
    private let args: [String]
    private let stdin: Data?
    private let deadline: TimeInterval
    private let grace: TimeInterval

    private let process = Process()
    private var continuation: CheckedContinuation<Result<CoreOutput, CoreError>, Never>?
    private var channels: [DispatchIO] = []
    private var out = Data()
    private var err = Data()
    private var exited = false
    private var status: Int32 = 0
    private var outEOF = false
    private var errEOF = false
    private var stdinDone = false
    /// Set when a cap or the deadline fired and the helper is being killed.
    private var verdict: CoreError?
    private var finished = false

    init(helper: URL, args: [String], stdin: Data?, deadline: TimeInterval, grace: TimeInterval) {
        self.helper = helper
        self.args = args
        self.stdin = stdin
        self.deadline = deadline
        self.grace = grace
    }

    func start(_ continuation: CheckedContinuation<Result<CoreOutput, CoreError>, Never>) {
        queue.async { [self] in
            self.continuation = continuation
            launch()
        }
    }

    private func launch() {
        // Allocate one pipe at a time; on any failure, every earlier pipe is closed again.
        var made: [(read: Int32, write: Int32)] = []
        func closeAll() {
            for p in made {
                close(p.read)
                close(p.write)
            }
        }
        guard let outPipe = Self.pipe() else {
            return finish(.failure(.launchFailed("pipe() failed")))
        }
        made.append(outPipe)
        guard let errPipe = Self.pipe() else {
            closeAll()
            return finish(.failure(.launchFailed("pipe() failed")))
        }
        made.append(errPipe)
        // stdin is a pipe only when there is a baseline to send; failing to make it is a failed
        // launch, since the helper would otherwise run without the baseline it was told to read.
        var inPipe: (read: Int32, write: Int32)?
        if stdin != nil {
            guard let p = Self.pipe() else {
                closeAll()
                return finish(.failure(.launchFailed("pipe() failed")))
            }
            made.append(p)
            inPipe = p
        }
        process.executableURL = helper
        process.arguments = args
        process.standardOutput = FileHandle(fileDescriptor: outPipe.write, closeOnDealloc: false)
        process.standardError = FileHandle(fileDescriptor: errPipe.write, closeOnDealloc: false)
        if let inPipe {
            process.standardInput = FileHandle(fileDescriptor: inPipe.read, closeOnDealloc: false)
        } else {
            process.standardInput = FileHandle.nullDevice
        }
        process.terminationHandler = { [self] finished in
            queue.async { [self] in
                exited = true
                status = finished.terminationStatus
                step()
            }
        }
        do {
            try process.run()
        } catch {
            closeAll()
            return finish(.failure(.launchFailed(error.localizedDescription)))
        }
        // The child has its ends; ours must go, or EOF could never arrive.
        close(outPipe.write)
        close(errPipe.write)
        if let inPipe { close(inPipe.read) }

        queue.asyncAfter(deadline: .now() + deadline) { [self] in expire() }

        drain(outPipe.read, isOut: true)
        drain(errPipe.read, isOut: false)
        if let inPipe, let data = stdin, !data.isEmpty {
            feed(inPipe.write, data)
        } else {
            if let inPipe { close(inPipe.write) }
            stdinDone = true
        }
    }

    private static func pipe() -> (read: Int32, write: Int32)? {
        var fds: [Int32] = [0, 0]
        guard Darwin.pipe(&fds) == 0 else { return nil }
        for fd in fds { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        return (fds[0], fds[1])
    }

    private func channel(_ fd: Int32) -> DispatchIO {
        let io = DispatchIO(type: .stream, fileDescriptor: fd, queue: queue) { _ in close(fd) }
        io.setLimit(highWater: 64 << 10)
        channels.append(io)
        return io
    }

    private func drain(_ fd: Int32, isOut: Bool) {
        channel(fd).read(offset: 0, length: Int.max, queue: queue) { [self] done, data, _ in
            guard !finished else { return }
            if let data, !data.isEmpty, verdict == nil {
                if isOut {
                    data.enumerateBytes { bytes, _, _ in out.append(bytes) }
                } else {
                    data.enumerateBytes { bytes, _, _ in err.append(bytes) }
                }
                if out.count > CoreClient.stdoutCap || err.count > CoreClient.stderrCap {
                    return stop(.outputTooLarge)
                }
            }
            if done {
                if isOut { outEOF = true } else { errEOF = true }
                step()
            }
        }
    }

    /// Writes the baseline, then closes. Errors (the helper may exit unread) just end the write.
    private func feed(_ fd: Int32, _ data: Data) {
        let io = channel(fd)
        let bytes = data.withUnsafeBytes { DispatchData(bytes: $0) }
        io.write(offset: 0, data: bytes, queue: queue) { [self] done, _, _ in
            guard done, !finished else { return }
            io.close()
            stdinDone = true
            step()
        }
    }

    /// Finishes once the helper has exited and every pipe is done; a pending verdict wins.
    private func step() {
        guard !finished else { return }
        if let verdict {
            if exited { finish(.failure(verdict)) }
            return
        }
        guard exited, outEOF, errEOF, stdinDone else { return }
        if status == 0 {
            finish(.success(CoreOutput(stdout: out, stderr: err)))
        } else {
            let first =
                String(decoding: err, as: UTF8.self)
                .split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            finish(.failure(.exit(status, first.trimmingCharacters(in: .whitespaces))))
        }
    }

    /// The deadline: a helper that already exited but whose pipes are still open is also late.
    private func expire() {
        guard !finished, verdict == nil else { return }
        if exited { finish(.failure(.timedOut)) } else { stop(.timedOut) }
    }

    /// SIGTERM, then SIGKILL after `grace`, then finish once the helper is reaped.
    private func stop(_ error: CoreError) {
        verdict = error
        guard !exited else { return finish(.failure(error)) }
        signalHelper(SIGTERM)
        queue.asyncAfter(deadline: .now() + grace) { [self] in
            guard !finished, !exited else { return }
            signalHelper(SIGKILL)
            // SIGKILL can't be ignored; this only bounds the wait if the kernel is slow to reap.
            queue.asyncAfter(deadline: .now() + 1) { [self] in finish(.failure(error)) }
        }
    }

    private func signalHelper(_ signal: Int32) {
        if process.isRunning { kill(process.processIdentifier, signal) }
    }

    /// Closes every channel without waiting for EOF (a descendant may still hold the pipes).
    private func finish(_ result: Result<CoreOutput, CoreError>) {
        guard !finished else { return }
        finished = true
        process.terminationHandler = nil
        for io in channels { io.close(flags: .stop) }
        channels = []
        continuation?.resume(returning: result)
        continuation = nil
    }
}
