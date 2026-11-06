import Foundation

// Runs the opt-in `cainary-otel-debug` helper as a child process (design §9, §14.7, §14.9). The
// app holds the write end of the child's stdin for as long as it runs: the child exits on EOF, so
// it can't outlive the app, SIGKILL included. The config goes over stdin once, never in argv.

final class CollectorClient: @unchecked Sendable {
    enum Event: Equatable, Sendable {
        /// One stdout line, without its newline.
        case line(Data)
        /// A line longer than `maxLine`; the child has been killed.
        case oversize
        /// The child ended on its own. `stderr` is the last 8 KiB it wrote.
        case exited(Int32, stderr: String)
        /// The child never started.
        case failed(String)
    }

    static let maxLine = 4 << 20
    static let stderrCap = 8 << 10

    private let helper: URL
    private let args: [String]
    private let config: Data
    private let maxLine: Int
    private let onEvent: @Sendable (Event) -> Void

    /// Guards everything below. Never held across a blocking call.
    private let lock = NSLock()
    private var process: Process?
    private var stdinHandle: FileHandle?
    private var stdoutHandle: FileHandle?
    private var stderrHandle: FileHandle?
    private var stopped = false
    private var oversized = false

    /// `onEvent` is called from the reader thread, lines in order; `.exited` comes last.
    init(
        helper: URL, args: [String], config: Data, maxLine: Int = CollectorClient.maxLine,
        onEvent: @escaping @Sendable (Event) -> Void
    ) {
        self.helper = helper
        self.args = args
        self.config = config
        self.maxLine = maxLine
        self.onEvent = onEvent
    }

    /// `Contents/Helpers/cainary-otel-debug`. DEBUG builds honour `CAINARY_OTEL_DEBUG`.
    static func locate() -> URL {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["CAINARY_OTEL_DEBUG"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        #endif
        return Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/cainary-otel-debug")
    }

    // MARK: Start

    func start() {
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            return onEvent(.failed("the collector is missing from the app"))
        }
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        let child = Process()
        child.executableURL = helper
        child.arguments = args
        child.standardInput = stdin
        child.standardOutput = stdout
        child.standardError = stderr
        do {
            try child.run()
        } catch {
            return onEvent(.failed(error.localizedDescription))
        }
        // The child has its ends. Ours must go, or stdout and stderr could never reach EOF.
        try? stdin.fileHandleForReading.close()
        try? stdout.fileHandleForWriting.close()
        try? stderr.fileHandleForWriting.close()
        // Our ends never leak into another child, and a write to a dead child is EPIPE, not a signal.
        let inFD = stdin.fileHandleForWriting.fileDescriptor
        for fd in [
            inFD, stdout.fileHandleForReading.fileDescriptor,
            stderr.fileHandleForReading.fileDescriptor,
        ] {
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        }
        _ = fcntl(inFD, F_SETNOSIGPIPE, 1)
        _ = fcntl(inFD, F_SETFL, fcntl(inFD, F_GETFL) | O_NONBLOCK)

        lock.lock()
        process = child
        stdinHandle = stdin.fileHandleForWriting
        stdoutHandle = stdout.fileHandleForReading
        stderrHandle = stderr.fileHandleForReading
        let alreadyStopped = stopped
        lock.unlock()
        // `stop` may have run between `run()` and here, before there was a stdin to close.
        if alreadyStopped { closeStdin() }

        let done = DispatchSemaphore(value: 0)
        let tail = Tail()
        Thread.detachNewThread { [self] in
            readStderr(into: tail)
            done.signal()
        }
        Thread.detachNewThread { [self] in
            writeConfig()
            readLines()
            guard let child = currentProcess() else { return }
            child.waitUntilExit()
            // The helper has exited, so stderr is at EOF; the bound is for a stray descendant.
            _ = done.wait(timeout: .now() + 1)
            lock.lock()
            let quiet = stopped || oversized
            lock.unlock()
            if !quiet {
                onEvent(.exited(child.terminationStatus, stderr: tail.text))
            }
        }
    }

    /// The config line, then nothing: stdin stays open as the lifeline. The pipe is non-blocking
    /// and each attempt holds the lock, so `closeStdin` can't close a descriptor mid-write.
    private func writeConfig() {
        var bytes = config
        bytes.append(0x0A)
        var offset = 0
        while offset < bytes.count {
            lock.lock()
            guard let handle = stdinHandle else {
                lock.unlock()
                return
            }
            let n = bytes.withUnsafeBytes {
                write(handle.fileDescriptor, $0.baseAddress! + offset, $0.count - offset)
            }
            let err = errno
            lock.unlock()
            if n > 0 {
                offset += n
            } else if n < 0 && (err == EAGAIN || err == EINTR) {
                usleep(2_000)
            } else {
                return
            }
        }
    }

    private func readLines() {
        guard let handle = handleOut() else { return }
        let fd = handle.fileDescriptor
        defer { try? handle.close() }
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            buffer.append(contentsOf: chunk[0..<n])
            while let newline = buffer.firstIndex(of: 0x0A) {
                if newline - buffer.startIndex > maxLine { return tooLong() }
                let line = buffer[buffer.startIndex..<newline]
                if !line.isEmpty { onEvent(.line(Data(line))) }
                buffer.removeSubrange(buffer.startIndex...newline)
            }
            if buffer.count > maxLine { return tooLong() }
        }
    }

    private func handleOut() -> FileHandle? {
        lock.lock()
        defer { lock.unlock() }
        return stdoutHandle
    }

    private func currentProcess() -> Process? {
        lock.lock()
        defer { lock.unlock() }
        return process
    }

    /// Reports the oversize line and kills the child; the caller then reaps it.
    private func tooLong() {
        lock.lock()
        oversized = true
        let child = process
        lock.unlock()
        onEvent(.oversize)
        if let child, child.isRunning { kill(child.processIdentifier, SIGKILL) }
    }

    private func readStderr(into tail: Tail) {
        lock.lock()
        let handle = stderrHandle
        lock.unlock()
        guard let handle else { return }
        defer { try? handle.close() }
        let fd = handle.fileDescriptor
        var chunk = [UInt8](repeating: 0, count: 4 << 10)
        while true {
            let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            tail.append(chunk[0..<n], cap: Self.stderrCap)
        }
    }

    // MARK: Stop

    /// Close stdin, SIGTERM, wait up to `grace`, SIGKILL, reap. Blocks; call it off the main
    /// thread unless the app is quitting. Safe to call twice, or before `start`.
    func stop(grace: TimeInterval) {
        lock.lock()
        stopped = true
        let child = process
        lock.unlock()
        closeStdin()
        guard let child, child.isRunning else { return }
        kill(child.processIdentifier, SIGTERM)
        let deadline = Date().addingTimeInterval(grace)
        while child.isRunning && Date() < deadline { usleep(10_000) }
        if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        child.waitUntilExit()
    }

    private func closeStdin() {
        lock.lock()
        let handle = stdinHandle
        stdinHandle = nil
        lock.unlock()
        try? handle?.close()
    }
}

/// The last bytes of a stream, as text.
private final class Tail: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func append(_ bytes: ArraySlice<UInt8>, cap: Int) {
        lock.lock()
        defer { lock.unlock() }
        data.append(contentsOf: bytes)
        if data.count > cap { data = data.suffix(cap) }
    }

    var text: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}
