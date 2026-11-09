import Darwin
import Foundation

// Swift twin of linux/crates/tray-model/src/hostcheck.rs: whether the takeover host names reach
// this computer. Each name goes through getaddrinfo on its own thread and is raced against a
// timer, so a stuck resolver never blocks the caller; its thread is abandoned.

enum LookupResult: Equatable, Sendable {
    /// Every address is loopback.
    case here
    /// At least one address is somewhere else; these are the others.
    case elsewhere([String])
    case error(String)
}

enum HostLookup {
    static let timeout: TimeInterval = 5
    static let noAddress = "No address found"
    static let couldntStart = "Couldn't start a lookup"
    static let timedOut = "The lookup timed out"

    /// Resolves a name to address strings, or throws a message. Called off the main thread.
    typealias Resolver = @Sendable (String) throws -> [String]
    /// Runs the work on its own thread; false when it couldn't start.
    typealias Starter = @Sendable (@escaping @Sendable () -> Void) -> Bool

    struct Failure: Error { let message: String }

    static func check(_ names: [String]) async -> [String: LookupResult] {
        await check(names, timeout: timeout, resolve: getaddrinfoResolver, start: threadStarter)
    }

    static func check(
        _ names: [String], timeout: TimeInterval, resolve: @escaping Resolver,
        start: @escaping Starter = threadStarter
    ) async -> [String: LookupResult] {
        await withTaskGroup(of: (String, LookupResult).self) { group in
            for name in names {
                group.addTask {
                    (name, await lookup(name, timeout: timeout, resolve: resolve, start: start))
                }
            }
            var results: [String: LookupResult] = [:]
            for await (name, result) in group { results[name] = result }
            return results
        }
    }

    /// What a set of resolved addresses means. Pure.
    static func classify(_ addresses: [String]) -> LookupResult {
        let others = addresses.filter { !isLoopback($0) }
        if !others.isEmpty { return .elsewhere(others) }
        return addresses.isEmpty ? .error(noAddress) : .here
    }

    /// 127.0.0.0/8, ::1, and the v4-mapped forms of those.
    static func isLoopback(_ address: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            return UInt32(bigEndian: v4.s_addr) >> 24 == 127
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, address, &v6) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        if bytes.dropLast() == [UInt8](repeating: 0, count: 15)[...] && bytes[15] == 1 {
            return true
        }
        let mapped = bytes[0..<10].allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
        return mapped && bytes[12] == 127
    }

    private static func lookup(
        _ name: String, timeout: TimeInterval, resolve: @escaping Resolver,
        start: Starter
    ) async -> LookupResult {
        await withCheckedContinuation { continuation in
            let race = Race(continuation)
            let started = start {
                do {
                    race.finish(classify(try resolve(name)))
                } catch let failure as Failure {
                    race.finish(.error(failure.message))
                } catch {
                    race.finish(.error(error.localizedDescription))
                }
            }
            if !started {
                race.finish(.error(couldntStart))
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                race.finish(.error(timedOut))
            }
        }
    }

    static let threadStarter: Starter = { work in
        let thread = Thread(block: work)
        thread.name = "cainary-host-lookup"
        thread.start()
        return true
    }

    static let getaddrinfoResolver: Resolver = { name in
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var found: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(name, "443", &hints, &found)
        guard status == 0 else { throw Failure(message: String(cString: gai_strerror(status))) }
        defer { freeaddrinfo(found) }
        var out: [String] = []
        var cursor = found
        while let info = cursor?.pointee {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(
                info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0,
                NI_NUMERICHOST) == 0
            {
                out.append(
                    String(
                        decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                        as: UTF8.self))
            }
            cursor = info.ai_next
        }
        return out
    }
}

/// The first of the lookup and the timer to finish wins; the other is dropped.
private final class Race: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<LookupResult, Never>?

    init(_ continuation: CheckedContinuation<LookupResult, Never>) {
        self.continuation = continuation
    }

    func finish(_ result: LookupResult) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: result)
    }
}
