import Darwin
import Foundation

// Swift twin of linux/crates/tray-model/src/hostsfile.rs (the pure analysis, `expectedBlock` and
// `read`) and of the gating rules in hostsview.rs. The block rules (markers, line terminators,
// malformed markers) must agree byte-for-byte with the hosts helper's `edit`; the tests run the
// shared fixtures in linux/crates/tray-model/tests/fixtures/hosts.

enum BlockState: String, Equatable, Sendable {
    /// No marker anywhere.
    case absent
    /// A well-formed block whose lines are exactly what `set` writes for the configured names.
    case current
    /// A well-formed block with any other content.
    case stale
    /// A single, repeated, nested or misordered marker, or a malformed one. The helper refuses.
    case damaged
}

/// An unmanaged line that maps a configured name to a non-loopback address.
struct HostsConflict: Equatable, Sendable {
    /// 1-based.
    let line: Int
    let address: String
    let host: String
}

struct HostsAnalysis: Equatable, Sendable {
    let state: BlockState
    let conflicts: [HostsConflict]
    /// Configured names the helper would refuse, in configured order.
    let reserved: [String]
}

/// Why the helper would refuse /etc/hosts as a file, whatever is in it (hostsfile.rs
/// `Unsupported`, with the macOS owner/link checks the helper's os_macos.rs makes).
enum HostsUnsupported: Equatable, Sendable {
    case symlink(target: String)
    /// A different device from /private/etc: something is mounted over it.
    case mountPoint
    /// Not owned by root, or group- or world-writable.
    case unprotected
    /// More than one hard link.
    case hardlinked

    var reason: String {
        switch self {
        case .symlink(let target):
            let to = target.isEmpty ? "" : " (it links to \(target))"
            return
                "/etc/hosts is managed elsewhere\(to). Edit the file it points to yourself; cAInary won't edit it."
        case .mountPoint:
            return "/etc/hosts is mounted from elsewhere. Edit it where it is stored."
        case .unprotected:
            return
                "/etc/hosts can be changed by users other than root; cAInary won't edit it."
        case .hardlinked:
            return "/etc/hosts has more than one link; cAInary won't edit it."
        }
    }
}

/// `analysis` is nil when the file couldn't be read; `error` says why. `unsupported` is set when
/// the file may be read but the helper would refuse to change it.
struct HostsFileSummary: Equatable, Sendable {
    let error: String?
    let analysis: HostsAnalysis?
    var unsupported: HostsUnsupported? = nil
}

/// What the Add/Update and Remove buttons may do, and why not.
struct HostsGate: Equatable, Sendable {
    let canEdit: Bool
    let canRemove: Bool
    /// Why Add/Update is disabled; nil when it is available or there is nothing to say.
    let editReason: String?
    /// Set when the file itself can't be edited; both buttons are off.
    var unsupported: HostsUnsupported? = nil
}

/// What `lstat`/`stat` said about a path.
struct HostsStat: Equatable, Sendable {
    var mode: UInt32
    var uid: UInt32
    var nlink: UInt32
    var dev: Int64

    var isRegular: Bool { mode & 0o170000 == 0o100000 }
    var isSymlink: Bool { mode & 0o170000 == 0o120000 }
}

/// The system calls `HostsFile.inspect` makes, so tests can fake every answer.
struct HostsFileProbe: Sendable {
    /// Doesn't follow a link at the last component; the failure is the error text.
    var linkInfo: @Sendable (String) -> Result<HostsStat, HostsStatFailure>
    /// Follows links.
    var fileInfo: @Sendable (String) -> Result<HostsStat, HostsStatFailure>
    var linkTarget: @Sendable (String) -> String?

    static let system = HostsFileProbe(
        linkInfo: { systemStat($0, follow: false) },
        fileInfo: { systemStat($0, follow: true) },
        linkTarget: { path in
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let count = readlink(path, &buffer, buffer.count - 1)
            guard count >= 0 else { return nil }
            return String(
                decoding: buffer.prefix(count).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        })
}

private func systemStat(_ path: String, follow: Bool) -> Result<HostsStat, HostsStatFailure> {
    var info = stat()
    let status = follow ? stat(path, &info) : lstat(path, &info)
    guard status == 0 else { return .failure(.current) }
    return .success(HostsStat(info))
}

struct HostsStatFailure: Error, Equatable, Sendable {
    let message: String

    static var current: HostsStatFailure {
        HostsStatFailure(message: String(cString: strerror(errno)))
    }
}

extension HostsStat {
    fileprivate init(_ info: stat) {
        self.init(
            mode: UInt32(info.st_mode), uid: UInt32(info.st_uid), nlink: UInt32(info.st_nlink),
            dev: Int64(info.st_dev))
    }
}

enum HostsFile {
    static let path = "/etc/hosts"
    /// Larger files are not read; the helper refuses them too.
    static let maxReadBytes = 16 * 1024 * 1024
    /// The helper's limit on names per edit.
    static let maxEditHosts = 8

    static let beginMarker =
        "# >>> cAInary takeover: managed by cAInary, lines in here are replaced; remove with the app >>>"
    static let endMarker = "# <<< cAInary takeover <<<"

    /// The lines a user would paste for these names, markers included.
    static func expectedBlock(hosts: [String]) -> [String] {
        [beginMarker] + expectedBody(hosts) + [endMarker]
    }

    // MARK: Reading

    /// Reads the file as the helper would admit it (a regular file under the cap), then analyzes it.
    static func read(
        path: String = HostsFile.path, hosts: [String], nodename: String = HostsFile.nodename(),
        probe: HostsFileProbe = .system
    ) -> HostsFileSummary {
        let isDefault = path == HostsFile.path
        let found = inspect(
            path: path, canonical: isDefault ? canonicalPath : nil,
            directory: isDefault
                ? canonicalDirectory : (path as NSString).deletingLastPathComponent,
            probe: probe)
        let unsupported = found.unsupported
        if let error = found.error {
            return HostsFileSummary(error: error, analysis: nil, unsupported: unsupported)
        }
        // O_NONBLOCK so a swapped-in FIFO can't hang the open.
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            return HostsFileSummary(
                error: String(cString: strerror(errno)), analysis: nil, unsupported: unsupported)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data: Data
        do {
            data = try handle.read(upToCount: maxReadBytes + 1) ?? Data()
        } catch {
            return HostsFileSummary(
                error: error.localizedDescription, analysis: nil, unsupported: unsupported)
        }
        if data.count > maxReadBytes {
            return HostsFileSummary(
                error: "The file is too large", analysis: nil, unsupported: unsupported)
        }
        return HostsFileSummary(
            error: nil, analysis: analyze(bytes: [UInt8](data), hosts: hosts, nodename: nodename),
            unsupported: unsupported)
    }

    /// `/etc` is a link to `private/etc` on macOS; the file there is the one the helper edits.
    static let canonicalPath = "/private/etc/hosts"
    static let canonicalDirectory = "/private/etc"

    struct Inspection: Equatable, Sendable {
        var unsupported: HostsUnsupported?
        /// Set when the file can't be read at all (a missing or non-regular file).
        var error: String?
    }

    /// Looks at the path with lstat (a FIFO is never opened, a link is noticed), and at
    /// `canonical` too when given. A link is still followed to read it, as on Linux; the other
    /// findings (owner, mode, hard links, mount point) only matter for a file that isn't a link.
    static func inspect(
        path: String, canonical: String? = nil, directory: String = canonicalDirectory,
        owner: UInt32 = 0, probe: HostsFileProbe
    ) -> Inspection {
        var found = Inspection(unsupported: nil, error: nil)
        let paths = [path] + (canonical.map { $0 == path ? [] : [$0] } ?? [])
        for (index, current) in paths.enumerated() {
            let info: HostsStat
            switch probe.linkInfo(current) {
            case .failure(let failure):
                // A missing canonical twin says nothing; the given path is what gets read.
                if index == 0 { return Inspection(unsupported: nil, error: failure.message) }
                continue
            case .success(let value): info = value
            }
            var target = info
            if info.isSymlink {
                found.unsupported =
                    found.unsupported ?? .symlink(target: probe.linkTarget(current) ?? "")
                switch probe.fileInfo(current) {
                case .failure(let failure):
                    found.error = failure.message
                    return found
                case .success(let value): target = value
                }
            }
            guard target.isRegular else {
                found.error = "Not a regular file"
                return found
            }
            guard !info.isSymlink, found.unsupported == nil else { continue }
            if case .success(let dir) = probe.fileInfo(directory), dir.dev != info.dev {
                found.unsupported = .mountPoint
            } else if info.uid != owner || info.mode & 0o022 != 0 {
                found.unsupported = .unprotected
            } else if info.nlink > 1 {
                found.unsupported = .hardlinked
            }
        }
        return found
    }

    /// The node name from `uname`, or empty.
    static func nodename() -> String {
        var uts = utsname()
        guard uname(&uts) == 0 else { return "" }
        return withUnsafePointer(to: &uts.nodename) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
    }

    // MARK: Gating (hostsview.rs `view`)

    /// `file` is nil before the first read.
    static func gate(hosts: [String], file: HostsFileSummary?) -> HostsGate {
        guard let file else { return HostsGate(canEdit: false, canRemove: false, editReason: nil) }
        if let unsupported = file.unsupported {
            return HostsGate(
                canEdit: false, canRemove: false, editReason: unsupported.reason,
                unsupported: unsupported)
        }
        if let error = file.error {
            return HostsGate(
                canEdit: false, canRemove: false, editReason: "Couldn't read /etc/hosts: \(error)")
        }
        guard let analysis = file.analysis else {
            return HostsGate(canEdit: false, canRemove: false, editReason: nil)
        }
        let damaged = analysis.state == .damaged
        let removable = analysis.state == .current || analysis.state == .stale
        let reason: String?
        if damaged {
            reason = "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts."
        } else if hosts.isEmpty {
            reason = "There are no host names to add."
        } else if hosts.count > maxEditHosts {
            reason =
                "More than \(maxEditHosts) host names; cAInary can add at most \(maxEditHosts)."
        } else if !analysis.reserved.isEmpty {
            reason =
                "Can't add reserved names: \(analysis.reserved.joined(separator: ", "))."
        } else {
            reason = nil
        }
        return HostsGate(canEdit: reason == nil, canRemove: removable, editReason: reason)
    }

    // MARK: Analysis

    static func analyze(text: String, hosts: [String], nodename: String) -> HostsAnalysis {
        analyze(bytes: Array(text.utf8), hosts: hosts, nodename: nodename)
    }

    /// Pure core. `hosts` are the valid configured names; `nodename` is `uname().nodename`.
    static func analyze(bytes: [UInt8], hosts: [String], nodename: String) -> HostsAnalysis {
        let lines = splitLines(bytes)
        let layout = layout(of: lines)
        let state: BlockState
        switch layout {
        case .none: state = .absent
        case .damaged: state = .damaged
        case .block(let begin, let end):
            let body = lines[(begin + 1)..<end].sorted { $0.lexicographicallyPrecedes($1) }
            let expected = expectedBodyBytes(hosts).sorted { $0.lexicographicallyPrecedes($1) }
            state = !hosts.isEmpty && body == expected ? .current : .stale
        }
        // Unmanaged: everything outside a well-formed block; in a damaged file, everything.
        var managed: ClosedRange<Int>?
        if case .block(let begin, let end) = layout { managed = begin...end }
        let node = Array(nodename.utf8).map(lower)
        let nodeLabel = firstLabel(node)
        var conflicts: [HostsConflict] = []
        var onNodenameLine = [Bool](repeating: false, count: hosts.count)
        for (index, content) in lines.enumerated() {
            if let managed, managed.contains(index) { continue }
            guard let tokens = fields(content) else { continue }
            let names = tokens.dropFirst().map { $0.map(lower) }
            let namesNodename = !node.isEmpty && names.contains { $0 == node || $0 == nodeLabel }
            let address = String(bytes: tokens[0], encoding: .utf8).flatMap(normalizedAddress)
            for (slot, host) in hosts.enumerated() where names.contains(Array(host.utf8)) {
                onNodenameLine[slot] = onNodenameLine[slot] || namesNodename
                if let address, !HostLookup.isLoopback(address) {
                    conflicts.append(HostsConflict(line: index + 1, address: address, host: host))
                }
            }
        }
        let reserved = hosts.enumerated()
            .filter { isReserved($0.element, nodename: node) || onNodenameLine[$0.offset] }
            .map(\.element)
        return HostsAnalysis(state: state, conflicts: conflicts, reserved: reserved)
    }

    // MARK: Internals

    private enum Layout {
        case none
        /// Line indexes of the begin and end markers.
        case block(Int, Int)
        case damaged
    }

    /// Lines as the helper sees them: the bytes up to `\n`, minus one `\r` right before it. An
    /// unterminated rest at EOF is a line too, kept as is: a lone `\r` there isn't a terminator.
    private static func splitLines(_ bytes: [UInt8]) -> [[UInt8]] {
        var parts = bytes.split(separator: 10, omittingEmptySubsequences: false).map(Array.init)
        let rest = parts.popLast() ?? []
        parts = parts.map { $0.last == 13 ? Array($0.dropLast()) : $0 }
        if !rest.isEmpty { parts.append(rest) }
        return parts
    }

    private static func isBlank(_ byte: UInt8) -> Bool { byte == 0x20 || byte == 0x09 }

    private static func lower(_ byte: UInt8) -> UInt8 {
        byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte
    }

    /// Not a marker, but a comment that mentions the takeover: the helper refuses these.
    private static func isMalformedMarker(_ content: [UInt8]) -> Bool {
        let rest = content.drop(while: isBlank)
        guard rest.first == 0x23 else { return false }
        let needle = Array("cainary takeover".utf8)
        let hay = rest.map(lower)
        guard hay.count >= needle.count else { return false }
        return (0...(hay.count - needle.count)).contains {
            Array(hay[$0..<($0 + needle.count)]) == needle
        }
    }

    private static func layout(of lines: [[UInt8]]) -> Layout {
        let begin = Array(beginMarker.utf8)
        let end = Array(endMarker.utf8)
        var begins: [Int] = []
        var ends: [Int] = []
        for (index, line) in lines.enumerated() {
            if line == begin {
                begins.append(index)
            } else if line == end {
                ends.append(index)
            } else if isMalformedMarker(line) {
                return .damaged
            }
        }
        if begins.isEmpty && ends.isEmpty { return .none }
        if begins.count == 1, ends.count == 1, begins[0] < ends[0] {
            return .block(begins[0], ends[0])
        }
        return .damaged
    }

    private static func expectedBody(_ hosts: [String]) -> [String] {
        hosts.flatMap { ["127.0.0.1 \($0)", "::1 \($0)"] }
    }

    private static func expectedBodyBytes(_ hosts: [String]) -> [[UInt8]] {
        expectedBody(hosts).map { Array($0.utf8) }
    }

    private static func isSpace(_ byte: UInt8) -> Bool {
        (byte >= 0x09 && byte <= 0x0d) || byte == 0x20
    }

    /// The address and the names of a hosts line; nil for blank and comment-only lines.
    private static func fields(_ content: [UInt8]) -> [[UInt8]]? {
        let code = content.prefix { $0 != 0x23 }
        let tokens = code.split(whereSeparator: isSpace).map(Array.init)
        return tokens.count >= 2 ? tokens : nil
    }

    private static func firstLabel(_ name: [UInt8]) -> [UInt8] {
        Array(name.prefix { $0 != 0x2e })
    }

    private static func isReserved(_ host: String, nodename: [UInt8]) -> Bool {
        let fixed = ["localhost.localdomain", "localhost4.localdomain4", "localhost6.localdomain6"]
        if host.hasSuffix(".localhost") || host.hasSuffix(".localdomain") || fixed.contains(host) {
            return true
        }
        return !nodename.isEmpty && firstLabel(Array(host.utf8)) == firstLabel(nodename)
    }

    /// The canonical text of an IPv4 or IPv6 address, or nil when it isn't one.
    private static func normalizedAddress(_ text: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count)).map {
                String(cString: $0)
            }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count)).map {
                String(cString: $0)
            }
        }
        return nil
    }
}
