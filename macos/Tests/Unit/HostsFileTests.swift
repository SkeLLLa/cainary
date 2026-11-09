import Foundation

// Tests for HostsFile.swift and HostLookup.swift. HostsFile runs every fixture in
// linux/crates/tray-model/tests/fixtures/hosts with the states of tray-model's tests/hostsfile.rs
// and the gating cases of hostsview.rs.

private func fixture(_ name: String) -> [UInt8] {
    let url = repoRoot().appendingPathComponent(
        "linux/crates/tray-model/tests/fixtures/hosts/\(name).hosts")
    return (try? [UInt8](Data(contentsOf: url))) ?? []
}

private let otel = ["otel.example.com"]

private func run(_ name: String) -> HostsAnalysis {
    HostsFile.analyze(bytes: fixture(name), hosts: otel, nodename: "myhost")
}

@MainActor
func hostsFileTests() {
    check("hosts: fixtures are found", !fixture("block-lf").isEmpty)
    for name in ["no-block", "comments-aliases"] {
        check("hosts: absent \(name)", run(name).state == .absent)
    }
    check(
        "hosts: empty is absent",
        HostsFile.analyze(bytes: [], hosts: otel, nodename: "h").state == .absent)

    for name in [
        "block-lf", "block-crlf", "block-eof-unterminated", "block-eof-crlf",
        "block-mixed-endings", "invalid-utf8", "nul-bytes",
    ] {
        check("hosts: current \(name)", run(name).state == .current)
    }
    for name in ["block-stale", "block-incomplete", "block-extra-line"] {
        check("hosts: stale \(name)", run(name).state == .stale)
    }
    let more = ["otel.example.com", "b.example.com"]
    check(
        "hosts: later names make it stale",
        HostsFile.analyze(bytes: fixture("block-lf"), hosts: more, nodename: "h").state == .stale)
    check(
        "hosts: no names makes any block stale",
        HostsFile.analyze(bytes: fixture("block-lf"), hosts: [], nodename: "h").state == .stale)
    check(
        "hosts: reordered names with a missing one are stale",
        HostsFile.analyze(
            bytes: fixture("block-lf"), hosts: ["b.example.com", "otel.example.com"],
            nodename: "h"
        ).state == .stale)

    for name in [
        "damaged-begin-only", "damaged-end-only", "damaged-end-before-begin",
        "damaged-repeated-begin", "damaged-repeated-end", "damaged-two-blocks",
        "malformed-trailing-space", "malformed-case", "malformed-suffix",
        "malformed-indented-comment", "malformed-eof-cr",
    ] {
        check("hosts: damaged \(name)", run(name).state == .damaged)
    }

    check(
        "hosts: conflicts are unmanaged non-loopback lines",
        run("conflicts").conflicts == [
            HostsConflict(line: 3, address: "10.0.0.5", host: "otel.example.com"),
            HostsConflict(line: 4, address: "0.0.0.0", host: "otel.example.com"),
        ])
    let inside = run("conflict-inside-block")
    check(
        "hosts: block content is not a conflict", inside.state == .stale && inside.conflicts.isEmpty
    )
    check(
        "hosts: conflicts survive comments, aliases, case",
        run("comments-aliases").conflicts.map { [String($0.line), $0.address] }
            == [["5", "10.1.1.1"]])
    check("hosts: damaged file has no conflicts here", run("damaged-begin-only").conflicts.isEmpty)
    let extra = fixture("damaged-begin-only") + Array("10.2.2.2 otel.example.com\n".utf8)
    check(
        "hosts: damaged file counts every line as unmanaged",
        HostsFile.analyze(bytes: extra, hosts: otel, nodename: "myhost").conflicts.count == 1)

    let names = [
        "otel.example.com", "x.localhost", "y.localdomain", "localhost.localdomain",
        "localhost6.localdomain6", "myhost.corp.example", "other.corp.example",
    ]
    check(
        "hosts: reserved names",
        HostsFile.analyze(bytes: fixture("no-block"), hosts: names, nodename: "MyHost.Corp.Example")
            .reserved == [
                "x.localhost", "y.localdomain", "localhost.localdomain",
                "localhost6.localdomain6", "myhost.corp.example",
            ])

    let two = ["myhost.corp.example", "otel.example.com"]
    check(
        "hosts: other node, none reserved",
        HostsFile.analyze(bytes: fixture("nodename-line"), hosts: two, nodename: "other-node")
            .reserved.isEmpty)
    check(
        "hosts: nodename alias reserves",
        HostsFile.analyze(bytes: fixture("nodename-line"), hosts: two, nodename: "myhost").reserved
            == ["myhost.corp.example"])
    check(
        "hosts: alias on a nodename line reserves",
        HostsFile.analyze(
            bytes: Array("127.0.1.1 mynode.lan mynode alias.example.com\n".utf8),
            hosts: ["alias.example.com"], nodename: "mynode"
        ).reserved == ["alias.example.com"])
    check(
        "hosts: the managed block doesn't count",
        HostsFile.analyze(bytes: fixture("block-lf"), hosts: otel, nodename: "otel.example.com")
            .reserved == ["otel.example.com"])

    // expectedBlock round-trips through the analysis.
    let block = HostsFile.expectedBlock(hosts: otel)
    check(
        "hosts: expected block shape",
        block == [
            HostsFile.beginMarker, "127.0.0.1 otel.example.com", "::1 otel.example.com",
            HostsFile.endMarker,
        ])
    check(
        "hosts: expected block is current",
        HostsFile.analyze(text: block.joined(separator: "\n") + "\n", hosts: otel, nodename: "h")
            .state
            == .current)

    // read(path:)
    let dir = scratchDirectory("hosts-read")
    let path = dir.appendingPathComponent("hosts").path
    try? Data(fixture("block-crlf")).write(to: URL(fileURLWithPath: path))
    let read = HostsFile.read(path: path, hosts: otel, nodename: "h")
    check("hosts: read analyzes", read.error == nil && read.analysis?.state == .current)
    check(
        "hosts: missing file is an error",
        HostsFile.read(path: dir.path + "/none", hosts: otel, nodename: "h").error != nil)
    check(
        "hosts: a directory is refused",
        HostsFile.read(path: dir.path, hosts: otel, nodename: "h").error != nil)
    let big = dir.appendingPathComponent("big").path
    try? Data(count: HostsFile.maxReadBytes + 1).write(to: URL(fileURLWithPath: big))
    check(
        "hosts: over 16 MiB is refused",
        HostsFile.read(path: big, hosts: otel, nodename: "h").error == "The file is too large")
    let atCap = dir.appendingPathComponent("cap").path
    try? Data(count: HostsFile.maxReadBytes).write(to: URL(fileURLWithPath: atCap))
    check(
        "hosts: exactly 16 MiB is read",
        HostsFile.read(path: atCap, hosts: otel, nodename: "h").analysis != nil)

    // Gating (hostsview.rs).
    func summary(_ state: BlockState, reserved: [String] = []) -> HostsFileSummary {
        HostsFileSummary(
            error: nil, analysis: HostsAnalysis(state: state, conflicts: [], reserved: reserved))
    }
    func hostNames(_ count: Int) -> [String] { (0..<count).map { "h\($0).example.com" } }
    let absent = HostsFile.gate(hosts: hostNames(1), file: summary(.absent))
    check(
        "gate: absent can add, not remove",
        absent.canEdit && !absent.canRemove && absent.editReason == nil)
    for state in [BlockState.current, .stale] {
        let gate = HostsFile.gate(hosts: hostNames(1), file: summary(state))
        check("gate: \(state) can update and remove", gate.canEdit && gate.canRemove)
    }
    let damaged = HostsFile.gate(hosts: hostNames(1), file: summary(.damaged))
    check(
        "gate: damaged blocks both",
        !damaged.canEdit && !damaged.canRemove && damaged.editReason != nil)
    let reserved = HostsFile.gate(
        hosts: hostNames(1), file: summary(.absent, reserved: hostNames(1)))
    check(
        "gate: reserved blocks add, names them",
        !reserved.canEdit && reserved.editReason?.contains("h0.example.com") == true)
    check(
        "gate: reserved keeps remove",
        HostsFile.gate(hosts: hostNames(1), file: summary(.stale, reserved: hostNames(1))).canRemove
    )
    check("gate: 8 names ok", HostsFile.gate(hosts: hostNames(8), file: summary(.absent)).canEdit)
    let nine = HostsFile.gate(hosts: hostNames(9), file: summary(.current))
    check(
        "gate: 9 names blocks add, keeps remove",
        !nine.canEdit && nine.canRemove && nine.editReason != nil)
    check("gate: no names blocks add", !HostsFile.gate(hosts: [], file: summary(.absent)).canEdit)
    let unreadable = HostsFile.gate(
        hosts: hostNames(1), file: HostsFileSummary(error: "Permission denied", analysis: nil))
    check(
        "gate: unreadable blocks both",
        !unreadable.canEdit && !unreadable.canRemove
            && unreadable.editReason?.contains("Permission denied") == true)
    let unread = HostsFile.gate(hosts: hostNames(1), file: nil)
    check("gate: not read yet blocks both", !unread.canEdit && !unread.canRemove)
    for why in [
        HostsUnsupported.symlink(target: "/etc/static/hosts"), .mountPoint, .unprotected,
        .hardlinked,
    ] {
        let gate = HostsFile.gate(
            hosts: hostNames(1),
            file: HostsFileSummary(
                error: nil,
                analysis: HostsAnalysis(state: .current, conflicts: [], reserved: []),
                unsupported: why))
        check(
            "gate: \(why) blocks add and remove",
            !gate.canEdit && !gate.canRemove && gate.unsupported == why
                && gate.editReason == why.reason)
    }
    check(
        "gate: symlink reason names the target",
        HostsUnsupported.symlink(target: "/etc/static/hosts").reason.contains("/etc/static/hosts"))

    inspectTests()
}

// The lstat checks, on injected stat results.
@MainActor
private func inspectTests() {
    let regular: UInt32 = 0o100644
    func file(
        mode: UInt32 = 0o100644, uid: UInt32 = 0, nlink: UInt32 = 1, dev: Int64 = 1
    ) -> HostsStat {
        HostsStat(mode: mode, uid: uid, nlink: nlink, dev: dev)
    }
    let etcHosts = "/etc/hosts"
    let real = HostsFile.canonicalPath
    func probe(
        _ table: [String: HostsStat], follow: [String: HostsStat] = [:],
        links: [String: String] = [:],
        dir: HostsStat? = HostsStat(
            mode: 0o040755, uid: 0, nlink: 5, dev: 1)
    ) -> HostsFileProbe {
        HostsFileProbe(
            linkInfo: { path in
                table[path].map { .success($0) } ?? .failure(HostsStatFailure(message: "ENOENT"))
            },
            fileInfo: { path in
                if path == HostsFile.canonicalDirectory {
                    return dir.map { .success($0) } ?? .failure(HostsStatFailure(message: "no dir"))
                }
                let found = follow[path] ?? table[path].flatMap { $0.isSymlink ? nil : $0 }
                return found.map { .success($0) } ?? .failure(HostsStatFailure(message: "dangling"))
            },
            linkTarget: { links[$0] })
    }
    func inspect(_ p: HostsFileProbe) -> HostsFile.Inspection {
        HostsFile.inspect(path: etcHosts, canonical: real, probe: p)
    }

    // The stock macOS layout: /etc is a link, but /etc/hosts is a plain root-owned file.
    let stock = inspect(probe([etcHosts: file(), real: file()]))
    check("inspect: stock file is fine", stock.unsupported == nil && stock.error == nil)
    check(
        "inspect: missing file is an error",
        inspect(probe([:])).error == "ENOENT" && inspect(probe([:])).unsupported == nil)
    check(
        "inspect: missing canonical twin is ignored",
        inspect(probe([etcHosts: file()])) == .init(unsupported: nil, error: nil))

    let link = inspect(
        probe(
            [etcHosts: file(mode: 0o120755, nlink: 1), real: file()],
            follow: [etcHosts: file()], links: [etcHosts: "/etc/static/hosts"]))
    check(
        "inspect: a symlink at /etc/hosts",
        link.unsupported == .symlink(target: "/etc/static/hosts") && link.error == nil)
    let canonicalLink = inspect(
        probe(
            [etcHosts: file(), real: file(mode: 0o120755)], follow: [real: file()],
            links: [real: "/somewhere"]))
    check(
        "inspect: a symlink at /private/etc/hosts",
        canonicalLink.unsupported == .symlink(target: "/somewhere"))
    let dangling = inspect(
        probe([etcHosts: file(mode: 0o120755)], links: [etcHosts: "/nowhere"]))
    check(
        "inspect: a dangling link is a symlink with an error",
        dangling.unsupported == .symlink(target: "/nowhere") && dangling.error == "dangling")
    check(
        "inspect: a link to a directory is not a regular file",
        inspect(
            probe(
                [etcHosts: file(mode: 0o120755)], follow: [etcHosts: file(mode: 0o040755)],
                links: [etcHosts: "/tmp"])
        ).error == "Not a regular file")
    check(
        "inspect: a FIFO is not a regular file",
        inspect(probe([etcHosts: file(mode: 0o010644)])).error == "Not a regular file")

    check(
        "inspect: owner must be root",
        inspect(probe([etcHosts: file(uid: 501), real: file(uid: 501)])).unsupported
            == .unprotected)
    check(
        "inspect: group-writable",
        inspect(probe([etcHosts: file(mode: regular | 0o020), real: file()])).unsupported
            == .unprotected)
    check(
        "inspect: world-writable",
        inspect(probe([etcHosts: file(mode: regular | 0o002), real: file()])).unsupported
            == .unprotected)
    check(
        "inspect: only the canonical file is writable",
        inspect(probe([etcHosts: file(), real: file(mode: regular | 0o022)])).unsupported
            == .unprotected)
    check(
        "inspect: read-only for others is fine",
        inspect(probe([etcHosts: file(mode: 0o100444), real: file(mode: 0o100444)])).unsupported
            == nil)
    check(
        "inspect: hard links",
        inspect(probe([etcHosts: file(nlink: 2), real: file(nlink: 2)])).unsupported
            == .hardlinked)
    check(
        "inspect: another device is a mount point",
        inspect(probe([etcHosts: file(dev: 9), real: file(dev: 9)])).unsupported == .mountPoint)
    check(
        "inspect: an unreadable directory skips the mount check",
        inspect(probe([etcHosts: file(dev: 9), real: file(dev: 9)], dir: nil)).unsupported == nil)
    check(
        "inspect: a mount point wins over the owner",
        inspect(probe([etcHosts: file(uid: 5, dev: 9), real: file(uid: 5, dev: 9)])).unsupported
            == .mountPoint)

    // The real thing: a temp file we own isn't root's, so it is "unprotected" but still read.
    let dir = scratchDirectory("hosts-inspect").path
    let path = dir + "/hosts"
    try? Data("127.0.0.1 localhost\n".utf8).write(to: URL(fileURLWithPath: path))
    let linkPath = dir + "/link"
    try? FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: path)
    let viaLink = HostsFile.read(path: linkPath, hosts: [], nodename: "h")
    check(
        "hosts: read follows a symlink but reports it (\(viaLink))",
        viaLink.analysis != nil && viaLink.unsupported == .symlink(target: path))
    let direct = HostsFile.read(path: path, hosts: [], nodename: "h")
    check(
        "hosts: read of a user-owned file reports it unprotected (\(direct))",
        direct.analysis != nil && direct.unsupported == .unprotected)
}

@MainActor
func hostLookupTests() async {
    check("lookup: loopback v4", HostLookup.classify(["127.0.0.1"]) == .here)
    check("lookup: 127/8", HostLookup.classify(["127.5.5.5"]) == .here)
    check("lookup: loopback v6", HostLookup.classify(["::1"]) == .here)
    check("lookup: v4-mapped loopback", HostLookup.classify(["::ffff:127.0.0.1"]) == .here)
    check("lookup: both loopbacks", HostLookup.classify(["::1", "127.0.0.1"]) == .here)
    check(
        "lookup: v4-mapped elsewhere",
        HostLookup.classify(["::ffff:10.0.0.1"]) == .elsewhere(["::ffff:10.0.0.1"]))
    check(
        "lookup: one other address",
        HostLookup.classify(["127.0.0.1", "10.0.0.5"]) == .elsewhere(["10.0.0.5"]))
    check("lookup: none is an error", HostLookup.classify([]) == .error("No address found"))

    let results = await HostLookup.check(
        ["a", "b", "c", "d"], timeout: 2,
        resolve: { name in
            switch name {
            case "a": return ["127.0.0.1"]
            case "b": return ["93.184.216.34"]
            case "c": return []
            default: throw HostLookup.Failure(message: "nodename nor servname provided")
            }
        })
    check("lookup: here", results["a"] == .here)
    check("lookup: elsewhere", results["b"] == .elsewhere(["93.184.216.34"]))
    check("lookup: no address", results["c"] == .error("No address found"))
    check("lookup: failure text", results["d"] == .error("nodename nor servname provided"))

    // A resolver that outlives the timer: the result is the timeout and the call returns.
    let started = Date()
    let slow = await HostLookup.check(
        ["slow", "fast"], timeout: 0.2,
        resolve: { name in
            if name == "slow" { Thread.sleep(forTimeInterval: 3) }
            return ["127.0.0.1"]
        })
    check("lookup: timeout result", slow["slow"] == .error("The lookup timed out"))
    check("lookup: fast name unaffected", slow["fast"] == .here)
    check("lookup: timeout doesn't await the resolver", Date().timeIntervalSince(started) < 2)

    let refused = await HostLookup.check(
        ["x"], timeout: 1, resolve: { _ in ["127.0.0.1"] }, start: { _ in false })
    check("lookup: couldn't start", refused["x"] == .error("Couldn't start a lookup"))
}
