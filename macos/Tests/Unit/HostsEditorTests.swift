import Foundation

// Tests for HostsEditor.swift: the helper check with fakes, the pure script builders, and the
// mapping of osascript results (nothing here runs osascript, sudo or pfctl).

private let req =
    "identifier \"ua.SkeLLLa.cAInary.hosts-helper\" and certificate leaf = H\"abc123\""
private let helperPath = "/Applications/cAInary.app/Contents/Helpers/cainary-hosts-helper"

private func probe(
    real: [String: String]? = nil,
    info: (isRegular: Bool, mode: UInt16)? = (true, 0o755),
    leaf: String? = "abc123", valid: Bool = true
) -> HostsHelperProbe {
    let table =
        real ?? [
            "/Applications/cAInary.app": "/Applications/cAInary.app",
            helperPath: helperPath,
        ]
    return HostsHelperProbe(
        realpath: { table[$0] }, fileInfo: { _ in info }, ownLeafSHA1: { leaf },
        satisfies: { _, r in valid && r == req })
}

private let bundle = URL(fileURLWithPath: "/Applications/cAInary.app")

private func result(_ out: String, err: String = "", status: Int32 = 0, timedOut: Bool = false)
    -> HostsEditor.ProcessResult
{
    .init(stdout: out, stderr: err, status: status, timedOut: timedOut)
}

private func hostsRefused(_ build: () throws -> String) -> HostsEditError? {
    do {
        _ = try build()
        return nil
    } catch { return error as? HostsEditError }
}

@MainActor
func hostsEditorTests() async {
    // Helper check.
    check(
        "editor: ready",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe()) == .ready(requirement: req))
    check(
        "editor: ad-hoc build",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(leaf: nil))
            == .unavailable(HostsHelperCheck.unsignedReason))
    check(
        "editor: missing helper",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(real: [:]))
            == .unavailable(HostsHelperCheck.missingReason))
    check(
        "editor: symlink out of the bundle",
        HostsHelperCheck.check(
            bundleURL: bundle,
            probe: probe(real: [
                "/Applications/cAInary.app": "/Applications/cAInary.app", helperPath: "/tmp/evil",
            ])) == .unavailable(HostsHelperCheck.outsideReason))
    check(
        "editor: sibling prefix is outside",
        HostsHelperCheck.check(
            bundleURL: bundle,
            probe: probe(real: [
                "/Applications/cAInary.app": "/Applications/cAInary.app",
                helperPath: "/Applications/cAInary.app2/x",
            ])) == .unavailable(HostsHelperCheck.outsideReason))
    check(
        "editor: group-writable helper",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(info: (true, 0o775)))
            == .unavailable(HostsHelperCheck.notFileReason))
    check(
        "editor: other-writable helper",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(info: (true, 0o757)))
            == .unavailable(HostsHelperCheck.notFileReason))
    check(
        "editor: not a regular file",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(info: (false, 0o755)))
            == .unavailable(HostsHelperCheck.notFileReason))
    check(
        "editor: unreadable file",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(info: nil))
            == .unavailable(HostsHelperCheck.notFileReason))
    check(
        "editor: failed signature",
        HostsHelperCheck.check(bundleURL: bundle, probe: probe(valid: false))
            == .unavailable(HostsHelperCheck.failedReason))
    check(
        "editor: requirement text",
        HostsHelperCheck.requirement(leafSHA1: "abc123") == req)

    // Script builder: rejections.
    func hosts(_ list: [String], op: HostsOp = .set, uid: UInt32 = 501) -> HostsEditError? {
        hostsRefused {
            try HostsEditor.hostsScript(
                op: op, hosts: list, uid: uid, helperPath: helperPath, requirement: req)
        }
    }
    check("editor: quote rejected", hosts(["a'b.example.com"]) == .badHost("a'b.example.com"))
    check("editor: backslash rejected", hosts(["a\\b.example.com"]) == .badHost("a\\b.example.com"))
    check("editor: dquote rejected", hosts(["a\"b.example.com"]) != nil)
    check("editor: newline rejected", hosts(["a.example.com\nb.example.com"]) != nil)
    check("editor: NUL rejected", hosts(["a\u{0}.example.com"]) != nil)
    check("editor: escape rejected", hosts(["a\u{1b}.example.com"]) != nil)
    check("editor: DEL rejected", hosts(["a\u{7f}.example.com"]) != nil)
    check("editor: space rejected", hosts(["a b.example.com"]) != nil)
    check("editor: semicolon rejected", hosts(["a.example.com;id"]) != nil)
    check("editor: dollar rejected", hosts(["$(id).example.com"]) != nil)
    check("editor: uppercase rejected", hosts(["A.example.com"]) != nil)
    check("editor: unicode rejected", hosts(["é.example.com"]) != nil)
    check("editor: one label rejected", hosts(["localhost"]) != nil)
    check("editor: IP rejected", hosts(["1.2.3.4"]) != nil)
    check("editor: leading hyphen rejected", hosts(["-a.example.com"]) != nil)
    check("editor: empty label rejected", hosts(["a..example.com"]) != nil)
    check("editor: wildcard rejected", hosts(["*.example.com"]) != nil)
    check("editor: empty list rejected", hosts([]) == .noHosts)
    let nine = (0..<9).map { "h\($0).example.com" }
    check("editor: nine names rejected", hosts(nine) == .tooManyHosts)
    check("editor: eight names accepted", hosts(Array(nine.prefix(8))) == nil)
    check("editor: duplicates rejected", hosts(["a.example.com", "a.example.com"]) != nil)
    check("editor: clear with names rejected", hosts(["a.example.com"], op: .clear) != nil)
    check("editor: clear accepted", hosts([], op: .clear) == nil)
    check("editor: bad uid rejected", hosts(["a.example.com"], uid: UInt32.max) == .badUID)
    check(
        "editor: relative helper rejected",
        hostsRefused {
            try HostsEditor.hostsScript(
                op: .clear, hosts: [], uid: 1, helperPath: "h", requirement: req)
        } == .badPath)
    check(
        "editor: control char in requirement rejected",
        hostsRefused {
            try HostsEditor.hostsScript(
                op: .clear, hosts: [], uid: 1, helperPath: helperPath, requirement: "a\nb")
        } == .badRequirement)

    // Quoting.
    check("editor: shell quote", HostsEditor.shellQuote("a'b") == "'a'\\''b'")
    check(
        "editor: applescript escape",
        HostsEditor.appleScriptEscape("a\\b\"c\nd") == "a\\\\b\\\"c\\nd")

    // Goldens.
    let setScript = try? HostsEditor.hostsScript(
        op: .set, hosts: ["otel.example-corp.test"], uid: 501, helperPath: helperPath,
        requirement: req)
    let expectedSet = #"""
        do shell script "d=$(/usr/bin/mktemp -d /private/var/tmp/cainary-hosts.XXXXXX) || { /usr/bin/printf '%s\\n' 'cainary-hosts-helper/1 error no-workdir'; exit 0; }\ntrap '/bin/rm -rf \"$d\"' EXIT\n/bin/cp '/Applications/cAInary.app/Contents/Helpers/cainary-hosts-helper' \"$d/h\" || { /usr/bin/printf '%s\\n' 'cainary-hosts-helper/1 error no-workdir'; exit 0; }\n/usr/bin/codesign --verify --strict '-R=identifier \"ua.SkeLLLa.cAInary.hosts-helper\" and certificate leaf = H\"abc123\"' \"$d/h\" >/dev/null 2>&1 || { /usr/bin/printf '%s\\n' 'cainary-hosts-helper/1 error untrusted-helper'; exit 0; }\nr=$(CAINARY_HOSTS_UID='501' \"$d/h\" 'set' 'otel.example-corp.test' 2>/dev/null); s=$?\nif [ -z \"$r\" ]; then /usr/bin/printf 'no-reply status=%s\\n' \"$s\"; exit 0; fi\n/usr/bin/printf '%s\\n' \"$r\"\ncase \"$r\" in 'cainary-hosts-helper/1 ok'*) /usr/bin/dscacheutil -flushcache && /usr/bin/killall -HUP mDNSResponder || /usr/bin/printf '%s\\n' 'flush-failed';; esac\nexit 0" with prompt "cAInary wants to add its lines to /etc/hosts." with administrator privileges without altering line endings
        """#
    check("editor: set golden", setScript == expectedSet)
    if setScript != expectedSet { print(setScript ?? "nil") }

    let clearScript = try? HostsEditor.hostsScript(
        op: .clear, hosts: [], uid: 501, helperPath: helperPath, requirement: req)
    check(
        "editor: clear golden",
        clearScript?.contains(#"\"$d/h\" 'clear' 2>/dev/null); s=$?"#) == true
            && clearScript?.contains(
                "with prompt \"cAInary wants to remove its lines from /etc/hosts.\"") == true
    )

    let redirectSet = try? HostsEditor.redirectScript(op: .set, port: 8443)
    let expectedRedirectSet = #"""
        do shell script "/usr/bin/printf '%s\\n' 'rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443' 'rdr pass on lo0 inet6 proto tcp from any to ::1 port 443 -> ::1 port 8443' | /sbin/pfctl -a com.apple/cainary -f - >/dev/null 2>&1; s=$?\nif [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"cainary-redirect/1 error pfctl $s\"; exit 0; fi\n/sbin/pfctl -E >/dev/null 2>&1; s=$?\nif [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"cainary-redirect/1 error pfctl $s\"; exit 0; fi\n/usr/bin/printf '%s\\n' 'cainary-redirect/1 ok set'\nexit 0" with prompt "cAInary wants to redirect port 443 to port 8443 on this Mac." with administrator privileges without altering line endings
        """#
    check("editor: redirect set golden", redirectSet == expectedRedirectSet)
    if redirectSet != expectedRedirectSet { print(redirectSet ?? "nil") }
    let redirectClear = try? HostsEditor.redirectScript(op: .clear, port: nil)
    let expectedRedirectClear = #"""
        do shell script "/sbin/pfctl -a com.apple/cainary -F all >/dev/null 2>&1; s=$?\nif [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"cainary-redirect/1 error pfctl $s\"; exit 0; fi\n/usr/bin/printf '%s\\n' 'cainary-redirect/1 ok clear'\nexit 0" with prompt "cAInary wants to remove its port 443 redirect." with administrator privileges without altering line endings
        """#
    check("editor: redirect clear golden", redirectClear == expectedRedirectClear)
    if redirectClear != expectedRedirectClear { print(redirectClear ?? "nil") }

    // The rules are the ones the setup text prints.
    let golden = try? String(
        contentsOf: repoRoot().appendingPathComponent(
            "crates/cainary-net/tests/golden/takeover-macos-redirect.txt"), encoding: .utf8)
    check(
        "editor: rules match the setup golden",
        HostsEditor.redirectRules(port: 8443).allSatisfy { golden?.contains("'\($0)'") == true })

    for port in [0, 80, 443, 1023, 65536, -1, 100_000] {
        check(
            "editor: port \(port) rejected",
            hostsRefused { try HostsEditor.redirectScript(op: .set, port: port) } == .badPort)
    }
    check(
        "editor: port nil on set rejected",
        hostsRefused { try HostsEditor.redirectScript(op: .set, port: nil) } == .badPort)
    check(
        "editor: port on clear rejected",
        hostsRefused { try HostsEditor.redirectScript(op: .clear, port: 8443) } == .badPort)
    check(
        "editor: ports 1024 and 65535 accepted",
        hostsRefused { try HostsEditor.redirectScript(op: .set, port: 1024) } == nil
            && hostsRefused { try HostsEditor.redirectScript(op: .set, port: 65535) } == nil)

    // Reply parsing.
    func edit(_ op: HostsOp, _ r: HostsEditor.ProcessResult) -> HostsEditOutcome {
        HostsReply.outcome(op: op, r)
    }
    let p = "cainary-hosts-helper/1"
    check(
        "editor: set changed",
        edit(.set, result("\(p) ok set changed\n"))
            == .done(changed: true, synced: true, message: ""))
    check(
        "editor: set unchanged",
        edit(.set, result("\(p) ok set unchanged\n"))
            == .done(changed: false, synced: true, message: ""))
    check(
        "editor: clear unchanged",
        edit(.clear, result("\(p) ok clear unchanged\n"))
            == .done(changed: false, synced: true, message: "No cAInary lines in /etc/hosts."))
    check(
        "editor: clear changed has the backup note",
        edit(.clear, result("\(p) ok clear changed\n"))
            == .done(changed: true, synced: true, message: HostsReply.backupNote))
    if case .done(true, false, let m) = edit(.set, result("\(p) ok set changed-unsynced\n")) {
        check("editor: unsynced add", m.hasPrefix("The lines were added, but"))
    } else {
        check("editor: unsynced add", false)
    }
    if case .done(true, false, let m) = edit(.clear, result("\(p) ok clear changed-unsynced\n")) {
        check("editor: unsynced remove", m.hasPrefix("The lines were removed, but"))
    } else {
        check("editor: unsynced remove", false)
    }
    if case .done(_, _, let m) = edit(.set, result("\(p) ok set changed\nflush-failed\n")) {
        check(
            "editor: flush-failed note",
            m.hasPrefix("The DNS cache wasn't flushed; run sudo dscacheutil -flushcache"))
    } else {
        check("editor: flush-failed note", false)
    }
    for token in [
        "bad-args", "not-pkexec", "reserved-name", "too-many", "symlink", "not-regular",
        "unprotected", "mount-point", "no-mount-id", "hardlinked", "too-large", "damaged-block",
        "bad-lock", "busy", "changed", "label", "read-only", "write-failed", "untrusted-helper",
        "no-workdir",
    ] {
        if case .refused(let t, let m) = edit(.set, result("\(p) error \(token)\n")) {
            check(
                "editor: token \(token)",
                t == token && m.hasSuffix("Nothing changed.") && !m.isEmpty)
        } else {
            check("editor: token \(token)", false)
        }
    }
    check(
        "editor: not-pkexec wording",
        HostsReply.refusalText("not-pkexec").contains("not run through the admin prompt"))
    check(
        "editor: untrusted-helper wording",
        HostsReply.refusalText("untrusted-helper")
            == "The helper failed its signature check, so nothing changed.")
    check(
        "editor: cancel",
        edit(
            .set,
            result("", err: "execution error: User canceled. (-128)\n", status: 1))
            == .cancelled(message: "Nothing changed. The authentication was cancelled."))
    // A failed authentication is a refusal, not "uncertain"; -128 stays a cancel.
    for text in [
        "execution error: The authorization was denied. (-60005)",
        "execution error: The administrator user name or password was incorrect. (-60007)",
        "errAuthorizationDenied",
    ] {
        check(
            "editor: auth failure \(text.suffix(12))",
            edit(.set, result("", err: text, status: 1))
                == .refused(
                    token: "not-authorized",
                    message: "Not authorized to change /etc/hosts. Nothing changed."))
        check(
            "editor: redirect auth failure \(text.suffix(12))",
            RedirectReply.outcome(op: .set, result("", err: text, status: 1))
                == .failed(message: "Not authorized to change the redirect. Nothing changed."))
    }
    check(
        "editor: -128 with auth words is still a cancel",
        edit(.clear, result("", err: "User canceled. (-128)", status: 1))
            == .cancelled(message: "Nothing changed. The authentication was cancelled."))
    check(
        "editor: a helper reply beats auth text",
        edit(.set, result("\(p) ok set changed\n", err: "(-60005)"))
            == .done(changed: true, synced: true, message: ""))
    check(
        "editor: other osascript errors stay uncertain",
        {
            if case .uncertain = edit(.set, result("", err: "(-1708)", status: 1)) {
                true
            } else {
                false
            }
        }()
    )
    for (token, word) in [
        ("symlink", "a link"), ("not-regular", "regular file"), ("unprotected", "other than root"),
        ("mount-point", "mounted"), ("no-mount-id", "mounted"),
        ("hardlinked", "more than one link"),
        ("too-large", "too large"), ("bad-lock", "lock"), ("write-failed", "Writing"),
    ] {
        check(
            "editor: wording for \(token)",
            HostsReply.refusalText(token).contains(word)
                && !HostsReply.refusalText(token).contains("(\(token))"))
    }
    for (name, r) in [
        ("empty", result("")), ("garbled", result("hello\n")),
        ("wrong op", result("\(p) ok clear changed\n")),
        ("bad word", result("\(p) ok set maybe\n")),
        ("extra words", result("\(p) ok set changed now\n")),
        ("no-reply", result("no-reply status=3\n")),
        ("osascript failed", result("", err: "execution error: nope (-1)", status: 1)),
        ("timeout", result("", timedOut: true)),
    ] {
        if case .uncertain = edit(.set, r) {
            check("editor: uncertain \(name)", true)
        } else {
            check("editor: uncertain \(name)", false)
        }
    }
    if case .notRun = edit(
        .set, .init(stdout: "", stderr: "", status: -1, spawnError: "no such file"))
    {
        check("editor: spawn failure is not-run", true)
    } else {
        check("editor: spawn failure is not-run", false)
    }

    // Redirect replies.
    let q = "cainary-redirect/1"
    check(
        "editor: redirect set ok",
        {
            if case .done = RedirectReply.outcome(op: .set, result("\(q) ok set\n")) {
                true
            } else {
                false
            }
        }())
    check(
        "editor: redirect clear ok",
        {
            if case .done = RedirectReply.outcome(op: .clear, result("\(q) ok clear\n")) {
                true
            } else {
                false
            }
        }())
    check(
        "editor: redirect pfctl error",
        {
            if case .failed = RedirectReply.outcome(op: .set, result("\(q) error pfctl 1\n")) {
                true
            } else {
                false
            }
        }())
    check(
        "editor: redirect cancel",
        {
            if case .cancelled = RedirectReply.outcome(
                op: .set, result("", err: "(-128)", status: 1))
            {
                true
            } else {
                false
            }
        }())
    for (name, op, r) in [
        ("empty", HostsOp.set, result("")), ("wrong op", .clear, result("\(q) ok set\n")),
        ("garbled", .set, result("\(q) error pfctl x\n")),
    ] {
        if case .uncertain = RedirectReply.outcome(op: op, r) {
            check("editor: redirect uncertain \(name)", true)
        } else {
            check("editor: redirect uncertain \(name)", false)
        }
    }

    // run: the injected runner gets exactly the built script.

    let box = SeenBox()
    let outcome = await HostsEditor.editHosts(
        op: .set, hosts: ["a.example.com"], uid: 501, helperPath: helperPath, requirement: req,
        runner: { s in
            await box.set(s)
            return result("\(p) ok set changed\n")
        })
    let seen = await box.value
    check("editor: run maps the reply", outcome == .done(changed: true, synced: true, message: ""))
    check("editor: run passes the script", seen.contains("'set' 'a.example.com'"))
    let bad = await HostsEditor.editHosts(
        op: .set, hosts: ["a'.example.com"], uid: 501, helperPath: helperPath, requirement: req,
        runner: { _ in
            await box.set("RAN")
            return result("")
        })
    let ranBad = await box.value == "RAN"
    if case .notRun = bad {
        check("editor: invalid host is never run", !ranBad)
    } else {
        check("editor: invalid host is never run", false)
    }
}

private actor SeenBox {
    var value = ""
    func set(_ v: String) { value = v }
}
