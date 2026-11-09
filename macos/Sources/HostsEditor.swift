import CryptoKit
import Darwin
import Foundation
import Security

// The one-click edits behind the takeover guide: the /etc/hosts block through the signed
// cainary-hosts-helper, and the pf redirect through fixed commands. Both run as root through one
// `osascript` admin prompt. Three parts:
//   - HostsHelperCheck: finds the bundled helper and decides whether it is the one this app was
//     signed with (same leaf certificate, same identifier), or why one-click is unavailable;
//   - HostsEditor.hostsScript / redirectScript: pure builders of the AppleScript source;
//   - HostsEditor.editHosts / editRedirect: run osascript and map the reply to an outcome.
// Wording of the outcomes mirrors linux/crates/tray-model/src/hostsview.rs.

// MARK: - Helper check

enum HostsHelperStatus: Equatable, Sendable {
    /// The helper is inside the bundle and passes `requirement` (also re-checked on the root copy).
    case ready(requirement: String)
    case unavailable(String)
}

/// The system calls `HostsHelperCheck` makes, so tests can fake every answer.
struct HostsHelperProbe: Sendable {
    /// The canonical path, or nil when it doesn't exist.
    var realpath: @Sendable (String) -> String?
    /// Whether the path is a regular file, and its permission bits; nil when it can't be read.
    var fileInfo: @Sendable (String) -> (isRegular: Bool, mode: UInt16)?
    /// Hex SHA-1 of this app's signing leaf certificate; nil for an ad-hoc or unsigned build.
    var ownLeafSHA1: @Sendable () -> String?
    /// Whether the code at the path satisfies the requirement text.
    var satisfies: @Sendable (String, String) -> Bool

    static let system = HostsHelperProbe(
        realpath: { path in
            guard let resolved = Darwin.realpath(path, nil) else { return nil }
            defer { free(resolved) }
            return String(cString: resolved)
        },
        fileInfo: { path in
            var st = stat()
            guard stat(path, &st) == 0 else { return nil }
            return (st.st_mode & S_IFMT == S_IFREG, UInt16(st.st_mode & 0o7777))
        },
        ownLeafSHA1: { SigningInfo.ownLeafSHA1() },
        satisfies: { path, requirement in
            SigningInfo.satisfies(path: path, requirement: requirement)
        }
    )
}

enum HostsHelperCheck {
    static let identifier = "ua.SkeLLLa.cAInary.hosts-helper"
    static let relativePath = "Contents/Helpers/cainary-hosts-helper"

    static let unsignedReason =
        "One-click editing needs a signed cAInary build. Add the lines below yourself."
    static let missingReason =
        "The hosts helper is missing from this copy of cAInary. Add the lines below yourself."
    static let outsideReason =
        "The hosts helper isn't inside the app, so it isn't trusted. Add the lines below yourself."
    static let notFileReason =
        "The hosts helper isn't a plain file that only its owner can change, so it isn't trusted. Add the lines below yourself."
    static let failedReason =
        "The hosts helper failed its signature check, so it isn't trusted. Add the lines below yourself."

    static func requirement(leafSHA1: String) -> String {
        "identifier \"\(identifier)\" and certificate leaf = H\"\(leafSHA1)\""
    }

    /// The helper path inside `bundleURL` (not yet checked).
    static func helperPath(bundleURL: URL) -> String {
        bundleURL.appendingPathComponent(relativePath).path
    }

    /// Where the checked helper is; only meaningful after `.ready`.
    static func check(
        bundleURL: URL = Bundle.main.bundleURL, probe: HostsHelperProbe = .system
    ) -> HostsHelperStatus {
        let path = helperPath(bundleURL: bundleURL)
        guard let real = probe.realpath(path), let bundleReal = probe.realpath(bundleURL.path)
        else { return .unavailable(missingReason) }
        let root = bundleReal.hasSuffix("/") ? bundleReal : bundleReal + "/"
        guard real.hasPrefix(root) else { return .unavailable(outsideReason) }
        guard let info = probe.fileInfo(real), info.isRegular, info.mode & 0o022 == 0 else {
            return .unavailable(notFileReason)
        }
        guard let leaf = probe.ownLeafSHA1(), !leaf.isEmpty else {
            return .unavailable(unsignedReason)
        }
        let requirement = requirement(leafSHA1: leaf)
        guard probe.satisfies(real, requirement) else { return .unavailable(failedReason) }
        return .ready(requirement: requirement)
    }
}

/// The Security.framework calls behind `HostsHelperProbe.system`.
enum SigningInfo {
    static func ownLeafSHA1() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode
        else { return nil }
        var info: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                == errSecSuccess,
            let dict = info as? [String: Any],
            let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
            let leaf = certs.first
        else { return nil }
        let der = SecCertificateCopyData(leaf) as Data
        return Insecure.SHA1.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }

    static func satisfies(path: String, requirement: String) -> Bool {
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode)
                == errSecSuccess, let staticCode
        else { return false }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess,
            let req
        else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        return SecStaticCodeCheckValidity(staticCode, flags, req) == errSecSuccess
    }
}

// MARK: - Script building

enum HostsEditError: Error, Equatable, Sendable {
    case noHosts
    case tooManyHosts
    case badHost(String)
    case badPort
    case badUID
    case badRequirement
    case badPath
}

enum HostsOp: String, Sendable {
    case set
    case clear
}

enum HostsEditor {
    static let helperProtocol = "cainary-hosts-helper/1"
    static let redirectProtocol = "cainary-redirect/1"
    static let maxHosts = 8
    static let timeout: TimeInterval = 300
    static let pfAnchor = "com.apple/cainary"

    // MARK: quoting and validation

    /// `'…'` with each `'` as `'\''`.
    static func shellQuote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// The text as the inside of an AppleScript string literal. Newlines become `\n`.
    static func appleScriptEscape(_ text: String) -> String {
        var out = ""
        for ch in text.unicodeScalars {
            switch ch {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            default: out.unicodeScalars.append(ch)
            }
        }
        return out
    }

    /// The helper's own name rule: lowercase DNS labels, at least two, no IP-address shape.
    static func validHost(_ host: String) -> Bool {
        let bytes = Array(host.utf8)
        guard !bytes.isEmpty, bytes.count <= 253 else { return false }
        let labels = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        func labelOK(_ label: ArraySlice<UInt8>) -> Bool {
            guard !label.isEmpty, label.count <= 63, label.first != UInt8(ascii: "-"),
                label.last != UInt8(ascii: "-")
            else { return false }
            return label.allSatisfy {
                ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                    || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                    || $0 == UInt8(ascii: "-")
            }
        }
        guard labels.allSatisfy(labelOK) else { return false }
        return !labels[labels.count - 1].allSatisfy {
            $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9")
        }
    }

    /// A path or requirement that can be quoted safely: printable ASCII, no control characters.
    private static func printable(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7f }
    }

    private static func admin(_ command: String, prompt: String) -> String {
        "do shell script \"\(appleScriptEscape(command))\" with prompt \"\(appleScriptEscape(prompt))\""
            + " with administrator privileges without altering line endings"
    }

    // MARK: hosts script

    /// AppleScript source that copies the helper into a fresh root-owned directory, re-verifies the
    /// copy's signature, runs it and prints its reply (then flushes the DNS cache when it said ok).
    /// `helperPath` is the checked helper in the bundle; `requirement` is `HostsHelperStatus.ready`'s.
    static func hostsScript(
        op: HostsOp, hosts: [String], uid: UInt32, helperPath: String, requirement: String
    ) throws -> String {
        switch op {
        case .set:
            guard !hosts.isEmpty else { throw HostsEditError.noHosts }
            guard hosts.count <= maxHosts else { throw HostsEditError.tooManyHosts }
            if let bad = hosts.first(where: { !validHost($0) }) {
                throw HostsEditError.badHost(bad)
            }
            guard Set(hosts).count == hosts.count else {
                throw HostsEditError.badHost(
                    hosts.first { h in hosts.filter { $0 == h }.count > 1 } ?? "")
            }
        case .clear:
            guard hosts.isEmpty else { throw HostsEditError.badHost(hosts[0]) }
        }
        guard uid != UInt32.max else { throw HostsEditError.badUID }
        guard printable(helperPath), helperPath.hasPrefix("/") else { throw HostsEditError.badPath }
        guard printable(requirement) else { throw HostsEditError.badRequirement }

        let proto = helperProtocol
        let helperArgs = ([op.rawValue] + hosts).map(shellQuote).joined(separator: " ")
        let lines = [
            "d=$(/usr/bin/mktemp -d /private/var/tmp/cainary-hosts.XXXXXX) || { /usr/bin/printf '%s\\n' '\(proto) error no-workdir'; exit 0; }",
            "trap '/bin/rm -rf \"$d\"' EXIT",
            "/bin/cp \(shellQuote(helperPath)) \"$d/h\" || { /usr/bin/printf '%s\\n' '\(proto) error no-workdir'; exit 0; }",
            "/usr/bin/codesign --verify --strict \(shellQuote("-R=" + requirement)) \"$d/h\" >/dev/null 2>&1 || { /usr/bin/printf '%s\\n' '\(proto) error untrusted-helper'; exit 0; }",
            "r=$(CAINARY_HOSTS_UID=\(shellQuote(String(uid))) \"$d/h\" \(helperArgs) 2>/dev/null); s=$?",
            "if [ -z \"$r\" ]; then /usr/bin/printf 'no-reply status=%s\\n' \"$s\"; exit 0; fi",
            "/usr/bin/printf '%s\\n' \"$r\"",
            "case \"$r\" in '\(proto) ok'*) /usr/bin/dscacheutil -flushcache && /usr/bin/killall -HUP mDNSResponder || /usr/bin/printf '%s\\n' 'flush-failed';; esac",
            "exit 0",
        ]
        let prompt =
            op == .set
            ? "cAInary wants to add its lines to /etc/hosts."
            : "cAInary wants to remove its lines from /etc/hosts."
        return admin(lines.joined(separator: "\n"), prompt: prompt)
    }

    // MARK: redirect script

    /// The two pf rules, exactly as the setup text prints them.
    static func redirectRules(port: Int) -> [String] {
        [
            "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port \(port)",
            "rdr pass on lo0 inet6 proto tcp from any to ::1 port 443 -> ::1 port \(port)",
        ]
    }

    /// `port` is the redirect target for a set; nil for a clear.
    static func redirectScript(op: HostsOp, port: Int?) throws -> String {
        let proto = redirectProtocol
        switch op {
        case .set:
            guard let port, (1024...65535).contains(port) else { throw HostsEditError.badPort }
            let rules = redirectRules(port: port).map(shellQuote).joined(separator: " ")
            let lines = [
                "/usr/bin/printf '%s\\n' \(rules) | /sbin/pfctl -a \(pfAnchor) -f - >/dev/null 2>&1; s=$?",
                "if [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"\(proto) error pfctl $s\"; exit 0; fi",
                "/sbin/pfctl -E >/dev/null 2>&1; s=$?",
                "if [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"\(proto) error pfctl $s\"; exit 0; fi",
                "/usr/bin/printf '%s\\n' '\(proto) ok set'",
                "exit 0",
            ]
            return admin(
                lines.joined(separator: "\n"),
                prompt: "cAInary wants to redirect port 443 to port \(port) on this Mac.")
        case .clear:
            guard port == nil else { throw HostsEditError.badPort }
            let lines = [
                "/sbin/pfctl -a \(pfAnchor) -F all >/dev/null 2>&1; s=$?",
                "if [ \"$s\" -ne 0 ]; then /usr/bin/printf '%s\\n' \"\(proto) error pfctl $s\"; exit 0; fi",
                "/usr/bin/printf '%s\\n' '\(proto) ok clear'",
                "exit 0",
            ]
            return admin(
                lines.joined(separator: "\n"),
                prompt: "cAInary wants to remove its port 443 redirect.")
        }
    }

    // MARK: running

    struct ProcessResult: Equatable, Sendable {
        var stdout: String
        var stderr: String
        var status: Int32
        var timedOut: Bool = false
        /// Set when osascript couldn't be started.
        var spawnError: String? = nil
    }

    /// Runs a script source and returns what osascript did. Replaced in tests.
    typealias Runner = @Sendable (String) async -> ProcessResult

    static let osascript: Runner = { script in
        await runOsascript(script, timeout: timeout)
    }

    static func editHosts(
        op: HostsOp, hosts: [String], uid: UInt32 = getuid(), helperPath: String,
        requirement: String, runner: Runner = osascript
    ) async -> HostsEditOutcome {
        let script: String
        do {
            script = try hostsScript(
                op: op, hosts: hosts, uid: uid, helperPath: helperPath, requirement: requirement)
        } catch {
            return HostsReply.notRun(op, "invalid request (\(error))")
        }
        return HostsReply.outcome(op: op, await runner(script))
    }

    static func editRedirect(
        op: HostsOp, port: Int?, runner: Runner = osascript
    ) async -> RedirectOutcome {
        let script: String
        do {
            script = try redirectScript(op: op, port: port)
        } catch {
            return .notRun(
                message: "Couldn't build the redirect command (\(error)). Nothing changed.")
        }
        return RedirectReply.outcome(op: op, await runner(script))
    }

    // MARK: osascript process

    private final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        func set(_ value: Data) {
            lock.lock()
            data = value
            lock.unlock()
        }
        var text: String {
            lock.lock()
            defer { lock.unlock() }
            return String(decoding: data, as: UTF8.self)
        }
    }

    static func runOsascript(_ script: String, timeout: TimeInterval) async -> ProcessResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: runOsascriptBlocking(script, timeout: timeout))
            }
        }
    }

    private static func runOsascriptBlocking(_ script: String, timeout: TimeInterval)
        -> ProcessResult
    {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-"]
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            return ProcessResult(
                stdout: "", stderr: "", status: -1, spawnError: error.localizedDescription)
        }
        let out = Capture()
        let err = Capture()
        let readers = DispatchGroup()
        for (pipe, box) in [(stdout, out), (stderr, err)] {
            readers.enter()
            DispatchQueue.global().async {
                box.set((try? pipe.fileHandleForReading.readToEnd()) ?? Data())
                readers.leave()
            }
        }
        try? stdin.fileHandleForWriting.write(contentsOf: Data(script.utf8))
        try? stdin.fileHandleForWriting.close()

        var timedOut = false
        if exited.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            process.terminate()
            _ = exited.wait(timeout: .now() + 5)
        }
        _ = readers.wait(timeout: .now() + 5)
        return ProcessResult(
            stdout: out.text, stderr: err.text,
            status: process.isRunning ? -1 : process.terminationStatus, timedOut: timedOut)
    }
}

// MARK: - Outcomes

/// What one hosts edit came to. After `uncertain` (and `refused`) the caller re-reads /etc/hosts;
/// nothing is retried automatically.
enum HostsEditOutcome: Equatable, Sendable {
    /// The helper finished. `message` is empty when the step already says everything.
    case done(changed: Bool, synced: Bool, message: String)
    case cancelled(message: String)
    /// Nothing was run: the request or the prompt couldn't be made.
    case notRun(message: String)
    case refused(token: String, message: String)
    case uncertain(message: String)
}

enum RedirectOutcome: Equatable, Sendable {
    case done(message: String)
    case cancelled(message: String)
    case notRun(message: String)
    case failed(message: String)
    case uncertain(message: String)
}

enum HostsReply {
    static let backupNote =
        "No cAInary lines in /etc/hosts. The previous version is saved as /etc/hosts.cainary-backup (readable by root)."
    static let flushNote =
        "The DNS cache wasn't flushed; run sudo dscacheutil -flushcache and sudo killall -HUP mDNSResponder."

    /// osascript's cancel: error -128, "User canceled." on stderr.
    static func isCancel(_ result: HostsEditor.ProcessResult) -> Bool {
        result.stderr.contains("(-128)") || result.stderr.contains("User canceled")
    }

    /// The admin prompt rejected the credentials or the user isn't allowed to authorize: -60005
    /// (errAuthorizationDenied), -60007 and -60008, or their text. Not a cancel (-128).
    static func isAuthFailure(_ result: HostsEditor.ProcessResult) -> Bool {
        let text = result.stderr
        return ["-60005", "-60007", "-60008", "errAuthorizationDenied"].contains {
            text.contains($0)
        }
            || text.localizedCaseInsensitiveContains("password was incorrect")
            || text.localizedCaseInsensitiveContains("authorization was denied")
            || text.localizedCaseInsensitiveContains("not authorized")
    }

    static let notAuthorizedToken = "not-authorized"

    static func notRun(_ op: HostsOp, _ why: String) -> HostsEditOutcome {
        let yourself = op == .set ? "Add the lines yourself." : "Remove the lines yourself."
        return .notRun(
            message: "Couldn't ask for permission (\(why)). Nothing changed. \(yourself)")
    }

    static func refusalText(_ token: String) -> String {
        switch token {
        case "damaged-block":
            return "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts."
        case "changed": return "/etc/hosts changed while cAInary was editing it. Try again."
        case "busy": return "Another cAInary edit is in progress."
        case "label": return "Couldn't keep the file's permissions or security label."
        case "read-only": return "/etc/hosts is read-only on this system."
        case "not-pkexec": return "The helper was not run through the admin prompt."
        case "untrusted-helper": return "The helper failed its signature check, so nothing changed."
        case "no-workdir": return "Couldn't prepare a safe place to run the helper."
        case "reserved-name":
            return "One of the host names belongs to this Mac and can't be redirected."
        case "too-many": return "Too many host names for one edit."
        case "symlink":
            return "/etc/hosts is a link, so cAInary won't edit it. Edit the file it points to."
        case "not-regular": return "/etc/hosts isn't a regular file, so cAInary won't edit it."
        case "unprotected":
            return
                "/etc/hosts or its folder can be changed by users other than root (or has flags or an access list), so cAInary won't edit it."
        case "mount-point", "no-mount-id":
            return "/etc/hosts is mounted from elsewhere. Edit it where it is stored."
        case "hardlinked": return "/etc/hosts has more than one link, so cAInary won't edit it."
        case "too-large": return "/etc/hosts is too large for cAInary to edit."
        case "bad-lock": return "The helper's lock file isn't safe to use."
        case "write-failed": return "Writing /etc/hosts failed."
        case notAuthorizedToken: return "Not authorized to change /etc/hosts."
        default: return "Couldn't change /etc/hosts (\(token))."
        }
    }

    /// The reply lines: the first line starting with the protocol, plus whether `flush-failed` follows.
    static func parse(_ stdout: String) -> (reply: String?, flushFailed: Bool) {
        let lines = stdout.split(whereSeparator: \.isNewline).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let reply = lines.first { $0.hasPrefix(HostsEditor.helperProtocol + " ") }
        return (reply, lines.contains("flush-failed"))
    }

    static func outcome(op: HostsOp, _ result: HostsEditor.ProcessResult) -> HostsEditOutcome {
        if let why = result.spawnError { return notRun(op, why) }
        if isCancel(result) {
            return .cancelled(message: "Nothing changed. The authentication was cancelled.")
        }
        let parsed = parse(result.stdout)
        if parsed.reply == nil, isAuthFailure(result) {
            return .refused(
                token: notAuthorizedToken,
                message: refusalText(notAuthorizedToken) + " Nothing changed.")
        }
        let adding = op == .set
        if result.timedOut && parsed.reply == nil {
            return .uncertain(
                message:
                    "cAInary couldn't tell whether /etc/hosts changed (the prompt timed out). It checked again; the step shows the current state. Check again in a moment."
            )
        }
        guard let reply = parsed.reply else {
            return .uncertain(
                message:
                    "cAInary couldn't tell whether /etc/hosts changed (no reply from the helper). It checked again; the step shows the current state."
            )
        }
        let words = reply.split(separator: " ").map(String.init)
        // `<proto> ok set|clear changed|unchanged|changed-unsynced` or `<proto> error <token>`.
        if words.count == 3, words[1] == "error" {
            return .refused(token: words[2], message: refusalText(words[2]) + " Nothing changed.")
        }
        if words.count == 4, words[1] == "ok", words[2] == op.rawValue {
            var message = ""
            var changed = true
            var synced = true
            switch words[3] {
            case "unchanged":
                changed = false
                if !adding { message = "No cAInary lines in /etc/hosts." }
            case "changed-unsynced":
                synced = false
                message =
                    adding
                    ? "The lines were added, but the system couldn't confirm they were saved to disk. They work now; check again after a restart."
                    : "The lines were removed, but the system couldn't confirm that was saved to disk. The change works now; check again after a restart."
            case "changed":
                if !adding { message = backupNote }
            default:
                return garbled()
            }
            if parsed.flushFailed { message += (message.isEmpty ? "" : " ") + flushNote }
            return .done(changed: changed, synced: synced, message: message)
        }
        return garbled()
    }

    private static func garbled() -> HostsEditOutcome {
        .uncertain(
            message:
                "cAInary couldn't tell whether /etc/hosts changed (unexpected reply). It checked again; the step shows the current state."
        )
    }
}

enum RedirectReply {
    static func outcome(op: HostsOp, _ result: HostsEditor.ProcessResult) -> RedirectOutcome {
        if let why = result.spawnError {
            return .notRun(message: "Couldn't ask for permission (\(why)). Nothing changed.")
        }
        if HostsReply.isCancel(result) {
            return .cancelled(message: "Nothing changed. The authentication was cancelled.")
        }
        let lines = result.stdout.split(whereSeparator: \.isNewline).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let proto = HostsEditor.redirectProtocol
        if !lines.contains(where: { $0.hasPrefix(proto + " ") }), HostsReply.isAuthFailure(result) {
            return .failed(message: "Not authorized to change the redirect. Nothing changed.")
        }
        let uncertain = RedirectOutcome.uncertain(
            message:
                "cAInary couldn't tell whether the redirect changed. Check it with sudo pfctl -a com.apple/cainary -s nat."
        )
        guard let reply = lines.first(where: { $0.hasPrefix(proto + " ") }) else {
            return uncertain
        }
        if reply == "\(proto) ok set" && op == .set {
            return .done(
                message: "Port 443 is redirected until you restart this Mac or remove it.")
        }
        if reply == "\(proto) ok clear" && op == .clear {
            return .done(message: "The redirect is removed.")
        }
        let words = reply.split(separator: " ").map(String.init)
        if words.count == 4, words[1] == "error", words[2] == "pfctl", Int(words[3]) != nil {
            return .failed(message: "pfctl failed (status \(words[3])). Run the commands yourself.")
        }
        return uncertain
    }
}
