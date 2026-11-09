import Foundation

// The "OTel debug collector" preferences and what they turn into: the helper's
// argv (port, log file, --json) and the one config line sent over stdin. Pattern text never
// goes in argv, where `ps` would show it (architecture.md §12.7).

/// A built-in red-flag preset. Names match `cainary-otel-debug --list-presets`.
struct CollectorPreset: Hashable, Sendable {
    var name: String
    var title: String
    var defaultOn: Bool

    static let all: [CollectorPreset] = [
        CollectorPreset(name: "email", title: "Email addresses", defaultOn: true),
        CollectorPreset(name: "private-key", title: "Private keys", defaultOn: true),
        CollectorPreset(name: "jwt", title: "JSON Web Tokens", defaultOn: true),
        CollectorPreset(name: "aws-access-key", title: "AWS access keys", defaultOn: true),
        CollectorPreset(name: "github-token", title: "GitHub tokens", defaultOn: true),
        CollectorPreset(name: "anthropic-key", title: "Anthropic API keys", defaultOn: true),
        CollectorPreset(name: "openai-key", title: "OpenAI API keys", defaultOn: true),
        CollectorPreset(name: "slack-token", title: "Slack tokens", defaultOn: true),
        CollectorPreset(name: "ipv4", title: "IPv4 addresses", defaultOn: false),
    ]

    static var defaultOnNames: [String] { all.filter(\.defaultOn).map(\.name) }
}

/// A user red flag. `kind` is `text` or `regex`. `id` only keeps table rows stable; it isn't stored.
struct CollectorPattern: Codable, Hashable, Identifiable, Sendable {
    var id = UUID()
    var name: String
    var kind: String
    var pattern: String
    var caseSensitive: Bool

    init(
        name: String = "", kind: String = "text", pattern: String = "", caseSensitive: Bool = false
    ) {
        self.name = name
        self.kind = kind
        self.pattern = pattern
        self.caseSensitive = caseSensitive
    }

    var isRegex: Bool {
        get { kind == "regex" }
        set { kind = newValue ? "regex" : "text" }
    }

    private enum CodingKeys: String, CodingKey { case name, kind, pattern, caseSensitive }

    /// The collector's limit on all red flags, enabled presets included.
    static let maxTotal = 64
    static let maxPatternBytes = 1024

    /// `^[a-z0-9][a-z0-9_-]{0,63}$`, as `redflag::valid_name`.
    static func validName(_ name: String) -> Bool {
        let b = Array(name.utf8)
        guard (1...64).contains(b.count), let first = b.first else { return false }
        func lower(_ c: UInt8) -> Bool { (0x61...0x7A).contains(c) || (0x30...0x39).contains(c) }
        guard lower(first) else { return false }
        return b.allSatisfy { lower($0) || $0 == 0x5F || $0 == 0x2D }
    }
}

/// Why the collector can't start: a stable code for the UI and a message fit to show.
struct SettingsProblem: Equatable, Sendable {
    enum Code: String, Sendable {
        case portRange = "port-range"
        case tlsBadHost = "tls-bad-host"
        case tlsNoHost = "tls-no-host"
        case tlsTooManyHosts = "tls-too-many-hosts"
        case patterns
    }
    var code: Code
    var message: String
    init(_ code: Code, _ message: String) {
        self.code = code
        self.message = message
    }
}

struct CollectorSettings: Equatable, Sendable {
    static let defaultPort = 4318
    static let portRange = 1024...65535
    /// The collector's own limit on the config line.
    static let maxConfigBytes = 1 << 20

    var enabled = false
    /// Keep `enabled` across launches; off starts every launch with the collector off.
    var startAtLaunch = false
    var port = defaultPort
    var logToFile = false
    var logPath = ""
    /// The presets that are on.
    var presets = CollectorPreset.defaultOnNames
    var patterns: [CollectorPattern] = []
    var notify = true
    /// The HTTPS takeover: `--tls`, with the host names to answer for.
    var takeover = false
    var takeoverHosts: [String] = []
    var takeoverPort = defaultTakeoverPort

    static let defaultTakeoverPort = 8443
    static let takeoverPortRange = 1024...65535
    static let maxHosts = 32

    /// A DNS name the collector accepts for `--tls-host`: two or more labels, no wildcard, no IP.
    static func validHost(_ host: String) -> Bool {
        let h = host.lowercased()
        guard h.utf8.count <= 253 else { return false }
        if h.split(separator: ".").last?.allSatisfy(\.isNumber) == true { return false }
        let label = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
        let pattern = "^" + label + "(\\." + label + ")+$"
        return h.range(of: pattern, options: .regularExpression) != nil
    }

    /// The names that will be passed: valid ones, lowercased, once each, at most 32.
    var validHosts: [String] {
        var seen: Set<String> = []
        var out: [String] = []
        for raw in takeoverHosts {
            let h = raw.trimmingCharacters(in: .whitespaces).lowercased()
            if Self.validHost(h), seen.insert(h).inserted, out.count < Self.maxHosts {
                out.append(h)
            }
        }
        return out
    }

    /// The most host names the hosts helper writes (HostsFile/HostsEditor enforce the same).
    static let maxEditHosts = HostsFile.maxEditHosts

    /// The first reason the collector can't start, or nil. Mirrors Linux `CollectorSettings::problem`.
    var problem: SettingsProblem? {
        if !Self.portRange.contains(port) {
            return SettingsProblem(.portRange, "The collector port must be 1024–65535.")
        }
        if takeover {
            if !Self.takeoverPortRange.contains(takeoverPort) {
                return SettingsProblem(.portRange, "The HTTPS port must be 1024–65535.")
            }
            if let bad = badHostProblem { return bad }
            if validHosts.isEmpty {
                return SettingsProblem(
                    .tlsNoHost, "Add at least one host name for the HTTPS takeover.")
            }
        }
        if overLimit {
            return SettingsProblem(
                .patterns,
                "Too many red-flag patterns: presets and custom patterns share a limit of \(CollectorPattern.maxTotal)."
            )
        }
        return nil
    }

    /// Why "Add/Update" in the hosts block must stay disabled: more than 8 names. Not a start
    /// problem; the collector itself takes 32.
    var hostsEditProblem: SettingsProblem? {
        validHosts.count > Self.maxEditHosts
            ? SettingsProblem(
                .tlsTooManyHosts,
                "More than \(Self.maxEditHosts) host names; cAInary can add at most \(Self.maxEditHosts)."
            )
            : nil
    }

    private var badHostProblem: SettingsProblem? {
        var seen: Set<String> = []
        for raw in takeoverHosts {
            let h = raw.trimmingCharacters(in: .whitespaces).lowercased()
            if h.isEmpty { continue }
            if !Self.validHost(h) {
                return SettingsProblem(
                    .tlsBadHost,
                    "Host name “\(h)”: use a DNS name with at least two labels; wildcards and IP addresses aren't supported."
                )
            }
            if !seen.insert(h).inserted {
                return SettingsProblem(.tlsBadHost, "Host name “\(h)” is already listed.")
            }
        }
        return nil
    }

    /// Where "Also save to" starts: `~/Library/Logs/cAInary/otel-debug.jsonl`.
    static var defaultLogPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/cAInary/otel-debug.jsonl").path
    }

    /// The file the helper writes, if the user asked for one. `~` is expanded.
    var effectiveLogPath: String? {
        guard logToFile else { return nil }
        let path = logPath.trimmingCharacters(in: .whitespaces)
        return path.isEmpty ? Self.defaultLogPath : (path as NSString).expandingTildeInPath
    }

    /// argv: only things that aren't secret.
    var arguments: [String] {
        var args = ["--json", "--config-stdin", "--port", String(takeover ? takeoverPort : port)]
        if takeover {
            args.append("--tls")
            for host in validHosts { args += ["--tls-host", host] }
        }
        if let path = effectiveLogPath { args += ["--log-file", path] }
        return args
    }

    /// Why a row would stop the collector, or nil if it is fine. A row with neither a name nor a
    /// pattern is blank (half typed) and not an error. Mirrors the collector's rules; whether a
    /// regex compiles is left to it.
    func problem(at index: Int) -> String? {
        let row = patterns[index]
        let name = row.name.trimmingCharacters(in: .whitespaces)
        if name.isEmpty && row.pattern.isEmpty { return nil }
        if !CollectorPattern.validName(name) {
            return "Name: 1–64 characters, a–z, 0–9, - and _, starting with a letter or digit."
        }
        if CollectorPreset.all.contains(where: { $0.name == name }) {
            return "That name belongs to a preset."
        }
        if patterns[..<index].contains(where: {
            $0.name.trimmingCharacters(in: .whitespaces) == name
        }) {
            return "Another pattern has this name."
        }
        if row.pattern.isEmpty { return "The pattern is empty." }
        if row.pattern.utf8.count > CollectorPattern.maxPatternBytes {
            return "The pattern is over \(CollectorPattern.maxPatternBytes) bytes."
        }
        return nil
    }

    /// The rows the collector gets: valid ones, as long as the total fits its limit.
    var validPatterns: [CollectorPattern] {
        patterns.indices.filter { problem(at: $0) == nil && !patterns[$0].pattern.isEmpty }
            .map { patterns[$0] }
    }

    /// Set when presets plus valid patterns exceed the collector's 64.
    var overLimit: Bool {
        presets.filter { name in CollectorPreset.all.contains { $0.name == name } }.count
            + validPatterns.count > CollectorPattern.maxTotal
    }

    /// The first stdin line (without its newline): every known preset on or off, and the user's
    /// patterns. Rows without a name or pattern are half-typed and skipped. Nil if it would exceed
    /// the collector's 1 MiB limit.
    var configLine: Data? {
        var flags: [[String: Any]] = []
        for pattern in validPatterns {
            flags.append([
                "name": pattern.name.trimmingCharacters(in: .whitespaces), "kind": pattern.kind,
                "pattern": pattern.pattern, "caseSensitive": pattern.caseSensitive,
            ])
        }
        var presetFlags: [String: Bool] = [:]
        for preset in CollectorPreset.all {
            presetFlags[preset.name] = presets.contains(preset.name)
        }
        let object: [String: Any] = ["v": 1, "redFlags": flags, "presets": presetFlags]
        guard !overLimit,
            let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
            data.count <= Self.maxConfigBytes
        else { return nil }
        return data
    }
}

extension KeyValueStore {
    /// The collector preferences with their defaults (macos.md §2.8). A stored port outside
    /// 1024...65535 is clamped; an unreadable pattern list is empty.
    var collectorSettings: CollectorSettings {
        get {
            var s = CollectorSettings()
            s.enabled = bool(forKey: PrefKey.otelCollectorEnabled)
            // Migration: a store without the key keeps whatever `enabled` was.
            s.startAtLaunch =
                object(forKey: PrefKey.otelCollectorStartAtLaunch) == nil
                ? s.enabled : bool(forKey: PrefKey.otelCollectorStartAtLaunch)
            let port = integer(forKey: PrefKey.otelCollectorPort)
            if port != 0 {
                let range = CollectorSettings.portRange
                s.port = min(max(port, range.lowerBound), range.upperBound)
            }
            s.logToFile = bool(forKey: PrefKey.otelCollectorLogToFile)
            s.logPath = string(forKey: PrefKey.otelCollectorLogPath) ?? ""
            if let presets = stringArray(forKey: PrefKey.otelCollectorPresets) {
                s.presets = presets
            }
            if let stored = data(forKey: PrefKey.otelCollectorPatterns),
                let patterns = try? JSONDecoder().decode([CollectorPattern].self, from: stored)
            {
                s.patterns = patterns
            }
            s.notify =
                object(forKey: PrefKey.otelCollectorNotify) == nil
                ? true : bool(forKey: PrefKey.otelCollectorNotify)
            s.takeover = bool(forKey: PrefKey.otelCollectorTls)
            s.takeoverHosts = stringArray(forKey: PrefKey.otelCollectorTlsHosts) ?? []
            let tlsPort = integer(forKey: PrefKey.otelCollectorTlsPort)
            if tlsPort != 0 {
                let range = CollectorSettings.takeoverPortRange
                s.takeoverPort = min(max(tlsPort, range.lowerBound), range.upperBound)
            }
            return s
        }
        set {
            set(newValue.enabled, forKey: PrefKey.otelCollectorEnabled)
            set(newValue.startAtLaunch, forKey: PrefKey.otelCollectorStartAtLaunch)
            set(newValue.port, forKey: PrefKey.otelCollectorPort)
            set(newValue.logToFile, forKey: PrefKey.otelCollectorLogToFile)
            set(newValue.logPath, forKey: PrefKey.otelCollectorLogPath)
            set(newValue.presets, forKey: PrefKey.otelCollectorPresets)
            set(try? JSONEncoder().encode(newValue.patterns), forKey: PrefKey.otelCollectorPatterns)
            set(newValue.notify, forKey: PrefKey.otelCollectorNotify)
            set(newValue.takeover, forKey: PrefKey.otelCollectorTls)
            set(newValue.takeoverHosts, forKey: PrefKey.otelCollectorTlsHosts)
            set(newValue.takeoverPort, forKey: PrefKey.otelCollectorTlsPort)
        }
    }
}
