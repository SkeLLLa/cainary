import Foundation

// The "OTel debug collector" preferences (design §9) and what they turn into: the helper's
// argv (port, log file, --json) and the one config line sent over stdin. Pattern text never
// goes in argv, where `ps` would show it (§14.7).

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

    init(name: String = "", kind: String = "text", pattern: String = "", caseSensitive: Bool = false)
    {
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

    static let maxCount = 64
}

struct CollectorSettings: Equatable, Sendable {
    static let defaultPort = 4318
    static let portRange = 1024...65535
    /// The collector's own limit on the config line (design §14.7).
    static let maxConfigBytes = 1 << 20

    var enabled = false
    var port = defaultPort
    var logToFile = false
    var logPath = ""
    /// The presets that are on.
    var presets = CollectorPreset.defaultOnNames
    var patterns: [CollectorPattern] = []
    var notify = true

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
        var args = ["--json", "--config-stdin", "--port", String(port)]
        if let path = effectiveLogPath { args += ["--log-file", path] }
        return args
    }

    /// The first stdin line (without its newline): every known preset on or off, and the user's
    /// patterns. Rows without a name or pattern are half-typed and skipped. Nil if it would exceed
    /// the collector's 1 MiB limit.
    var configLine: Data? {
        var flags: [[String: Any]] = []
        for pattern in patterns {
            let name = pattern.name.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty, !pattern.pattern.isEmpty else { continue }
            flags.append([
                "name": name, "kind": pattern.kind, "pattern": pattern.pattern,
                "caseSensitive": pattern.caseSensitive,
            ])
        }
        var presetFlags: [String: Bool] = [:]
        for preset in CollectorPreset.all { presetFlags[preset.name] = presets.contains(preset.name) }
        let object: [String: Any] = ["v": 1, "redFlags": flags, "presets": presetFlags]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
            data.count <= Self.maxConfigBytes
        else { return nil }
        return data
    }
}

extension KeyValueStore {
    /// The collector preferences with their defaults (design §9 table). A stored port outside
    /// 1024...65535 is clamped; an unreadable pattern list is empty.
    var collectorSettings: CollectorSettings {
        get {
            var s = CollectorSettings()
            s.enabled = bool(forKey: PrefKey.otelCollectorEnabled)
            let port = integer(forKey: PrefKey.otelCollectorPort)
            if port != 0 {
                let range = CollectorSettings.portRange
                s.port = min(max(port, range.lowerBound), range.upperBound)
            }
            s.logToFile = bool(forKey: PrefKey.otelCollectorLogToFile)
            s.logPath = string(forKey: PrefKey.otelCollectorLogPath) ?? ""
            if let presets = stringArray(forKey: PrefKey.otelCollectorPresets) { s.presets = presets }
            if let stored = data(forKey: PrefKey.otelCollectorPatterns),
                let patterns = try? JSONDecoder().decode([CollectorPattern].self, from: stored)
            {
                s.patterns = patterns
            }
            s.notify =
                object(forKey: PrefKey.otelCollectorNotify) == nil
                ? true : bool(forKey: PrefKey.otelCollectorNotify)
            return s
        }
        set {
            set(newValue.enabled, forKey: PrefKey.otelCollectorEnabled)
            set(newValue.port, forKey: PrefKey.otelCollectorPort)
            set(newValue.logToFile, forKey: PrefKey.otelCollectorLogToFile)
            set(newValue.logPath, forKey: PrefKey.otelCollectorLogPath)
            set(newValue.presets, forKey: PrefKey.otelCollectorPresets)
            set(try? JSONEncoder().encode(newValue.patterns), forKey: PrefKey.otelCollectorPatterns)
            set(newValue.notify, forKey: PrefKey.otelCollectorNotify)
        }
    }
}
