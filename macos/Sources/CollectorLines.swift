import Foundation

// The `cainary-otel-debug --json` stream, version 1. One JSON object per line.
// Within v1 changes are additive, so unknown types, keys and `error.source` values are ignored,
// and every field the app only displays is optional. Another `v` is refused.

struct CollectorHello: Codable, Equatable, Sendable {
    struct RedFlag: Codable, Equatable, Sendable {
        var name: String?
        var kind: String?
        var preset: Bool?
        var caseSensitive: Bool?
    }
    struct Setup: Codable, Equatable, Sendable {
        var claudeCode: [String]?
        var codex: [String]?
        var notes: [String]?
        /// The takeover steps, in TLS mode.
        var takeover: [String]?
    }
    struct TLS: Codable, Equatable, Sendable {
        struct CA: Codable, Equatable, Sendable {
            var path: String?
            var sha256: String?
        }
        var hosts: [String]?
        var ca: CA?
    }
    var generator: String?
    /// `receiver`, or `tls-receiver` in takeover mode.
    var mode: String?
    var tls: TLS?
    var listen: [String]?
    var endpoint: String?
    var showValues: Bool?
    var logFile: String?
    var redFlags: [RedFlag]?
    var setup: Setup?
}

struct CollectorBatch: Codable, Equatable, Sendable {
    struct Service: Codable, Equatable, Sendable {
        var name: String?
        var version: String?
    }
    struct Attr: Codable, Equatable, Sendable {
        var key: String?
        var group: String?
        var flag: String?
        var known: Bool?
    }
    struct Record: Codable, Equatable, Sendable {
        var name: String?
        var kind: String?
        var count: Int?
        var known: Bool?
        var what: String?
        var attrs: [Attr]?
    }
    struct Summary: Codable, Equatable, Sendable {
        var identity: [String]?
        var resource: [String]?
        var records: [Record]?
    }
    var ts: String?
    var seq: Int?
    var signal: String?
    var path: String?
    var bytes: Int?
    var vendor: String?
    var service: Service?
    var catalog: String?
    var records: Int?
    var notInCatalog: Int?
    var summary: Summary?
    var resourcesOmitted: Bool?
    var scanIncomplete: Bool?
}

struct CollectorAlert: Codable, Equatable, Sendable {
    var ts: String?
    var seq: Int?
    var pattern: String?
    var preset: Bool?
    var signal: String?
    var event: String?
    var events: [String]?
    var attribute: String?
    /// `where` on the wire: key, value, body, resource, scope or name.
    var place: String?
    var count: Int?
    var match: String?

    private enum CodingKeys: String, CodingKey {
        case ts, seq, pattern, preset, signal, event, events, attribute, count, match
        case place = "where"
    }
}

struct CollectorError: Codable, Equatable, Sendable {
    var ts: String?
    var source: String?
    var status: Int?
    var method: String?
    var path: String?
    var message: String?
    var dropped: Int?
}

/// What one line of the stream means to the app.
enum CollectorEvent: Equatable, Sendable {
    case hello(CollectorHello)
    case batch(CollectorBatch)
    case alert(CollectorAlert)
    case error(CollectorError)
    /// A `v` other than 1: the app can't read this collector.
    case unsupported(version: Int)
    /// An unknown `type`, or a line that isn't a v1 object. Skipped.
    case ignored

    private struct Probe: Decodable {
        var v: Int?
        var type: String?
    }

    static func decode(_ line: Data) -> CollectorEvent {
        let decoder = JSONDecoder()
        guard let probe = try? decoder.decode(Probe.self, from: line), let v = probe.v else {
            return .ignored
        }
        guard v == 1 else { return .unsupported(version: v) }
        switch probe.type {
        case "hello": return decoded(CollectorHello.self, line, CollectorEvent.hello)
        case "batch": return decoded(CollectorBatch.self, line, CollectorEvent.batch)
        case "alert": return decoded(CollectorAlert.self, line, CollectorEvent.alert)
        case "error": return decoded(CollectorError.self, line, CollectorEvent.error)
        default: return .ignored
        }
    }

    private static func decoded<T: Decodable>(
        _ type: T.Type, _ line: Data, _ make: (T) -> CollectorEvent
    ) -> CollectorEvent {
        (try? JSONDecoder().decode(type, from: line)).map(make) ?? .ignored
    }
}

extension CollectorBatch {
    /// The batch's `resources` (masked values), pretty-printed from its original line. Nil when
    /// the line has none, or `resourcesOmitted` was set.
    static func rawResources(in line: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
            let resources = object["resources"],
            let data = try? JSONSerialization.data(
                withJSONObject: resources, options: [.prettyPrinted, .sortedKeys]),
            let text = String(data: data, encoding: .utf8)
        else { return nil }
        return text
    }
}

extension String {
    /// Like `plainText`, but keeps line breaks and tabs: for a multi-line note such as stderr.
    var plainMultilineText: String {
        split(separator: "\n", omittingEmptySubsequences: false)
            .map { String($0).replacingOccurrences(of: "\t", with: "    ").plainText }
            .joined(separator: "\n")
    }

    /// Text safe to show or notify: control, bidi and escape characters become `\u{…}`. The child
    /// already escapes what it prints (architecture.md §12.3); this covers stderr and anything it missed.
    var plainText: String {
        var out = ""
        for scalar in unicodeScalars {
            let v = scalar.value
            let bad =
                v < 0x20 || (0x7F...0x9F).contains(v) || (0x202A...0x202E).contains(v)
                || (0x2066...0x2069).contains(v) || v == 0x200E || v == 0x200F || v == 0x061C
            if bad {
                out += "\\u{" + String(v, radix: 16, uppercase: true) + "}"
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }
}
