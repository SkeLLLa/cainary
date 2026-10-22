import Foundation

// The schema-3 report the Rust core prints (docs/architecture.md §3.6, §4.3). The UI renders what is
// here: it never computes a level, a summary or a diff.

/// A string enum that keeps values it doesn't know, so a newer core can add a slug without
/// breaking the app. Conformers list their known slugs in `known`; anything else is `.unknown`.
protocol OpenEnum: Codable, Hashable, Sendable {
    init(slug: String)
    var slug: String { get }
}

extension OpenEnum {
    init(from decoder: Decoder) throws {
        self.init(slug: try decoder.singleValueContainer().decode(String.self))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(slug)
    }
}

/// How worrying an entry or finding is. Ascending, so `max()` is the worst. An unknown level
/// sorts below everything and is drawn as a grey `?`.
enum Level: OpenEnum, Comparable {
    case notInstalled, ok, optedOut, low, medium, high
    case unknown(String)

    init(slug: String) {
        switch slug {
        case "not-installed": self = .notInstalled
        case "ok": self = .ok
        case "opted-out": self = .optedOut
        case "low": self = .low
        case "medium": self = .medium
        case "high": self = .high
        default: self = .unknown(slug)
        }
    }

    var slug: String {
        switch self {
        case .notInstalled: return "not-installed"
        case .ok: return "ok"
        case .optedOut: return "opted-out"
        case .low: return "low"
        case .medium: return "medium"
        case .high: return "high"
        case .unknown(let s): return s
        }
    }

    var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }

    private var rank: Int {
        switch self {
        case .unknown: return -1
        case .notInstalled: return 0
        case .ok: return 1
        case .optedOut: return 2
        case .low: return 3
        case .medium: return 4
        case .high: return 5
        }
    }

    static func < (a: Level, b: Level) -> Bool {
        // Two different unknown slugs are not ordered; they compare equal in rank.
        a.rank < b.rank
    }
}

/// What a finding sends (`sends`, entry `sends`). The enums below keep their slug as is, so an
/// unknown value shows as its slug and `isKnown` says whether the app recognises it.
struct Signal: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = [
        "prompts", "responses", "transcript", "tool-details", "file-contents", "traffic",
        "device-access", "usage", "identity", "vendor", "policy",
    ]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

/// Who set a value (`setBy`, a source's `origin`).
struct Origin: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = [
        "server", "mdm", "system", "org-installed", "unattributed", "environment", "user",
        "vendor-default",
    ]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
    static let user = Origin(slug: "user")
}

/// A checked location's state.
struct SourceState: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = ["present", "absent", "error", "refused", "capped"]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
    /// A location the scan couldn't fully read.
    var isProblem: Bool { ["error", "refused", "capped"].contains(slug) }
}

/// What a config path is: `file`, `dir`, `env`, `command`, `marker`.
struct SourceKind: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = ["file", "dir", "env", "command", "marker"]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

/// A product or surface: `claude-code`, `claude-desktop`, `codex`, `cursor`, `copilot`,
/// `chatgpt`, `device`.
struct Surface: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = [
        "claude-code", "claude-desktop", "codex", "cursor", "copilot", "chatgpt", "device",
    ]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

/// `app` or `monitor`.
struct EntryKind: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = ["app", "monitor"]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

/// `entry`, `finding`, `source` or `report`.
struct ChangeScope: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = ["entry", "finding", "source", "report"]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

/// `added`, `removed`, `raised`, `lowered` or `changed`.
struct ChangeKind: OpenEnum {
    let slug: String
    init(slug: String) { self.slug = slug }
    static let knownSlugs: Set<String> = ["added", "removed", "raised", "lowered", "changed"]
    var isKnown: Bool { Self.knownSlugs.contains(slug) }
}

struct Status: Codable, Hashable, Sendable {
    var level: Level
    var label: String
    var summary: String
}

/// Where a finding's setting lives and the lines that prove it.
struct Config: Codable, Hashable, Sendable {
    var path: String
    var kind: SourceKind
    var evidence: [String]
}

struct Finding: Codable, Hashable, Sendable {
    var id: String
    /// Stable across scans; the positional `id` is not.
    var key: String
    var level: Level
    var title: String
    var detail: String
    var surface: Surface
    var sends: [Signal]
    var setBy: Origin
    var inEffect: Bool
    var maybe: Bool
    var config: Config
    var docs: String?
}

struct Entry: Codable, Hashable, Sendable {
    var id: String
    var name: String
    var kind: EntryKind
    var installed: Bool
    var status: Status
    var sends: [Signal]
    var surfaces: [Surface]
    var findings: [Finding]
    var notes: [String]
}

/// Something the core looked at. `tool` is the surface it belongs to.
struct SourceRecord: Codable, Hashable, Sendable {
    struct Location: Codable, Hashable, Sendable {
        var path: String
        var origin: Origin
        var kind: SourceKind
    }
    var tool: Surface
    var source: Location
    var state: SourceState
    var note: String?
}

/// What `--since` compared against. `error` is set when the baseline was unusable.
struct Since: Codable, Hashable, Sendable {
    var scannedAt: String
    var error: String?
}

/// One difference from the baseline (docs/architecture.md §4.2). `from` and `to` are level, state or
/// `complete`/`incomplete` slugs.
struct Change: Codable, Hashable, Sendable {
    var id: String
    var scope: ChangeScope
    var entry: String?
    var key: String?
    var kind: ChangeKind
    var from: String?
    var to: String?
    var notify: Bool
    var text: String

    /// A change with an unknown scope or kind is shown but never notifies.
    var notifies: Bool { notify && scope.isKnown && kind.isKnown }
}

struct Report: Codable, Hashable, Sendable {
    var schema: Int
    var generator: String
    var scannedAt: String
    var os: String
    var envKind: String
    var complete: Bool
    var status: Status
    var apps: [Entry]
    var others: [Entry]
    var sources: [SourceRecord]
    /// Present only when the scan ran with `--since`.
    var since: Since?
    var changes: [Change]?

    /// Apps then others, the order the badge counts in.
    var entries: [Entry] { apps + others }

    /// The `changes` that notify, in core order.
    var notifyingChanges: [Change] { (changes ?? []).filter(\.notifies) }

    /// Decodes a core report. `alert` and `counts` are on the wire but unused, so they are ignored.
    static func decode(_ data: Data) throws -> Report {
        try JSONDecoder().decode(Report.self, from: data)
    }
}
