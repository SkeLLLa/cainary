import Foundation

// The interfaces the rest of the app shares: errors, scan state, what the menu bar icon shows,
// navigation and the notification seam. Frozen by task U2; later tasks only use them.

/// Why a scan produced no report.
enum CoreError: Error, Equatable, Sendable {
    case helperMissing
    case launchFailed(String)
    /// Non-zero exit, with the first line of stderr.
    case exit(Int32, String)
    case timedOut
    case outputTooLarge
    case decode(String)
    /// The report's `schema` isn't 3.
    case schema(Int)

    /// One line for the popover and the tooltip.
    var reason: String {
        switch self {
        case .helperMissing: return "the scanner is missing from the app"
        case .launchFailed(let why): return "couldn't start the scanner (\(why))"
        case .exit(let code, let line):
            return line.isEmpty
                ? "the scanner exited with code \(code)" : "the scanner failed: \(line)"
        case .timedOut: return "the scanner took too long"
        case .outputTooLarge: return "the scanner printed too much"
        case .decode(let why): return "the scan result was unreadable (\(why))"
        case .schema(let n): return "the scanner speaks schema \(n), this app expects 3"
        }
    }
}

/// The last good report and when its scan finished.
struct LastScan: Equatable, Sendable {
    var report: Report
    var at: Date
}

enum ScanState: Equatable, Sendable {
    /// A scan is running; `last` is the previous good one, if any.
    case scanning(last: LastScan?)
    case ready(Report, at: Date)
    case failed(CoreError, last: LastScan?)

    /// The most recent good report, whatever the state.
    var lastGood: LastScan? {
        switch self {
        case .scanning(let last), .failed(_, let last): return last
        case .ready(let report, let at): return LastScan(report: report, at: at)
        }
    }
}

/// How the menu bar icon is drawn.
enum IconStyle: String, CaseIterable, Sendable {
    /// Bird and badge tinted by level.
    case color
    /// A template bird that follows the menu bar.
    case monochrome
}

/// What Details shows.
enum DetailSelection: Hashable, Sendable {
    case changes
    case entry(String)
    case sources
}

/// What the menu bar icon looks like for a scan state (§2.1). Pure: the drawing code only reads it.
struct MenuState: Equatable, Sendable {
    enum Look: Equatable, Sendable {
        /// Template bird, no tint: first scan, or couldn't scan.
        case template
        /// Template bird, dimmed: nothing installed.
        case templateDimmed
        case green, blue, yellow, orange, red
    }

    enum Badge: Equatable, Sendable {
        case none
        /// A `?`: the result can't be trusted.
        case unknown
        /// Entries at `low` or above, 1...9.
        case count(Int)
    }

    var look: Look
    var badge: Badge
    /// Tooltip and accessibility label.
    var label: String

    init(look: Look, badge: Badge, label: String) {
        self.look = look
        self.badge = badge
        self.label = label
    }

    init(state: ScanState) {
        switch state {
        case .failed(let error, _):
            self.init(
                look: .template, badge: .unknown, label: "cAInary · Couldn't scan: \(error.reason)")
        case .scanning(last: nil):
            self.init(look: .template, badge: .none, label: "cAInary · Scanning…")
        case .scanning(last: let last?):
            self.init(report: last.report)
        case .ready(let report, _):
            self.init(report: report)
        }
    }

    private init(report: Report) {
        let level = report.status.level
        let label = "cAInary · \(report.status.label) · \(report.status.summary)"
        // The `status` rule: an incomplete scan that found nothing worrying can't claim "fine".
        if level.isUnknown || (!report.complete && level < .low) {
            self.init(look: .template, badge: .unknown, label: label)
            return
        }
        switch level {
        case .notInstalled:
            self.init(look: .templateDimmed, badge: .none, label: label)
        case .ok:
            self.init(look: .green, badge: .none, label: label)
        case .optedOut:
            self.init(look: .blue, badge: .none, label: label)
        default:
            let count = min(report.entries.filter { $0.status.level >= .low }.count, 9)
            let look: Look = level == .high ? .red : (level == .medium ? .orange : .yellow)
            self.init(look: look, badge: count > 0 ? .count(count) : .none, label: label)
        }
    }
}

/// One notification to post: an entry's changes folded into one banner (§2.4).
struct Planned: Equatable, Sendable {
    /// The entry id; also the notification identifier and thread.
    var entryId: String
    var title: String
    var body: String
    /// The change ids this notification covers.
    var changeIds: [String]
}

/// Posts notifications. `UNNotifier` is the real one; tests use `RecordingNotifier`.
@MainActor
protocol NotificationPosting: AnyObject {
    /// Returns the change ids it handled: posted, or deliberately muted. A change whose post
    /// failed isn't returned, so it stays due. `isCurrent` is asked after any await and before
    /// each add; once it returns false nothing more is handled.
    func post(_ planned: [Planned], isCurrent: () -> Bool) async -> Set<String>
}
