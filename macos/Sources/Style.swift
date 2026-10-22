import AppKit
import SwiftUI

// How levels, signals, origins and surfaces look and read. Colour is never the only cue: every
// level has its own symbol and text. Port of Style.swift, ExposureStyle.swift, ExposureChip.swift.

extension Level {
    /// The §2.2 colour table.
    var nsColor: NSColor {
        switch self {
        case .high: return .systemRed
        case .medium: return .systemOrange
        case .low: return .systemYellow
        case .optedOut: return .systemBlue
        case .ok: return .systemGreen
        case .notInstalled: return .tertiaryLabelColor
        case .unknown: return .secondaryLabelColor
        }
    }

    var color: Color { Color(nsColor: nsColor) }

    /// The §2.2 symbol table.
    var symbol: String {
        switch self {
        case .high: return "exclamationmark.octagon.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .low: return "exclamationmark.circle.fill"
        case .optedOut: return "hand.raised.circle.fill"
        case .ok: return "checkmark.circle.fill"
        case .notInstalled: return "circle.dashed"
        case .unknown: return "questionmark.circle"
        }
    }

    /// The text label (docs/architecture.md §3.2). An unknown level shows its slug.
    var title: String {
        switch self {
        case .notInstalled: return "NOT INSTALLED"
        case .ok: return "OK"
        case .optedOut: return "OPTED OUT"
        case .low: return "LOW"
        case .medium: return "MEDIUM"
        case .high: return "HIGH"
        case .unknown(let slug): return slug.uppercased()
        }
    }

    /// What the level means (docs/architecture.md §3.2), for the legend and tooltips.
    var meaning: String {
        switch self {
        case .notInstalled: return "The app isn't on this Mac."
        case .ok: return "Nothing tracked or sent that we can see."
        case .optedOut:
            return
                "The vendor's standard telemetry is turned off by a setting, and nothing else is sent."
        case .low: return "Usage, metrics, identity or vendor-default telemetry."
        case .medium:
            return "Activity: commands, tool details, file contents, traffic, device access."
        case .high: return "Conversations: prompts, responses, transcripts."
        case .unknown: return "A level this version of cAInary doesn't know."
        }
    }
}

extension Signal {
    /// A readable name; an unknown signal shows its slug.
    var displayName: String {
        switch slug {
        case "prompts": return "prompts"
        case "responses": return "responses"
        case "transcript": return "transcript"
        case "tool-details": return "tool details"
        case "file-contents": return "file contents"
        case "traffic": return "traffic"
        case "device-access": return "device access"
        case "usage": return "usage"
        case "identity": return "identity"
        case "vendor": return "vendor telemetry"
        case "policy": return "policy"
        default: return slug
        }
    }
}

extension Origin {
    /// Who set it, as the end of "Set by: …". An unknown origin shows its slug.
    var phrase: String {
        switch slug {
        case "server": return "your organization's server"
        case "mdm": return "your organization (MDM)"
        case "system": return "system settings"
        case "org-installed": return "your organization (installed file)"
        case "unattributed": return "an unknown source"
        case "environment": return "an environment variable"
        case "user": return "you"
        case "vendor-default": return "the vendor's default"
        default: return slug
        }
    }
}

extension Surface {
    /// An unknown surface shows its slug.
    var displayName: String {
        switch slug {
        case "claude-code": return "Claude Code"
        case "claude-desktop": return "Claude Desktop"
        case "codex": return "Codex"
        case "cursor": return "Cursor"
        case "copilot": return "GitHub Copilot"
        case "chatgpt": return "ChatGPT"
        case "device": return "This device"
        default: return slug
        }
    }
}

/// The note about variables a GUI app can't see (§2.3). Shown under an app entry's notes.
enum EnvironmentNote {
    static let text =
        "The app sees launchd's environment, not your shell's. Run `cainary scan` in a terminal to check your shell."

    static var attributed: AttributedString {
        (try? AttributedString(
            markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(text)
    }
}

/// Level shape, colour and text on a tinted capsule.
struct LevelChip: View {
    let level: Level
    var text: String?

    init(level: Level, text: String? = nil) {
        self.level = level
        self.text = text
    }

    /// A finding's chip: one that isn't in effect and found nothing reads "inactive" (docs/architecture.md §8.1).
    init(finding: Finding) {
        self.init(
            level: finding.level,
            text: !finding.inEffect && finding.level == .ok ? "inactive" : nil)
    }

    var body: some View {
        let label = text ?? level.title
        Label(label, systemImage: level.symbol)
            .font(.caption.weight(.medium))
            .foregroundStyle(level.color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(level.color.opacity(0.12), in: Capsule())
            .fixedSize(horizontal: true, vertical: false)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(label)
            .help(level.meaning)
    }
}

/// Captures the hosting `NSWindow` of a SwiftUI view.
struct WindowAccessor: NSViewRepresentable {
    let onWindow: @MainActor (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = WindowReportingView()
        view.onWindow = onWindow
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        (nsView as? WindowReportingView)?.onWindow = onWindow
    }

    private final class WindowReportingView: NSView {
        var onWindow: (@MainActor (NSWindow) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window else { return }
            let callback = onWindow
            // The window isn't fully set up inside this callback.
            DispatchQueue.main.async {
                MainActor.assumeIsolated { callback?(window) }
            }
        }
    }
}
