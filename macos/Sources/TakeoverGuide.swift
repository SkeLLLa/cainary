import Foundation

// Swift twin of linux/crates/tray-model/src/takeover_guide.rs. Splits the collector's takeover
// text (`hello.setup.takeover`, one string per line) into warnings, numbered steps, the undo and
// a footer. The step kind comes from what the commands are, never from the wording.

enum StepKind: String, Equatable, Sendable {
    case hosts, redirect, flush, trust, restart, other
}

struct GuideStep: Equatable, Sendable {
    let number: Int
    let title: String
    /// The indented lines under the title, with the indent removed.
    let lines: [String]
    let kind: StepKind
}

struct GuideUndo: Equatable, Sendable {
    var title = ""
    var lines: [String] = []
}

struct TakeoverGuide: Equatable, Sendable {
    /// The prose before the first step.
    var warnings: [String] = []
    var steps: [GuideStep] = []
    var undo = GuideUndo()
    /// The prose after the undo commands.
    var footer: [String] = []

    /// Parses the takeover lines. Text with no numbered step gives no steps, so the caller can
    /// show the raw lines instead.
    static func parse(_ lines: [String]) -> TakeoverGuide {
        var guide = TakeoverGuide()
        var raw: [(number: Int, title: String, lines: [String])] = []
        var inUndo = false
        for line in lines {
            let text = trimEnd(line)
            if text.isEmpty { continue }
            if text.hasPrefix("Undo:") {
                inUndo = true
                guide.undo.title = text
            } else if let command = indented(text) {
                if inUndo {
                    guide.undo.lines.append(command)
                } else if !raw.isEmpty {
                    raw[raw.count - 1].lines.append(command)
                } else {
                    guide.warnings.append(trimStart(text))
                }
            } else if inUndo {
                guide.footer.append(text)
            } else if let (number, title) = stepTitle(text) {
                raw.append((number, title, []))
            } else if raw.isEmpty {
                guide.warnings.append(text)
            } else {
                guide.footer.append(text)
            }
        }
        guide.steps = raw.map {
            GuideStep(number: $0.number, title: $0.title, lines: $0.lines, kind: kind(of: $0.lines))
        }
        return guide
    }

    /// `"3. title"` → `(3, "title")`.
    private static func stepTitle(_ line: String) -> (Int, String)? {
        let scalars = line.unicodeScalars
        let digits = scalars.prefix { $0.value >= 0x30 && $0.value <= 0x39 }
        guard !digits.isEmpty, let number = Int(String(String.UnicodeScalarView(digits))) else {
            return nil
        }
        let rest = String(String.UnicodeScalarView(scalars.dropFirst(digits.count)))
        guard rest.hasPrefix(". ") else { return nil }
        return (number, String(rest.dropFirst(2)))
    }

    private static func indented(_ line: String) -> String? {
        guard line.hasPrefix("  ") else { return nil }
        return trimEnd(String(line.dropFirst(2)))
    }

    private static func kind(of lines: [String]) -> StepKind {
        if lines.contains(where: { $0.hasPrefix("127.0.0.1 ") || $0.hasPrefix("::1 ") }) {
            return .hosts
        }
        if lines.contains(where: { $0.contains("nft ") || $0.contains("pfctl ") }) {
            return .redirect
        }
        if lines.contains(where: { $0.contains("dscacheutil") }) { return .flush }
        if lines.contains(where: { $0.contains("NODE_EXTRA_CA_CERTS") }) { return .trust }
        return lines.isEmpty ? .restart : .other
    }

    private static func trimEnd(_ text: String) -> String {
        var scalars = Substring(text).unicodeScalars
        while let last = scalars.last, CharacterSet.whitespacesAndNewlines.contains(last) {
            scalars.removeLast()
        }
        return String(scalars)
    }

    private static func trimStart(_ text: String) -> String {
        String(
            String.UnicodeScalarView(
                text.unicodeScalars.drop { CharacterSet.whitespacesAndNewlines.contains($0) }))
    }
}
