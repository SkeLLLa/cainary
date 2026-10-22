import AppKit

/// Build metadata and the standard About panel.
enum About {
    static let repository = URL(string: "https://github.com/SkeLLLa/cainary")!

    /// `CFBundleShortVersionString`; "development build" outside an app bundle.
    static var version: String {
        bundleValue("CFBundleShortVersionString") ?? "development build"
    }

    /// Full commit SHA stamped into Info.plist by packaging/bundle.sh; nil outside a bundle.
    static var commit: String? { bundleValue("CNGitCommit") }

    /// UTC build timestamp stamped into Info.plist by packaging/bundle.sh.
    static var buildDate: String? { bundleValue("CNBuildDate") }

    static var shortCommit: String? {
        guard let commit else { return nil }
        let dirty = commit.hasSuffix("-dirty")
        let base = dirty ? String(commit.dropLast("-dirty".count)) : commit
        // No HEAD yet (before the first commit): build scripts stamp "unknown".
        guard base != "unknown" else { return dirty ? "uncommitted" : nil }
        let sha = String(base.prefix(12))
        return dirty ? "\(sha)-dirty" : sha
    }

    /// "1.0.0 (abcdef123456)", or "1.0.0 (development build)" without a stamped commit.
    static var versionLine: String {
        "\(version) (\(shortCommit ?? "development build"))"
    }

    @MainActor
    static func show() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "cAInary",
            .applicationVersion: version,
            .version: shortCommit ?? "development build",
            .credits: credits(),
            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"):
                "Copyright © SkeLLLa and contributors. Licensed under GPL-3.0-or-later.",
        ])
    }

    private static func bundleValue(_ key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
            !value.isEmpty, !value.hasPrefix("__")
        else { return nil }
        return value
    }

    private static func credits() -> NSAttributedString {
        let text = NSMutableAttributedString()
        let body: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,
        ]
        let heading: [NSAttributedString.Key: Any] = [
            .font: NSFont.boldSystemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,
        ]
        func append(_ string: String, _ attributes: [NSAttributedString.Key: Any] = body) {
            text.append(NSAttributedString(string: string, attributes: attributes))
        }
        func link(_ title: String, _ url: URL) {
            var attributes = body
            attributes[.link] = url
            text.append(NSAttributedString(string: title, attributes: attributes))
        }

        append(
            "Shows what your AI tools and the device monitoring around them track and send, and where it goes. It only reads files and never uses the network.\n\n"
        )

        append("Build\n", heading)
        append("Version: \(version)\n")
        if let commit {
            append("Commit: ")
            let sha = commit.replacingOccurrences(of: "-dirty", with: "")
            link(commit, repository.appendingPathComponent("commit/\(sha)"))
            append("\n")
        } else {
            append("Commit: development build\n")
        }
        if let buildDate { append("Built: \(buildDate)\n") }
        append("Source: ")
        link(repository.absoluteString, repository)
        append("\n\n")

        append("License\n", heading)
        append(
            "cAInary is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 or (at your option) any later version. It comes with ABSOLUTELY NO WARRANTY. "
        )
        // COPYING ships in Contents/Resources.
        if let copying = Bundle.main.url(forResource: "COPYING", withExtension: nil) {
            link("Full license text", copying)
        } else {
            link("Full license text", repository.appendingPathComponent("blob/master/COPYING"))
        }
        append(".\n\n")

        append("Support Ukraine\n", heading)
        append(SupportLinks.note + "\n")
        for (index, support) in SupportLinks.all.enumerated() {
            if index > 0 { append(" · ") }
            link(support.title, support.url)
        }
        return text
    }
}
