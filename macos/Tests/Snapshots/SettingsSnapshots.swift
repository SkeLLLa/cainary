import Foundation
import SwiftUI

// The Settings window's collector section, on a fresh in-memory store: the switches, the port
// and the button into the collector window. Nothing from the real user's preferences. A grouped
// `Form` doesn't render in ImageRenderer, so the section is drawn in a plain stack.

@MainActor
func settingsSnapshots(out: URL) {
    let store = CollectorStore(defaults: MemoryStore())
    func render(_ file: String, dark: Bool) {
        let url = out.appendingPathComponent(file)
        let view = VStack(alignment: .leading, spacing: 8) {
            CollectorSettingsSection(collector: store, navigation: Navigation(store: MemoryStore()))
        }
        .padding(16)
        .frame(width: 480)
        checkPNG(file, url, size: writePNG(view, to: url, dark: dark), heights: 100...1400)
    }
    render("settings-collector.png", dark: false)
    render("settings-collector-dark.png", dark: true)
}
