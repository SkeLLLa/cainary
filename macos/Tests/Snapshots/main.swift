import AppKit
import Foundation
import SwiftUI

// §5c: runs the real helper on fixtures and writes 2× PNGs to target/ui-snapshots/. The one
// @main of the snapshot binary; it exits non-zero if a PNG is missing, empty or the wrong height.

@main
enum Snapshots {
    @MainActor
    static func main() async {
        signal(SIGPIPE, SIG_IGN)
        _ = NSApplication.shared
        EntryIcon.useAppIcons = false

        let root = repoRoot()
        let out = root.appendingPathComponent("target/ui-snapshots", isDirectory: true)
        try? FileManager.default.removeItem(at: out)
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

        await popoverSnapshots(root: root, out: out)
        await detailSnapshots(root: root, out: out)
        await detailChangesSnapshot(root: root, out: out)
        await detailFailedSnapshots(root: root, out: out)
        menuBarSnapshot(out: out)

        exit(finishChecks())
    }
}
