import AppKit
import Foundation

// Entry point: ignore SIGPIPE (a helper that exits without reading its stdin must give EPIPE,
// not kill the app), exit if another instance runs, then start the SwiftUI app.
signal(SIGPIPE, SIG_IGN)

MainActor.assumeIsolated {
    if let identifier = Bundle.main.bundleIdentifier,
        NSRunningApplication.runningApplications(withBundleIdentifier: identifier)
            .contains(where: { $0 != NSRunningApplication.current })
    {
        FileHandle.standardError.write(Data("cainary: already running\n".utf8))
        exit(0)
    }
    CainaryApp.main()
}
