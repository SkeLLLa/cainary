import Foundation
import SwiftUI

// The popover on fixtures, scanned by the real helper (target/debug/cainary).

/// Hosts PopoverView with the two disclosure bindings the app keeps in state.
private struct PopoverHost: View {
    let state: ScanState
    var notInstalledExpanded = false
    var legendExpanded = false
    var trackingUnavailable = false

    var body: some View {
        PopoverView(
            state: state,
            notInstalledExpanded: .constant(notInstalledExpanded),
            legendExpanded: .constant(legendExpanded),
            trackingUnavailable: trackingUnavailable)
    }
}

@MainActor
func popoverSnapshots(root: URL, out: URL) async {
    let helper = root.appendingPathComponent("target/debug/cainary")
    let fixtures = root.appendingPathComponent("crates/cainary-core/tests/fixtures")
    let now = Date()

    /// The real helper's report for one fixture.
    func scan(_ name: String) async -> Report? {
        let client = CoreClient(
            helper: helper, extraArgs: ["--fixture", fixtures.appendingPathComponent(name).path])
        switch await client.scan(baseline: nil) {
        case .success(let scan): return scan.report
        case .failure(let error):
            check("scan \(name): \(error.reason)", false)
            return nil
        }
    }

    func snap(
        _ file: String, _ state: ScanState, dark: Bool = false,
        notInstalled: Bool = false, legend: Bool = false, untracked: Bool = false,
        heights: ClosedRange<CGFloat> = 200...1400
    ) {
        let url = out.appendingPathComponent(file)
        let size = writePNG(
            PopoverHost(
                state: state, notInstalledExpanded: notInstalled, legendExpanded: legend,
                trackingUnavailable: untracked),
            to: url, dark: dark)
        checkPNG(file, url, size: size, heights: heights)
    }

    /// The org fixture scanned against the empty-macos golden as baseline, over stdin.
    func changed() async -> Report? {
        let golden = root.appendingPathComponent(
            "crates/cainary-core/tests/golden/empty-macos.json")
        guard let baseline = try? Data(contentsOf: golden) else {
            check("empty-macos golden readable", false)
            return nil
        }
        let client = CoreClient(
            helper: helper,
            extraArgs: ["--fixture", fixtures.appendingPathComponent("claude-code-org-macos").path])
        switch await client.scan(baseline: baseline) {
        case .success(let scan): return scan.report
        case .failure(let error):
            check("scan with baseline: \(error.reason)", false)
            return nil
        }
    }

    var reports: [String: Report] = [:]
    for name in [
        "empty-macos", "claude-code-org-macos", "device-macos-managed", "device-only-proxy",
        "cursor-macos-managed",
    ] {
        guard let report = await scan(name) else { continue }
        reports[name] = report
        snap("popover-\(name).png", .ready(report, at: now))
    }

    guard let org = reports["claude-code-org-macos"] else { return }
    if let changed = await changed() {
        check("changes present", !(changed.changes ?? []).isEmpty)
        snap("popover-changes.png", .ready(changed, at: now))
        snap("popover-changes-untracked.png", .ready(changed, at: now), untracked: true)
    }
    snap("popover-claude-code-org-macos-dark.png", .ready(org, at: now), dark: true)
    // The not-installed list and the legend open, to see every row type.
    snap(
        "popover-claude-code-org-macos-expanded.png", .ready(org, at: now),
        notInstalled: true, legend: true)
    snap("popover-failed.png", .failed(.timedOut, last: LastScan(report: org, at: now)))
    // No report to show, so these two are short: only the banner or the spinner and the footer.
    snap("popover-failed-nolast.png", .failed(.helperMissing, last: nil), heights: 80...1400)
    snap("popover-scanning.png", .scanning(last: nil), heights: 80...1400)
    snap("popover-scanning-last.png", .scanning(last: LastScan(report: org, at: now)))
}
