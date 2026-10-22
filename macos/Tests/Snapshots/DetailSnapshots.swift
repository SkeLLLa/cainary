import Foundation
import SwiftUI

// The Details entry pane on fixtures, scanned by the real helper. EntryDetailView is rendered
// directly: the split view and its ScrollView don't render in ImageRenderer.

/// An `EntryDetailView` with every finding row open (or none).
private struct DetailHost: View {
    let entry: Entry
    let expandAll: Bool

    var body: some View {
        EntryDetailView(
            entry: entry,
            expanded: .constant(expandAll ? Set(entry.findings.map(\.key)) : [])
        )
        .frame(width: 570, alignment: .topLeading)
    }
}

@MainActor
func detailSnapshots(root: URL, out: URL) async {
    let helper = root.appendingPathComponent("target/debug/cainary")
    let fixtures = root.appendingPathComponent("crates/cainary-core/tests/fixtures")

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

    func snap(_ file: String, _ entry: Entry?, expandAll: Bool = false) {
        guard let entry else {
            check("\(file): entry found", false)
            return
        }
        let url = out.appendingPathComponent(file)
        let size = writePNG(DetailHost(entry: entry, expandAll: expandAll), to: url)
        checkPNG(file, url, size: size, heights: 100...6000)
    }

    let org = await scan("claude-code-org-macos")
    snap("detail-claude.png", org?.apps.first { $0.id == "claude" }, expandAll: true)
    let managed = await scan("device-macos-managed")
    snap("detail-monitor.png", managed?.others.first)
    let empty = await scan("empty-macos")
    snap("detail-not-installed.png", empty?.apps.first { !$0.installed })
}

/// The failed Details states. The split view doesn't render in ImageRenderer, so the stale one is
/// the banner over the dimmed entry pane, built from the same pieces as `DetailView`.
@MainActor
func detailFailedSnapshots(root: URL, out: URL) async {
    let helper = root.appendingPathComponent("target/debug/cainary")
    let fixtures = root.appendingPathComponent("crates/cainary-core/tests/fixtures")
    let error = CoreError.exit(2, "no such directory")

    let first = DetailFailedView(error: error, onRetry: {}).frame(width: 570, height: 300)
    let firstFile = "detail-failed-first.png"
    let firstURL = out.appendingPathComponent(firstFile)
    checkPNG(firstFile, firstURL, size: writePNG(first, to: firstURL), heights: 100...6000)

    let client = CoreClient(
        helper: helper,
        extraArgs: ["--fixture", fixtures.appendingPathComponent("claude-code-org-macos").path])
    guard case .success(let scan) = await client.scan(baseline: nil),
        let entry = scan.report.apps.first(where: { $0.id == "claude" })
    else {
        check("detail-failed-stale: scan", false)
        return
    }
    let stale = VStack(spacing: 0) {
        DetailStaleBanner(at: Date(timeIntervalSince1970: 1_700_000_000), onRetry: {})
        Divider()
        EntryDetailView(entry: entry, expanded: .constant([])).staleLook(true)
    }
    .frame(width: 570, alignment: .topLeading)
    let staleFile = "detail-failed-stale.png"
    let staleURL = out.appendingPathComponent(staleFile)
    checkPNG(staleFile, staleURL, size: writePNG(stale, to: staleURL), heights: 100...6000)
}

/// The Changes pane: the org fixture scanned against the empty-macos golden as baseline.
@MainActor
func detailChangesSnapshot(root: URL, out: URL) async {
    let helper = root.appendingPathComponent("target/debug/cainary")
    let fixtures = root.appendingPathComponent("crates/cainary-core/tests/fixtures")
    let golden = root.appendingPathComponent("crates/cainary-core/tests/golden/empty-macos.json")
    guard let baseline = try? Data(contentsOf: golden) else {
        check("empty-macos golden readable", false)
        return
    }
    let client = CoreClient(
        helper: helper,
        extraArgs: ["--fixture", fixtures.appendingPathComponent("claude-code-org-macos").path])
    guard case .success(let scan) = await client.scan(baseline: baseline) else {
        check("detail-changes: scan with baseline", false)
        return
    }
    let file = "detail-changes.png"
    let url = out.appendingPathComponent(file)
    let view = ChangesPaneView(report: scan.report).frame(width: 570, alignment: .topLeading)
    let size = writePNG(view, to: url)
    checkPNG(file, url, size: size, heights: 100...6000)
}
