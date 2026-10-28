import AppKit
import SwiftUI

// The Details window (§2.3): a sidebar of entries and checked locations, and one pane per
// selection. Port of DetailView.swift.

/// The Details window, wired to `Navigation`. A failed scan never passes its last good report off
/// as current: a first failure is a message with Retry, a later one dims the stale results under
/// a banner.
struct DetailView: View {
    let state: ScanState
    @ObservedObject var navigation: Navigation
    let onRetry: () -> Void

    var body: some View {
        Group {
            switch state {
            case .scanning(last: nil):
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Scanning…")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .failed(let error, last: nil):
                DetailFailedView(error: error, onRetry: onRetry)
            case .failed(_, last: let last?):
                split(last.report, staleAt: last.at)
            case .scanning(last: let last?):
                split(last.report, staleAt: nil)
            case .ready(let report, _):
                split(report, staleAt: nil)
            }
        }
        .frame(minWidth: 640, minHeight: 440)
        .background(WindowAccessor { WindowOpener.shared.consumeDetailsRequest(window: $0) })
    }

    /// The sidebar and pane. `staleAt` is set when the latest scan failed and `report` is from
    /// that earlier time.
    private func split(_ report: Report, staleAt: Date?) -> some View {
        NavigationSplitView {
            sidebar(report)
        } detail: {
            VStack(spacing: 0) {
                if let staleAt {
                    DetailStaleBanner(at: staleAt, onRetry: onRetry)
                    Divider()
                }
                ScrollView {
                    pane(report)
                }
                .staleLook(staleAt != nil)
            }
        }
    }

    /// The selection, or the first installed app (then the first entry) when nothing valid is
    /// selected. `.changes` holds only while there are changes.
    private func current(_ report: Report) -> DetailSelection {
        if case .entry(let id)? = navigation.selection,
            report.entries.contains(where: { $0.id == id })
        {
            return .entry(id)
        }
        if navigation.selection == .sources { return .sources }
        if navigation.selection == .changes, !(report.changes ?? []).isEmpty { return .changes }
        let first = report.apps.first(where: \.installed) ?? report.entries.first
        return first.map { .entry($0.id) } ?? .sources
    }

    private func sidebar(_ report: Report) -> some View {
        List(selection: Binding(get: { current(report) }, set: { navigation.selection = $0 })) {
            if !(report.changes ?? []).isEmpty {
                Section {
                    Label("Changes", systemImage: "arrow.triangle.2.circlepath")
                        .tag(DetailSelection.changes)
                }
            }
            Section("AI apps") {
                ForEach(report.apps, id: \.id) { sidebarRow($0) }
            }
            if !report.others.isEmpty {
                Section("Other monitoring") {
                    ForEach(report.others, id: \.id) { sidebarRow($0) }
                }
            }
            Section {
                Label("Checked locations", systemImage: "doc.text.magnifyingglass")
                    .tag(DetailSelection.sources)
            }
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 260)
    }

    private func sidebarRow(_ entry: Entry) -> some View {
        Label {
            Text(entry.name).lineLimit(1)
        } icon: {
            EntryIcon(id: entry.id, installed: entry.installed, size: 18)
        }
        .foregroundStyle(entry.installed ? .primary : .secondary)
        .tag(DetailSelection.entry(entry.id))
    }

    /// Every text in the pane can be selected and copied.
    private func pane(_ report: Report) -> some View {
        Group {
            switch current(report) {
            case .entry(let id):
                if let entry = report.entries.first(where: { $0.id == id }) {
                    EntryDetailView(entry: entry, expanded: $navigation.expanded)
                }
            case .changes:
                ChangesPaneView(report: report)
            default:
                CheckedLocationsView(sources: report.sources)
            }
        }
        .textSelection(.enabled)
    }
}

// MARK: - Failed scan

extension View {
    /// The popover's failed look (dimmed), plus no colour, for results that are no longer current.
    func staleLook(_ stale: Bool) -> some View {
        opacity(stale ? 0.5 : 1).saturation(stale ? 0 : 1)
    }
}

/// The first scan failed: nothing to show but why, and a way to try again.
struct DetailFailedView: View {
    let error: CoreError
    let onRetry: () -> Void

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "questionmark.circle")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Couldn't scan").font(.title3.weight(.semibold))
            Text(error.reason)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Button("Retry", action: onRetry)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A later scan failed: says the pane below is from the previous scan.
struct DetailStaleBanner: View {
    let at: Date
    let onRetry: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("Couldn't scan — showing results from \(at.formatted(.dateTime.hour().minute()))")
                .font(.callout)
            Spacer()
            Button("Retry", action: onRetry)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.12))
    }
}

// MARK: - Entry pane

/// One entry: level 1 (who and what), level 2 (a row per finding), level 3 (the open rows).
/// No `ScrollView` of its own, so it can be snapshot-rendered; the split view adds one.
struct EntryDetailView: View {
    let entry: Entry
    /// Finding `key`s whose rows are open.
    @Binding var expanded: Set<String>

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if !entry.installed {
                Text("\(entry.name) isn't on this Mac.").foregroundStyle(.secondary)
            } else {
                findings
            }
            if !entry.notes.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(entry.notes, id: \.self) { note in
                        Label {
                            Text(note).fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: "info.circle")
                        }
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    }
                }
            }
            if entry.kind.slug == "app" && entry.installed {
                Divider()
                Text(EnvironmentNote.attributed)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Level 1

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                EntryIcon(id: entry.id, installed: entry.installed, size: 32)
                Text(entry.name).font(.title2.weight(.semibold))
                LevelChip(level: entry.status.level, text: entry.status.label)
                Spacer()
            }
            Text(entry.status.summary)
                .fixedSize(horizontal: false, vertical: true)
            let reach = reachLine
            if !reach.isEmpty {
                Text(reach)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// "Claude Code, Claude Desktop · sends: prompts, transcript"
    private var reachLine: String {
        var parts: [String] = []
        if entry.surfaces.count > 0 {
            parts.append(entry.surfaces.map(\.displayName).joined(separator: ", "))
        }
        if !entry.sends.isEmpty {
            parts.append("sends: " + entry.sends.map(\.displayName).joined(separator: ", "))
        }
        return parts.joined(separator: " · ")
    }

    // MARK: Level 2

    @ViewBuilder
    private var findings: some View {
        let active = entry.findings.filter(\.inEffect)
        let inactive = entry.findings.filter { !$0.inEffect }
        if active.isEmpty && inactive.isEmpty {
            Text("Nothing found for \(entry.name) on this Mac.").foregroundStyle(.secondary)
        }
        if !active.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(active, id: \.key) {
                    FindingRow(entry: entry, finding: $0, expanded: $expanded)
                }
            }
        }
        if !inactive.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("Present but not in effect").font(.headline)
                ForEach(inactive, id: \.key) {
                    FindingRow(entry: entry, finding: $0, expanded: $expanded)
                }
            }
            .foregroundStyle(.secondary)
        }
    }
}

private struct FindingRow: View {
    let entry: Entry
    let finding: Finding
    @Binding var expanded: Set<String>

    var body: some View {
        DisclosureGroup(isExpanded: expandedBinding) {
            details.padding(.vertical, 4)
        } label: {
            label
        }
    }

    private var label: some View {
        HStack(spacing: 6) {
            LevelChip(finding: finding)
            Text(title).lineLimit(2)
            Spacer(minLength: 4)
            if finding.maybe { Tag("may") }
            if finding.setBy == .user { Tag("set by you") }
        }
        .opacity(finding.inEffect ? 1 : 0.7)
    }

    /// Prefixed with the surface only when the entry has more than one.
    private var title: String {
        entry.surfaces.count > 1
            ? "\(finding.surface.displayName): \(finding.title)" : finding.title
    }

    // MARK: Level 3

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !finding.detail.isEmpty {
                Text(finding.detail).fixedSize(horizontal: false, vertical: true)
            }
            if !finding.sends.isEmpty {
                Text("Sends: " + finding.sends.map(\.displayName).joined(separator: ", "))
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Set by: \(finding.setBy.phrase)").font(.callout)
            Text(finding.config.path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !finding.config.evidence.isEmpty {
                Text(finding.config.evidence.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
            }
            HStack(spacing: 12) {
                if let url = revealURL {
                    Button("Reveal in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                    .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                }
                if let url = docsURL {
                    Button("Docs") { NSWorkspace.shared.open(url) }
                        .buttonStyle(.plain).foregroundStyle(Color.accentColor)
                }
            }
        }
    }

    private var expandedBinding: Binding<Bool> {
        Binding(
            get: { expanded.contains(finding.key) },
            set: { isOn in
                if isOn {
                    expanded.insert(finding.key)
                } else {
                    expanded.remove(finding.key)
                }
            })
    }

    /// Only files and directories at an absolute or `~/` path that exists.
    private var revealURL: URL? {
        guard ["file", "dir"].contains(finding.config.kind.slug) else { return nil }
        let path = finding.config.path
        guard path.hasPrefix("/") || path.hasPrefix("~/") else { return nil }
        let expanded = (path as NSString).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expanded) else { return nil }
        return URL(fileURLWithPath: expanded)
    }

    /// http(s) only: the core's `docs` is data, not something to hand to any scheme.
    private var docsURL: URL? {
        guard let docs = finding.docs, let url = URL(string: docs),
            ["http", "https"].contains(url.scheme?.lowercased())
        else { return nil }
        return url
    }
}

private struct Tag: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.caption2)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .overlay(Capsule().stroke(.secondary.opacity(0.5)))
            .foregroundStyle(.secondary)
            .fixedSize()
    }
}

/// Every change since the baseline, with its `from → to`.
struct ChangesPaneView: View {
    let report: Report

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(ChangeText.title(report)).font(.title2.weight(.semibold))
            ForEach(Array((report.changes ?? []).enumerated()), id: \.offset) { _, change in
                ChangeRow(change: change, report: report, detail: true)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Checked locations

/// Every location the scan looked at, grouped by surface. Problems show in orange with their note.
struct CheckedLocationsView: View {
    let sources: [SourceRecord]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Checked locations").font(.title2.weight(.semibold))
            ForEach(groups, id: \.surface) { group in
                VStack(alignment: .leading, spacing: 6) {
                    Text(group.surface.displayName).font(.headline)
                    ForEach(group.records.indices, id: \.self) { row(group.records[$0]) }
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Surfaces in first-seen (core) order.
    private var groups: [(surface: Surface, records: [SourceRecord])] {
        var order: [Surface] = []
        for record in sources where !order.contains(record.tool) { order.append(record.tool) }
        return order.map { surface in (surface, sources.filter { $0.tool == surface }) }
    }

    private func row(_ record: SourceRecord) -> some View {
        let problem = record.state.isProblem
        return HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol(record))
                .foregroundStyle(problem ? Color.orange : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(record.source.path)
                    .font(.system(.caption, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
                Text(status(record))
                    .font(.caption2)
                    .foregroundStyle(problem ? Color.orange : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func symbol(_ record: SourceRecord) -> String {
        if record.state.isProblem { return "exclamationmark.triangle.fill" }
        return record.state.slug == "present" ? "checkmark.circle" : "circle.dashed"
    }

    /// "Present", "Absent", or the problem state with its note.
    private func status(_ record: SourceRecord) -> String {
        let state = record.state.slug.prefix(1).uppercased() + record.state.slug.dropFirst()
        guard let note = record.note, !note.isEmpty else { return state }
        return "\(state): \(note)"
    }
}
