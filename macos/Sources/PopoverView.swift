import AppKit
import SwiftUI

/// What the popover's buttons do. `App.swift` wires these to the store, the windows and the
/// pasteboard; tests and snapshots leave them as no-ops.
struct PopoverActions {
    var refresh: () -> Void = {}
    /// Open Details at an entry.
    var openEntry: (String) -> Void = { _ in }
    var openDetails: () -> Void = {}
    /// Open Details on the Changes pane.
    var openChanges: () -> Void = {}
    /// Make the current report the baseline.
    var markAsSeen: () -> Void = {}
    var copyReport: () -> Void = {}
    var openSettings: () -> Void = {}
    var showAbout: () -> Void = {}
    var openSupport: (URL) -> Void = { _ in }
    var quit: () -> Void = {}
}

/// The menu bar popover, 360 pt wide. It has no `ScrollView` so it can be snapshot-rendered;
/// `App.swift` wraps it in one.
struct PopoverView: View {
    let state: ScanState
    @Binding var notInstalledExpanded: Bool
    @Binding var legendExpanded: Bool
    /// The baseline couldn't be replaced, so changes aren't tracked.
    var trackingUnavailable = false
    var actions = PopoverActions()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            content
            Divider()
            footer
        }
        .padding(12)
        .frame(width: 360)
    }

    private var isScanning: Bool {
        if case .scanning = state { return true }
        return false
    }

    @ViewBuilder
    private var content: some View {
        switch state {
        case .scanning(last: nil):
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Scanning…")
            }
            .padding(.vertical, 20)
            .frame(maxWidth: .infinity)
        case .scanning(last: let last?):
            report(last.report, at: last.at)
        case .ready(let report, let at):
            self.report(report, at: at)
        case .failed(let error, let last):
            failedBanner(error, last: last)
            if let last {
                self.report(last.report, at: last.at, dimmed: true)
            }
        }
    }

    // MARK: Report

    @ViewBuilder
    private func report(_ report: Report, at: Date, dimmed: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if !dimmed {
                header(report, at: at)
                Divider()
                if let changes = report.changes, !changes.isEmpty {
                    ChangesView(
                        report: report, openChanges: actions.openChanges,
                        markAsSeen: actions.markAsSeen)
                    Divider()
                }
            }
            appsSection(report)
            othersSection(report)
            LegendView(expanded: $legendExpanded)
        }
        .opacity(dimmed ? 0.5 : 1)
    }

    @ViewBuilder
    private func header(_ report: Report, at: Date) -> some View {
        // `MenuState` owns the "can't be trusted" rule, so the header and the icon agree.
        let untrusted = MenuState(state: state).badge == .unknown
        let level = report.status.level
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: untrusted ? "questionmark.circle" : level.symbol)
                .foregroundStyle(untrusted ? Color.secondary : level.color)
                .font(.title2)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(untrusted && !report.complete ? "Scan incomplete" : report.status.label)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(
                        untrusted || level == .notInstalled
                            ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary)
                    )
                    .lineLimit(1)
                Text(report.status.summary)
                    .font(.caption)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                scanLine(report, at: at)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            refreshButton
        }
    }

    @ViewBuilder
    private func scanLine(_ report: Report, at: Date) -> some View {
        let problems = report.sources.filter { $0.state.isProblem }.count
        let time = "Scanned \(at.formatted(.dateTime.hour().minute()))"
        let unreadable =
            problems == 0
            ? nil
            : "⚠ \(problems) location\(problems == 1 ? "" : "s") couldn't be read"
        let untracked = trackingUnavailable ? "Change tracking unavailable" : nil
        Text([time, unreadable, untracked].compactMap { $0 }.joined(separator: " · "))
            .font(.caption)
            .foregroundStyle(
                problems == 0 ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.orange)
            )
            .fixedSize(horizontal: false, vertical: true)
    }

    private var refreshButton: some View {
        Button(action: actions.refresh) {
            Group {
                if isScanning {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .frame(width: 20, height: 20)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(isScanning)
        .help("Refresh")
        .accessibilityLabel("Refresh")
    }

    // MARK: Failed

    @ViewBuilder
    private func failedBanner(_ error: CoreError, last: LastScan?) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "questionmark.circle")
                .foregroundStyle(.secondary)
                .font(.title2)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("Couldn't scan")
                    .font(.callout.weight(.semibold))
                Text(error.reason)
                    .font(.caption)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                if let last {
                    Text("Last scan at \(last.at.formatted(.dateTime.hour().minute()))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button("Retry", action: actions.refresh)
        }
        Divider()
    }

    // MARK: Entries

    @ViewBuilder
    private func appsSection(_ report: Report) -> some View {
        let installed = report.apps.filter(\.installed)
        let missing = report.apps.filter { !$0.installed }
        VStack(alignment: .leading, spacing: 4) {
            sectionTitle("AI apps")
            ForEach(installed, id: \.id) { entry in
                row(entry)
            }
            if !missing.isEmpty {
                notInstalledToggle(count: missing.count)
                if notInstalledExpanded {
                    ForEach(missing, id: \.id) { entry in
                        row(entry)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func othersSection(_ report: Report) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            sectionTitle("Other monitoring on this device")
            if report.others.isEmpty {
                Text("No other monitoring found")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(report.others, id: \.id) { entry in
                    row(entry)
                }
            }
        }
    }

    private func sectionTitle(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .accessibilityAddTraits(.isHeader)
    }

    private func notInstalledToggle(count: Int) -> some View {
        Button {
            notInstalledExpanded.toggle()
        } label: {
            HStack(spacing: 4) {
                Image(systemName: notInstalledExpanded ? "chevron.down" : "chevron.right")
                    .font(.system(size: 8, weight: .semibold))
                Text("\(count) not installed")
                    .font(.caption2)
                Spacer(minLength: 0)
            }
            .foregroundStyle(.secondary)
            .padding(.leading, 6)
            .frame(minHeight: 20)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(count) not installed")
        .accessibilityValue(notInstalledExpanded ? "expanded" : "collapsed")
        .accessibilityHint("Shows or hides apps that are not installed")
    }

    /// One entry: icon, name, level chip and a one-line summary. A click opens Details at it.
    private func row(_ entry: Entry) -> some View {
        Button {
            actions.openEntry(entry.id)
        } label: {
            HStack(spacing: 8) {
                EntryIcon(id: entry.id, installed: entry.installed, size: 24)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(entry.name)
                            .font(.callout.weight(.medium))
                            .lineLimit(1)
                        Spacer(minLength: 0)
                        LevelChip(level: entry.status.level, text: entry.status.label)
                    }
                    Text(entry.status.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .padding(.vertical, 2)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!entry.installed)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(entry.name): \(entry.status.label). \(entry.status.summary)")
        .accessibilityAddTraits(.isButton)
    }

    // MARK: Footer

    private var footer: some View {
        HStack {
            Button("Open details", action: actions.openDetails)
            Spacer()
            moreMenu
        }
    }

    private var moreMenu: some View {
        Menu {
            Button("Copy report", action: actions.copyReport)
                .disabled(state.lastGood == nil)
            Divider()
            Button("Settings…", action: actions.openSettings)
            Button("About cAInary", action: actions.showAbout)
            Menu("Support Ukraine") {
                ForEach(SupportLinks.all) { link in
                    Button(link.title) { actions.openSupport(link.url) }
                }
            }
            Divider()
            Button("Quit cAInary", action: actions.quit)
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("More")
    }
}
