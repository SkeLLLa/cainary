import SwiftUI

/// The collector's Red flags tab: what the rules matched, one card per pattern, most recent
/// first. Twin of linux/crates/cainary-tray/qml/CollectorFlags.qml (groups part; the rules
/// editor is its own view).
struct CollectorFlagsView: View {
    let groups: [FlagGroup]
    let focus: String?
    let enabled: Bool
    let markSeen: () -> Void
    let onShowInFeed: (String) -> Void
    /// The tab is left: the owner drops the one-shot `focus`, so it does not come back.
    var onLeave: () -> Void = {}
    /// Snapshots only: ImageRenderer draws no ScrollView.
    var staticLayout = false

    private var list: some View {
        VStack(alignment: .leading, spacing: 8) {
            if groups.isEmpty { emptyState }
            ForEach(groups, id: \.pattern) { group in
                card(group).id(group.pattern)
            }
        }
        .padding(10)
        .frame(
            maxWidth: .infinity, maxHeight: staticLayout ? .infinity : nil, alignment: .topLeading)
    }

    var body: some View {
        ScrollViewReader { proxy in
            Group {
                if staticLayout { list } else { ScrollView { list } }
            }
            .onAppear {
                markSeen()
                scroll(proxy)
            }
            .onChange(of: focus) { _, _ in scroll(proxy) }
            .onDisappear(perform: onLeave)
        }
    }

    private func scroll(_ proxy: ScrollViewProxy) {
        if let focus { proxy.scrollTo(focus, anchor: .top) }
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: "flag").font(.largeTitle).foregroundStyle(.secondary)
            Text("No red flags").fontWeight(.semibold)
            Text(enabled ? "Nothing matched the rules yet." : "The collector is off.")
                .font(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity).padding(.top, 40)
    }

    private func card(_ group: FlagGroup) -> some View {
        let target = focus == group.pattern
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Label(group.pattern, systemImage: "flag.fill")
                    .fontWeight(.semibold).foregroundStyle(.red)
                Text(group.preset ? "preset" : "custom").font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Text(hits(group)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            Text("Last seen \(group.lastTime)").font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            if !group.events.isEmpty {
                Text("Events: \(group.events.joined(separator: ", "))")
                    .font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            if !group.attributes.isEmpty {
                Text("Attributes: \(group.attributes.joined(separator: ", "))")
                    .font(.system(.callout, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !group.matched.isEmpty {
                Text("Matched: \(group.matched)")
                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
            }
            Text("Signals: \(group.signals.joined(separator: ", "))")
                .font(.callout).foregroundStyle(.secondary)
            Button {
                onShowInFeed(group.pattern)
            } label: {
                Text("Show in feed").font(.callout)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain).padding(.top, 2)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(target ? 0.12 : 0.05), in: RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.red.opacity(target ? 0.6 : 0.25)))
    }

    private func hits(_ group: FlagGroup) -> String {
        (group.hits == 1 ? "1 hit" : "\(group.hits) hits")
            + (group.total != group.hits ? " · ×\(group.total)" : "")
    }
}
