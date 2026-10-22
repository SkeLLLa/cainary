import SwiftUI

/// Collapsible key to the six levels: symbol, colour, label and meaning (§2.2).
struct LegendView: View {
    @Binding var expanded: Bool

    /// Worst first, like the popover.
    static let levels: [Level] = [.high, .medium, .low, .optedOut, .ok, .notInstalled]

    var body: some View {
        DisclosureGroup("What the levels mean", isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Self.levels, id: \.slug) { level in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: level.symbol)
                            .foregroundStyle(level.color)
                            .accessibilityHidden(true)
                        (Text(level.title).bold().foregroundColor(level.color)
                            + Text(" \(level.meaning)"))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .font(.caption)
            .padding(.top, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.caption)
    }
}
