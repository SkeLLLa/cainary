import AppKit
import SwiftUI

/// Draws a `MenuState` as one image: the robo-canary, with a level-tinted count badge (§2.1).
struct MenuBarLabel: View {
    let state: MenuState
    var style: IconStyle = .color

    var body: some View {
        Image(nsImage: MenuBarIcon.image(state, style))
            .accessibilityLabel(state.label)
            .help(state.label)
    }
}

enum MenuBarIcon {
    private static let badgeDiameter: CGFloat = 9
    /// How far the badge sticks out past the logo's top-left corner, which is empty.
    private static let overhang: CGFloat = 3
    private static let logoSize: CGFloat = 18
    /// Template alpha for "nothing installed".
    private static let dimmedAlpha: CGFloat = 0.45

    static func image(_ state: MenuState, _ style: IconStyle = .color) -> NSImage {
        let mono = style == .monochrome
        var tint: NSColor
        var badge: (text: String, color: NSColor, darkText: Bool)?
        // Template looks (no level yet) draw the silhouette in either style.
        var template = false
        var alpha: CGFloat = 1
        switch state.look {
        case .template:
            tint = .labelColor
            template = true
        case .templateDimmed:
            tint = .labelColor
            template = true
            alpha = dimmedAlpha
        case .green: tint = .systemGreen
        case .blue: tint = .systemBlue
        case .yellow: tint = .systemYellow
        case .orange: tint = .systemOrange
        case .red: tint = .systemRed
        }
        switch state.badge {
        case .none: break
        case .unknown: badge = ("?", .black, false)
        case .count(let n): badge = ("\(min(n, 9))", tint, state.look == .yellow)
        }
        if mono {
            // Template: only alpha matters. Nothing alerting means a bare silhouette.
            tint = .black
            template = true
            if let current = badge { badge = (current.text, .black, false) }
        }
        let overhang = badge == nil ? 0 : overhang
        let size = NSSize(width: logoSize + overhang, height: logoSize)
        let isTemplate = template
        let logoAlpha = alpha
        let image = NSImage(size: size, flipped: false) { rect in
            CanaryLogo.draw(
                in: NSRect(x: rect.width - logoSize, y: 0, width: logoSize, height: logoSize),
                silhouette: isTemplate ? .black : nil, alpha: logoAlpha)
            if let badge {
                // In the logo's empty top-left corner.
                let d = badgeDiameter
                let circle = NSRect(x: 0, y: rect.height - d, width: d, height: d)
                // Knock the logo out around the badge so the two never merge.
                if let context = NSGraphicsContext.current {
                    context.saveGraphicsState()
                    context.compositingOperation = .clear
                    let ring = NSBezierPath(ovalIn: circle.insetBy(dx: -0.75, dy: -0.75))
                    ring.fill()
                    context.restoreGraphicsState()
                }
                badge.color.setFill()
                NSBezierPath(ovalIn: circle).fill()
                if isTemplate {
                    // Digit knocked out of the filled circle, so it stays visible on any bar.
                    let attributes: [NSAttributedString.Key: Any] = [
                        .font: NSFont.systemFont(ofSize: 7, weight: .bold),
                        .foregroundColor: NSColor.black,
                    ]
                    let text = badge.text as NSString
                    let textSize = text.size(withAttributes: attributes)
                    if let context = NSGraphicsContext.current {
                        context.saveGraphicsState()
                        context.compositingOperation = .destinationOut
                        text.draw(
                            at: NSPoint(
                                x: circle.midX - textSize.width / 2,
                                y: circle.midY - textSize.height / 2),
                            withAttributes: attributes)
                        context.restoreGraphicsState()
                    }
                    return true
                }
                let attributes: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 7, weight: .bold),
                    .foregroundColor: badge.darkText
                        ? NSColor.black.withAlphaComponent(0.85) : NSColor.white,
                ]
                let text = badge.text as NSString
                let textSize = text.size(withAttributes: attributes)
                text.draw(
                    at: NSPoint(
                        x: circle.midX - textSize.width / 2, y: circle.midY - textSize.height / 2),
                    withAttributes: attributes)
            }
            return true
        }
        image.isTemplate = template
        image.accessibilityDescription = state.label
        return image
    }
}
