import AppKit
import SwiftUI

/// An entry's real app icon when its app is on this Mac (a local, read-only lookup), otherwise a
/// drawn glyph; monitors use SF Symbols. Grayed out when the entry isn't installed. Keyed by
/// entry id (§2.2).
struct EntryIcon: View {
    let id: String
    var installed = true
    var size: CGFloat = 20

    /// Snapshots turn the real icons off so they don't depend on the machine.
    @MainActor static var useAppIcons = true

    var body: some View {
        Group {
            if let icon = Self.appIcon(id) {
                Image(nsImage: icon).resizable().interpolation(.high)
            } else if let glyph = AppGlyph(entryId: id) {
                AppGlyphView(glyph: glyph)
            } else {
                Image(systemName: Self.monitorSymbol(id))
                    .font(.system(size: size * 0.8))
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: size, height: size)
        .grayscale(installed ? 0 : 1)
        .opacity(installed ? 1 : 0.4)
        .accessibilityHidden(true)
    }

    /// SF Symbols for monitors; the shield is the fallback.
    static func monitorSymbol(_ id: String) -> String {
        switch id {
        case "device": return "laptopcomputer"
        case "device-management": return "building.2"
        case "network-proxy": return "network"
        default: return "shield.lefthalf.filled"
        }
    }

    /// Candidate bundle IDs, in preference order. `appName` guards IDs that another product
    /// shares: the ChatGPT app also uses `com.openai.codex`, so it must not stand in for Codex.
    private static func candidates(_ id: String) -> [(id: String, appName: String?)] {
        switch id {
        case "claude":
            return [
                ("com.anthropic.claudefordesktop", nil),
                ("com.anthropic.claude-code-url-handler", nil),
            ]
        case "openai":
            return [("com.openai.codex", "ChatGPT.app"), ("com.openai.codex", "Codex.app")]
        case "cursor": return [("com.todesktop.230313mzl4w4u92", nil)]
        case "copilot":
            return [("com.microsoft.VSCode", nil), ("com.microsoft.VSCodeInsiders", nil)]
        default: return []
        }
    }

    /// Looked up on every render: `urlForApplication` is cheap, and not caching means an app
    /// installed or removed while we run shows up on the next refresh. Only `Info.plist` is read,
    /// to skip bundles that ship no icon (they would render as the generic app icon).
    @MainActor private static func appIcon(_ id: String) -> NSImage? {
        guard useAppIcons else { return nil }
        for (bundleId, appName) in candidates(id) {
            guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleId),
                appName == nil || url.lastPathComponent == appName,
                let info = Bundle(url: url)?.infoDictionary,
                info["CFBundleIconFile"] != nil || info["CFBundleIconName"] != nil
            else { continue }
            return NSWorkspace.shared.icon(forFile: url.path)
        }
        return nil
    }
}

/// The apps that have a drawn mark.
private enum AppGlyph {
    case starburst, rosette, cube, goggles

    init?(entryId: String) {
        switch entryId {
        case "claude": self = .starburst
        case "openai": self = .rosette
        case "cursor": self = .cube
        case "copilot": self = .goggles
        default: return nil
        }
    }

    var tile: Color {
        switch self {
        case .starburst: return Color(red: 0xD9 / 255, green: 0x77 / 255, blue: 0x57 / 255)
        case .rosette: return .black
        case .cube: return Color(white: 0.13)
        case .goggles: return Color(red: 0.11, green: 0.13, blue: 0.17)
        }
    }
}

/// Original, simplified marks drawn with `Path`, used when an app isn't installed. They evoke
/// each product in its brand colors; none is traced from vendor artwork.
private struct AppGlyphView: View {
    let glyph: AppGlyph

    var body: some View {
        GeometryReader { geo in
            let s = min(geo.size.width, geo.size.height)
            ZStack {
                RoundedRectangle(cornerRadius: s * 0.22).fill(glyph.tile)
                mark(s)
            }
            .frame(width: s, height: s)
        }
    }

    @ViewBuilder private func mark(_ s: CGFloat) -> some View {
        switch glyph {
        case .starburst:
            Starburst(rays: 8).stroke(
                .white, style: StrokeStyle(lineWidth: s * 0.08, lineCap: .round)
            )
            .frame(width: s * 0.62, height: s * 0.62)
        case .rosette:
            Rosette().stroke(.white, style: StrokeStyle(lineWidth: s * 0.07, lineJoin: .round))
                .frame(width: s * 0.6, height: s * 0.6)
        case .cube:
            Cube().stroke(.white, style: StrokeStyle(lineWidth: s * 0.07, lineJoin: .round))
                .frame(width: s * 0.58, height: s * 0.62)
        case .goggles:
            Goggles().fill(.white, style: FillStyle(eoFill: true)).frame(
                width: s * 0.66, height: s * 0.5)
        }
    }
}

private struct Starburst: Shape {
    let rays: Int

    func path(in r: CGRect) -> Path {
        var p = Path()
        let c = CGPoint(x: r.midX, y: r.midY)
        let radius = min(r.width, r.height) / 2
        for i in 0..<rays {
            let a = Double(i) * 2 * .pi / Double(rays)
            let len = i.isMultiple(of: 2) ? 1.0 : 0.72
            p.move(to: CGPoint(x: c.x + cos(a) * radius * 0.2, y: c.y + sin(a) * radius * 0.2))
            p.addLine(to: CGPoint(x: c.x + cos(a) * radius * len, y: c.y + sin(a) * radius * len))
        }
        return p
    }
}

private struct Rosette: Shape {
    func path(in r: CGRect) -> Path {
        let c = CGPoint(x: r.midX, y: r.midY)
        let radius = min(r.width, r.height) / 2
        func vertex(_ i: Int, _ k: Double) -> CGPoint {
            let a = Double(i) * .pi / 3 - .pi / 2
            return CGPoint(x: c.x + cos(a) * radius * k, y: c.y + sin(a) * radius * k)
        }
        var p = Path()
        p.move(to: vertex(0, 1))
        for i in 1..<6 { p.addLine(to: vertex(i, 1)) }
        p.closeSubpath()
        // Interlaced triangles inside the hexagon give the knotted look.
        for start in [0, 1] {
            p.move(to: vertex(start, 1))
            p.addLine(to: vertex(start + 2, 1))
            p.addLine(to: vertex(start + 4, 1))
            p.closeSubpath()
        }
        return p
    }
}

private struct Cube: Shape {
    func path(in r: CGRect) -> Path {
        let c = CGPoint(x: r.midX, y: r.midY)
        let w = r.width / 2
        let h = r.height / 2
        let top = CGPoint(x: c.x, y: c.y - h)
        let ul = CGPoint(x: c.x - w, y: c.y - h / 2)
        let ur = CGPoint(x: c.x + w, y: c.y - h / 2)
        let ll = CGPoint(x: c.x - w, y: c.y + h / 2)
        let lr = CGPoint(x: c.x + w, y: c.y + h / 2)
        let bottom = CGPoint(x: c.x, y: c.y + h)
        var p = Path()
        p.addLines([top, ur, lr, bottom, ll, ul])
        p.closeSubpath()
        p.move(to: ul)
        p.addLine(to: c)
        p.addLine(to: ur)
        p.move(to: c)
        p.addLine(to: bottom)
        return p
    }
}

/// Two round lenses joined by a bridge, with the pupils punched out (even-odd fill).
private struct Goggles: Shape {
    func path(in r: CGRect) -> Path {
        let d = r.height
        var p = Path()
        p.addRoundedRect(
            in: CGRect(x: r.minX, y: r.minY, width: r.width * 0.46, height: d),
            cornerSize: CGSize(width: d / 2, height: d / 2))
        p.addRoundedRect(
            in: CGRect(x: r.maxX - r.width * 0.46, y: r.minY, width: r.width * 0.46, height: d),
            cornerSize: CGSize(width: d / 2, height: d / 2))
        p.addRect(
            CGRect(
                x: r.minX + r.width * 0.46, y: r.midY - d * 0.08, width: r.width * 0.08,
                height: d * 0.16))
        let pupil = d * 0.34
        for cx in [r.minX + r.width * 0.23, r.maxX - r.width * 0.23] {
            p.addEllipse(
                in: CGRect(x: cx - pupil / 2, y: r.midY - pupil / 2, width: pupil, height: pupil))
        }
        return p
    }
}
