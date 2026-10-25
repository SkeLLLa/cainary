import AppKit

/// The app's robo-canary, drawn from the shapes of resources/icons/cainary-macos.svg (colored) and
/// cainary-mono.svg (the silhouette), in their `8 6 112 112` view box. Code, not an image file, so
/// the menu bar icon needs nothing from the bundle.
enum CanaryLogo {
    /// Draws the logo into `rect` of the current context: colored, or as a silhouette of `color`
    /// at `alpha`.
    static func draw(in rect: NSRect, silhouette color: NSColor?, alpha: CGFloat = 1) {
        guard let context = NSGraphicsContext.current?.cgContext else { return }
        context.saveGState()
        defer { context.restoreGState() }
        // The SVGs' y axis points down.
        context.translateBy(x: rect.minX, y: rect.maxY)
        context.scaleBy(x: rect.width / 112, y: -rect.height / 112)
        context.translateBy(x: -8, y: -6)
        if let color {
            // One layer, so overlapping shapes don't darken where a dimmed silhouette overlaps.
            context.setAlpha(alpha)
            context.beginTransparencyLayer(auxiliaryInfo: nil)
            drawSilhouette(context, color.cgColor)
            context.endTransparencyLayer()
        } else {
            drawColored(context)
        }
    }

    // MARK: - cainary-mono.svg

    private static func drawSilhouette(_ c: CGContext, _ color: CGColor) {
        // The head with the visor cut out, and the eye inside it.
        let head = CGMutablePath()
        head.addPath(roundedRect(60, 24, 38, 30, 9))
        head.addPath(roundedRect(70, 31, 24, 14, 5))
        fill(c, head, color, evenOdd: true)
        fill(c, circle(84, 38, 4.5), color)
        fill(c, polygon([p(101, 32), p(118, 40), p(101, 47)]), color)
        fill(c, circle(67.5, 12, 3.4), color)
        // The body and tail with the wing's outline cut out, and the wing inside it.
        let body = CGMutablePath()
        body.addPath(
            polygon([
                p(38, 62), p(66, 51), p(90, 51), p(92, 62), p(90, 84), p(70, 98), p(44, 98),
                p(46, 94), p(18, 114), p(24, 104), p(12, 106), p(34, 84), p(30, 84),
            ]))
        body.addPath(polygon([p(40, 72), p(70, 66), p(80, 76), p(58, 90), p(38, 86)]))
        fill(c, body, color, evenOdd: true)
        fill(
            c, polygon([p(42.2, 73.1), p(66.8, 68.2), p(75, 76.4), p(57.2, 88), p(40.8, 84.7)]),
            color)
        // Antenna, legs and toes.
        stroke(c, lines([[p(74, 24), p(68, 13)]]), color, width: 3, cap: .round)
        stroke(
            c, lines([[p(56, 96), p(54, 104)], [p(72, 96), p(72, 104)]]), color, width: 4,
            cap: .round)
        stroke(c, lines(toes), color, width: 2.4, cap: .round)
    }

    // MARK: - cainary-macos.svg

    private static func drawColored(_ c: CGContext) {
        // Legs.
        stroke(
            c, lines([[p(56, 94), p(54, 104)], [p(72, 92), p(72, 104)]]), rgb(0x90a4ae), width: 4,
            cap: .round)
        stroke(c, lines(toes), rgb(0x546e7a), width: 2.2, cap: .round)
        for x: CGFloat in [54, 72] {
            fill(c, circle(x, 104, 2.6), rgb(0xcfd8dc))
            stroke(c, circle(x, 104, 2.6), rgb(0x455a64), width: 1)
        }
        // Tail.
        fill(c, polygon([p(36, 82), p(12, 106), p(24, 104), p(18, 114), p(46, 94)]), rgb(0xc99700))
        // Body.
        fillLinear(
            c,
            polygon([
                p(38, 62), p(68, 50), p(92, 62), p(90, 84), p(70, 98), p(44, 98), p(30, 84),
            ]), plate, diagonal: true)
        stroke(
            c, lines([[p(68, 50), p(66, 70), p(90, 84)], [p(66, 70), p(44, 98)]]), rgb(0xb38600),
            width: 1.6)
        fill(c, circle(86, 66, 1.4), rgb(0x9e7700))
        fill(c, circle(85, 80, 1.4), rgb(0x9e7700))
        // Wing.
        let wing = polygon([p(40, 72), p(70, 66), p(80, 76), p(58, 90), p(38, 86)])
        fill(c, wing, rgb(0xe0a800))
        stroke(c, wing, rgb(0x9e7700), width: 1.6, join: .round)
        stroke(
            c, lines([[p(46, 78), p(72, 72)], [p(46, 84), p(66, 80)]]), rgb(0x9e7700), width: 1.4)
        // Neck joint.
        fillLinear(c, roundedRect(64, 50, 24, 7, 2), steel, diagonal: false)
        // Antenna: a stroke filled with the gradient over the line's own box, as in the SVG.
        let antenna = lines([[p(74, 28), p(68, 13)]])
        let shaft = antenna.copy(
            strokingWithWidth: 3, lineCap: .round, lineJoin: .miter, miterLimit: 10)
        fillLinear(c, shaft, steel, diagonal: false, box: antenna.boundingBoxOfPath)
        fill(c, circle(67.5, 12, 3.2), rgb(0xff1744))
        // Head.
        fillLinear(c, roundedRect(60, 24, 38, 30, 9), plate, diagonal: true)
        stroke(c, lines([[p(60, 40), p(72, 40)]]), rgb(0xb38600), width: 1.6)
        fill(c, circle(65, 30, 1.4), rgb(0x9e7700))
        fill(c, circle(65, 48, 1.4), rgb(0x9e7700))
        // Beak.
        fillLinear(c, polygon([p(97, 32), p(116, 40), p(97, 47)]), steel, diagonal: false)
        stroke(c, lines([[p(97, 40), p(112, 40)]]), rgb(0x455a64), width: 1.4)
        // Eye: the visor, its glow, the eye and its highlight.
        let visor = roundedRect(72, 30, 28, 16, 5)
        fill(c, visor, rgb(0x11181c))
        c.saveGState()
        c.addPath(visor)
        c.clip()
        c.drawRadialGradient(
            glow, startCenter: p(86, 38), startRadius: 0, endCenter: p(86, 38), endRadius: 14,
            options: [])
        c.restoreGState()
        c.saveGState()
        c.addPath(circle(86, 38, 5))
        c.clip()
        // The SVG's bounding-box gradient: centered at (0.4, 0.4) of the eye, radius 0.5.
        c.drawRadialGradient(
            eye, startCenter: p(85, 37), startRadius: 0, endCenter: p(85, 37), endRadius: 5,
            options: [.drawsAfterEndLocation])
        c.restoreGState()
        fill(c, circle(84.4, 36.4, 1.3), rgb(0xffe0e0))
    }

    private static let toes: [[CGPoint]] = ([54, 72] as [CGFloat]).flatMap { x in
        [[p(x, 104), p(x - 6, 108)], [p(x, 104), p(x, 110)], [p(x, 104), p(x + 6, 108)]]
    }

    private static let plate = gradient([(rgb(0xffd84d), 0), (rgb(0xe8b100), 1)])
    private static let steel = gradient([(rgb(0xcfd8dc), 0), (rgb(0x78909c), 1)])
    private static let glow = gradient([
        (rgb(0xff1744, 0.75), 0), (rgb(0xff1744, 0.3), 0.45), (rgb(0xff1744, 0), 1),
    ])
    private static let eye = gradient([
        (rgb(0xff8a80), 0), (rgb(0xff1744), 0.35), (rgb(0xb0001e), 1),
    ])

    // MARK: - Drawing

    private static func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x, y: y) }

    private static func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
        CGColor(
            srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
    }

    private static func gradient(_ stops: [(CGColor, CGFloat)]) -> CGGradient {
        CGGradient(
            colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
            colors: stops.map { $0.0 } as CFArray, locations: stops.map { $0.1 })!
    }

    private static func polygon(_ points: [CGPoint]) -> CGPath {
        let path = CGMutablePath()
        path.addLines(between: points)
        path.closeSubpath()
        return path
    }

    /// Open polylines, one per element.
    private static func lines(_ polylines: [[CGPoint]]) -> CGPath {
        let path = CGMutablePath()
        for points in polylines { path.addLines(between: points) }
        return path
    }

    private static func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) -> CGPath {
        CGPath(ellipseIn: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r), transform: nil)
    }

    private static func roundedRect(
        _ x: CGFloat, _ y: CGFloat, _ width: CGFloat, _ height: CGFloat, _ r: CGFloat
    ) -> CGPath {
        CGPath(
            roundedRect: CGRect(x: x, y: y, width: width, height: height), cornerWidth: r,
            cornerHeight: r, transform: nil)
    }

    private static func fill(
        _ c: CGContext, _ path: CGPath, _ color: CGColor, evenOdd: Bool = false
    ) {
        c.addPath(path)
        c.setFillColor(color)
        c.fillPath(using: evenOdd ? .evenOdd : .winding)
    }

    private static func stroke(
        _ c: CGContext, _ path: CGPath, _ color: CGColor, width: CGFloat, cap: CGLineCap = .butt,
        join: CGLineJoin = .miter
    ) {
        c.addPath(path)
        c.setStrokeColor(color)
        c.setLineWidth(width)
        c.setLineCap(cap)
        c.setLineJoin(join)
        c.strokePath()
    }

    /// Fills `path` with a gradient over `box` (the path's own by default): top-left to
    /// bottom-right when `diagonal`, else top to bottom, as SVG's bounding-box units.
    private static func fillLinear(
        _ c: CGContext, _ path: CGPath, _ gradient: CGGradient, diagonal: Bool, box: CGRect? = nil
    ) {
        let box = box ?? path.boundingBoxOfPath
        c.saveGState()
        c.addPath(path)
        c.clip()
        c.concatenate(
            CGAffineTransform(a: box.width, b: 0, c: 0, d: box.height, tx: box.minX, ty: box.minY))
        c.drawLinearGradient(
            gradient, start: .zero, end: CGPoint(x: diagonal ? 1 : 0, y: 1),
            options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        c.restoreGState()
    }
}
