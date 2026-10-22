import AppKit
import Foundation
import SwiftUI

// Shared by the snapshot suites: rendering a view to a PNG and checking the result.

/// Renders `view` at 2× on `background`, in the light or dark appearance, and writes a PNG.
/// Returns the size in points, or nil when rendering failed.
@MainActor
@discardableResult
func writePNG<V: View>(
    _ view: V, to url: URL, dark: Bool = false,
    background: Color = Color(nsColor: .windowBackgroundColor)
) -> CGSize? {
    // Dynamic colours resolve against the current appearance, so set both.
    let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    NSApp.appearance = appearance
    var size: CGSize?
    appearance?.performAsCurrentDrawingAppearance {
        let framed =
            view
            .background(background)
            .environment(\.colorScheme, dark ? .dark : .light)
        let renderer = ImageRenderer(content: framed)
        renderer.scale = 2
        guard let image = renderer.cgImage else { return }
        let rep = NSBitmapImageRep(cgImage: image)
        guard let data = rep.representation(using: .png, properties: [:]) else { return }
        do {
            try data.write(to: url)
            size = CGSize(width: image.width / 2, height: image.height / 2)
        } catch {}
    }
    return size
}

/// Checks that the PNG was written, isn't empty and is between `heights` points tall.
@MainActor
func checkPNG(_ name: String, _ url: URL, size: CGSize?, heights: ClosedRange<CGFloat>) {
    let bytes = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
    check("\(name): written and not empty", size != nil && bytes > 0)
    if let size {
        check("\(name): sane height (\(Int(size.height)) pt)", heights.contains(size.height))
    }
}
