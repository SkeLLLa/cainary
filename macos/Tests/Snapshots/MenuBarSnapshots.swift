import AppKit
import Foundation
import SwiftUI

// Every MenuState look, both icon styles, on a light and a dark menu bar strip.

@MainActor
func menuBarSnapshot(out: URL) {
    let states: [(String, MenuState)] = [
        ("template", MenuState(look: .template, badge: .none, label: "template")),
        ("template ?", MenuState(look: .template, badge: .unknown, label: "template ?")),
        ("dimmed", MenuState(look: .templateDimmed, badge: .none, label: "dimmed")),
        ("green", MenuState(look: .green, badge: .none, label: "green")),
        ("blue", MenuState(look: .blue, badge: .none, label: "blue")),
        ("yellow 1", MenuState(look: .yellow, badge: .count(1), label: "yellow")),
        ("orange 2", MenuState(look: .orange, badge: .count(2), label: "orange")),
        ("red 3", MenuState(look: .red, badge: .count(3), label: "red")),
        ("red 9", MenuState(look: .red, badge: .count(9), label: "red 9")),
    ]

    /// One strip: a menu bar coloured background with every state's icon in a row.
    func strip(style: IconStyle, dark: Bool) -> some View {
        let fg: Color = dark ? .white : .black
        return HStack(spacing: 18) {
            ForEach(states, id: \.0) { _, state in
                Image(nsImage: MenuBarIcon.image(state, style))
                    .foregroundStyle(fg)
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 28)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(dark ? Color(white: 0.16) : Color(white: 0.92))
    }

    func caption(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.secondary)
    }

    let sheet = VStack(alignment: .leading, spacing: 6) {
        caption("states: " + states.map(\.0).joined(separator: " · "))
        caption("color · light bar")
        strip(style: .color, dark: false)
        caption("color · dark bar")
        strip(style: .color, dark: true)
        caption("monochrome · light bar")
        strip(style: .monochrome, dark: false)
        caption("monochrome · dark bar")
        strip(style: .monochrome, dark: true)
    }
    .padding(10)
    .frame(width: 480)

    let url = out.appendingPathComponent("menubar.png")
    let size = writePNG(sheet, to: url, background: Color(white: 0.5))
    checkPNG("menubar.png", url, size: size, heights: 100...600)
}
