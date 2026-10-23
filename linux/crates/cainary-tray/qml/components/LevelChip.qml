import QtQuick
import QtQuick.Controls
import QtQuick.Window
import "style.js" as Style

// A capsule with the level's label (e.g. "MEDIUM"), tinted with the level colour.
Rectangle {
    id: root

    property string level: "unknown"
    property string label: ""
    // Legend meaning shown as a tooltip; empty for none.
    property string meaning: ""

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color tint: level === "not-installed" || level === "unknown"
        ? palette.windowText : Style.levelColor(level, dark, palette.windowText)
    readonly property real strength: level === "not-installed" ? 0.5 : (level === "unknown" ? 0.7 : 1)

    implicitWidth: text.implicitWidth + 14
    implicitHeight: text.implicitHeight + 4
    radius: height / 2
    color: Qt.alpha(tint, 0.12)

    Accessible.role: Accessible.StaticText
    Accessible.name: label

    Label {
        id: text
        anchors.centerIn: parent
        text: root.label
        font.pointSize: Application.font.pointSize * 0.85
        font.weight: Font.Medium
        color: Qt.alpha(root.tint, root.strength)
    }

    HoverHandler { id: hover }
    ToolTip.visible: hover.hovered && root.meaning.length > 0
    ToolTip.delay: 500
    ToolTip.text: root.meaning
}
