import QtQuick
import QtQuick.Controls
import "style.js" as Style

// A small count pill: "3" after a sidebar row or tab. Red for red flags, neutral otherwise.
Rectangle {
    id: root

    property int count: 0
    property bool alert: false
    // On a highlighted (selected) row the badge inverts.
    property bool onHighlight: false
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color tint: alert ? Style.levelColor("high", dark, palette.windowText) : palette.windowText

    visible: count > 0
    implicitWidth: Math.max(implicitHeight, label.implicitWidth + 10)
    implicitHeight: label.implicitHeight + 2
    radius: implicitHeight / 2
    color: onHighlight ? Qt.alpha(palette.highlightedText, 0.25) : alert ? tint : Qt.alpha(tint, 0.12)

    Label {
        id: label
        anchors.centerIn: parent
        text: root.count > 99 ? "99+" : root.count
        font.pointSize: Application.font.pointSize * 0.8
        font.weight: Font.DemiBold
        color: root.onHighlight ? root.palette.highlightedText : root.alert ? "white" : Qt.alpha(root.tint, 0.8)
    }
}
