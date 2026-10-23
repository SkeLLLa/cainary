import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style
import ua.SkeLLLa.cAInary

// "Couldn't scan" with the reason, the last scan time and a Retry button. When `compact` it is a
// single orange line (used above stale results) showing failure.banner.
Rectangle {
    id: root

    property var failure
    property bool compact: false

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color accent: Style.warningColor(dark)

    visible: failure !== null && failure !== undefined
    implicitHeight: row.implicitHeight + 16
    radius: 6
    color: Qt.alpha(accent, 0.12)

    RowLayout {
        id: row
        anchors.fill: parent
        anchors.margins: 8
        spacing: 10

        ColumnLayout {
            spacing: 2
            Layout.fillWidth: true
            Label {
                text: root.compact ? (root.failure ? root.failure.banner : "") : qsTr("Couldn't scan")
                font.weight: Font.DemiBold
                color: root.accent
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: !root.compact
                text: root.failure ? root.failure.reason : ""
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: !root.compact && root.failure && root.failure.lastScan.length > 0
                text: root.failure ? root.failure.lastScan : ""
                color: root.palette.placeholderText
                font.pointSize: 9
            }
        }
        Button {
            text: qsTr("Retry")
            Layout.alignment: Qt.AlignVCenter
            onClicked: AppController.refresh()
        }
    }
}
