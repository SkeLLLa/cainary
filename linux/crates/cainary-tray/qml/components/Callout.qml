import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// A notice with a coloured bar: a warning, an error or information. Children go under the body
// (buttons, disclosures).
Rectangle {
    id: root

    // "warning" | "error" | "info"
    property string tone: "warning"
    property string title: ""
    property string body: ""
    default property alias extra: more.data

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color accent: tone === "error" ? Style.errorColor(dark)
        : tone === "info" ? Style.infoColor(dark) : Style.warningColor(dark)

    implicitHeight: column.implicitHeight + 20
    radius: 4
    color: Qt.alpha(accent, 0.10)
    Accessible.role: tone === "error" ? Accessible.AlertMessage : Accessible.StaticText
    Accessible.name: title.length > 0 ? title : body

    Rectangle {
        width: 3
        height: parent.height
        radius: 1
        color: root.accent
    }
    RowLayout {
        id: column
        x: 14
        y: 10
        width: parent.width - 24
        spacing: 8
        GlyphIcon {
            glyph: root.tone === "error" ? "error" : root.tone === "info" ? "info" : "warning"
            color: root.accent
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 1
        }
        ColumnLayout {
            spacing: 4
            Layout.fillWidth: true
            Label {
                visible: root.title.length > 0
                text: root.title
                textFormat: Text.PlainText
                font.weight: Font.DemiBold
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: root.body.length > 0
                text: root.body
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            ColumnLayout {
                id: more
                spacing: 4
                Layout.fillWidth: true
            }
        }
    }
}
