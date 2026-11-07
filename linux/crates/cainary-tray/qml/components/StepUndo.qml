import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// The end of a setup step's body: how to take back what the step changed. Children follow the
// heading.
ColumnLayout {
    id: root

    property string text: ""
    default property alias body: inner.data

    spacing: Style.space.s
    Layout.fillWidth: true
    Layout.topMargin: Style.space.s

    Rectangle {
        height: 1
        color: Qt.alpha(palette.windowText, 0.12)
        Layout.fillWidth: true
    }
    Label {
        text: qsTr("Undo this step")
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }
    Label {
        visible: root.text.length > 0
        text: root.text
        textFormat: Text.PlainText
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    ColumnLayout {
        id: inner
        spacing: Style.space.s
        Layout.fillWidth: true
    }
}
