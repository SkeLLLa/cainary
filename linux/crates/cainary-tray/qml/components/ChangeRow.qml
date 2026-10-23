import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

// One change: marker, bold subject, text, optional "from → to" line.
RowLayout {
    id: root

    property var change

    spacing: 8

    Label {
        text: root.change ? root.change.marker : ""
        font.weight: Font.DemiBold
        Layout.alignment: Qt.AlignTop
        Layout.preferredWidth: 14
        horizontalAlignment: Text.AlignHCenter
    }
    ColumnLayout {
        spacing: 0
        Layout.fillWidth: true
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: root.change ? (root.change.subject.length > 0 ? root.change.subject + " " : "") + root.change.text : ""
            font.weight: Font.Normal
        }
        Label {
            visible: root.change && root.change.fromTo.length > 0
            text: root.change ? root.change.fromTo : ""
            font.pointSize: Application.font.pointSize * 0.85
            color: root.palette.placeholderText
        }
    }
}
