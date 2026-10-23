import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

// Collapsible "What the levels mean".
ColumnLayout {
    id: root

    property var legend: []
    property bool expanded: false

    spacing: 4

    AbstractButton {
        id: toggle
        Layout.fillWidth: true
        implicitHeight: 28
        checkable: false
        onClicked: root.expanded = !root.expanded
        Accessible.name: qsTr("What the levels mean")
        Accessible.role: Accessible.Button
        contentItem: RowLayout {
            spacing: 6
            Label {
                text: root.expanded ? "▾" : "▸"
                color: root.palette.placeholderText
            }
            Label {
                text: qsTr("What the levels mean")
                font.weight: Font.Medium
                Layout.fillWidth: true
            }
        }
    }
    Repeater {
        model: root.expanded ? root.legend : []
        delegate: RowLayout {
            id: item
            required property var modelData
            spacing: 8
            Layout.fillWidth: true
            LevelIcon {
                level: item.modelData.level
                size: 16
                Layout.alignment: Qt.AlignTop
            }
            ColumnLayout {
                spacing: 0
                Layout.fillWidth: true
                Label {
                    text: item.modelData.title
                    font.weight: Font.Medium
                    font.pointSize: Application.font.pointSize * 0.9
                }
                Label {
                    text: item.modelData.meaning
                    wrapMode: Text.Wrap
                    font.pointSize: Application.font.pointSize * 0.85
                    color: root.palette.placeholderText
                    Layout.fillWidth: true
                }
            }
        }
    }
}
