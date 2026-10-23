import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

// One app/other-monitoring row in the popup.
ItemDelegate {
    id: root

    property var row
    property string meaning: ""

    enabled: row ? row.installed : true
    implicitHeight: Math.max(48, contentItem.implicitHeight + topPadding + bottomPadding)
    topPadding: 6
    bottomPadding: 6
    Accessible.name: row ? row.a11y : ""

    background: Rectangle {
            color: parent.highlighted ? parent.palette.highlight
                   : parent.hovered ? Qt.alpha(parent.palette.highlight, 0.12) : "transparent"
            radius: 4
        }

    contentItem: RowLayout {
        spacing: 10
        EntryIcon {
            iconKey: root.row ? root.row.iconKey : ""
            name: root.row ? root.row.name : ""
            installed: root.row ? root.row.installed : true
            size: 24
            Layout.alignment: Qt.AlignVCenter
        }
        ColumnLayout {
            spacing: 0
            Layout.fillWidth: true
            Label {
                text: root.row ? root.row.name : ""
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
            }
            Label {
                text: root.row ? root.row.summary : ""
                font.pointSize: Application.font.pointSize * 0.85
                color: root.palette.placeholderText
                elide: Text.ElideRight
                Layout.fillWidth: true
            }
        }
        LevelChip {
            level: root.row ? root.row.level : "unknown"
            label: root.row ? root.row.label : ""
            Layout.alignment: Qt.AlignVCenter
        }
    }
}
