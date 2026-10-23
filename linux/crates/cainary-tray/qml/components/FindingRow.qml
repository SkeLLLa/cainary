import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "style.js" as Style

// One finding: a collapsed row (chip, title, tags) that expands to the detail, who sets it, the
// path and the evidence. Right-click offers "Copy as JSON".
ColumnLayout {
    id: root

    property var finding
    property string entryId
    property bool expanded: false

    spacing: 0

    ItemDelegate {
        Layout.fillWidth: true
        onClicked: root.expanded = !root.expanded
        Accessible.name: root.finding ? root.finding.title : ""

    background: Rectangle {
            color: parent.highlighted ? parent.palette.highlight
                   : parent.hovered ? Qt.alpha(parent.palette.highlight, 0.12) : "transparent"
            radius: 4
        }

        contentItem: RowLayout {
            spacing: 8
            Label {
                text: root.expanded ? "▾" : "▸"
                color: root.palette.placeholderText
            }
            LevelChip {
                level: root.finding && root.finding.chip === "inactive" ? "not-installed" : (root.finding ? root.finding.level : "unknown")
                label: root.finding ? root.finding.chip : ""
            }
            Label {
                text: root.finding ? root.finding.title : ""
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Repeater {
                model: root.finding ? root.finding.tags : []
                delegate: Rectangle {
                    id: tag
                    required property string modelData
                    implicitWidth: tagLabel.implicitWidth + 10
                    implicitHeight: tagLabel.implicitHeight + 2
                    radius: height / 2
                    color: "transparent"
                    border.color: root.palette.mid
                    Label {
                        id: tagLabel
                        anchors.centerIn: parent
                        text: tag.modelData
                        font.pointSize: Application.font.pointSize * 0.8
                        color: root.palette.placeholderText
                    }
                }
            }
        }

        TapHandler {
            acceptedButtons: Qt.RightButton
            onTapped: copyMenu.popup()
        }
        Menu {
            id: copyMenu
            MenuItem {
                text: qsTr("Copy as JSON")
                onTriggered: AppController.copyFindingJson(root.entryId, root.finding.id)
            }
        }
    }

    ColumnLayout {
        visible: root.expanded
        spacing: 6
        Layout.fillWidth: true
        Layout.leftMargin: 28
        Layout.rightMargin: 8
        Layout.bottomMargin: 10

        Label {
            visible: text.length > 0
            text: root.finding ? root.finding.detail : ""
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Label {
            visible: text.length > 0
            text: root.finding ? root.finding.sends : ""
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Label {
            visible: text.length > 0
            text: root.finding ? root.finding.setBy : ""
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        TextEdit {
            visible: text.length > 0
            text: root.finding ? root.finding.path : ""
            readOnly: true
            selectByMouse: true
            wrapMode: TextEdit.WrapAnywhere
            font.family: "monospace"
            font.pointSize: Application.font.pointSize * 0.9
            color: root.palette.windowText
            selectedTextColor: root.palette.highlightedText
            selectionColor: root.palette.highlight
            Layout.fillWidth: true
        }
        TextArea {
            visible: text.length > 0
            text: root.finding ? root.finding.evidence : ""
            readOnly: true
            selectByMouse: true
            wrapMode: TextEdit.WrapAnywhere
            font.family: "monospace"
            font.pointSize: Application.font.pointSize * 0.9
            Layout.fillWidth: true
        }
        RowLayout {
            spacing: 8
            Button {
                visible: root.finding && root.finding.revealPath.length > 0
                text: qsTr("Show in File Manager")
                onClicked: AppController.revealPath(root.finding.revealPath)
            }
            Button {
                visible: root.finding && root.finding.docs.length > 0
                text: qsTr("Docs")
                onClicked: Style.openExternal(root.finding.docs)
            }
        }
    }
}
