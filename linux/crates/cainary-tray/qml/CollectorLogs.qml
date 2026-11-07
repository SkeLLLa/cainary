pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"

// Live › OTel collector › Logs: what the collector itself reported — its messages and the tail of
// its stderr when it failed to listen.
ScrollView {
    id: root

    required property CollectorData collector

    readonly property bool empty: collector.view.stderrTail.length === 0 && collector.view.errors.length === 0

    contentWidth: availableWidth
    topPadding: 4
    bottomPadding: 12
    clip: true

    ColumnLayout {
        x: 12
        width: root.availableWidth - 24
        spacing: 12

        Label {
            visible: root.empty
            text: qsTr("The collector hasn't reported anything.")
            color: palette.placeholderText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
            Layout.topMargin: 8
        }

        GroupBox {
            visible: root.collector.view.errors.length > 0
            title: qsTr("Collector messages")
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                Repeater {
                    model: root.collector.view.errors
                    delegate: Label {
                        required property var modelData
                        text: modelData.source + ": " + modelData.message
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
                Button {
                    text: qsTr("Copy messages")
                    onClicked: CollectorController.copyText(root.collector.view.errors
                        .map(e => e.source + ": " + e.message).join("\n"))
                }
            }
        }

        GroupBox {
            visible: root.collector.view.stderrTail.length > 0
            title: qsTr("Collector listen error")
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                TextArea {
                    text: root.collector.view.stderrTail
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    Layout.fillWidth: true
                }
                Button {
                    text: qsTr("Copy error details")
                    onClicked: CollectorController.copyText(root.collector.view.stderrTail)
                }
            }
        }
    }
}
