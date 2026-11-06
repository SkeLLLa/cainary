import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary

ColumnLayout {
    id: root

    property var payload: null
    property bool expanded: false

    visible: payload !== null && payload !== undefined
    spacing: 6

    ToolButton {
        Layout.fillWidth: true
        text: (root.expanded ? "▾ " : "▸ ") + qsTr("What it sends")
        onClicked: root.expanded = !root.expanded
        Accessible.name: qsTr("What it sends")
    }

    ColumnLayout {
        visible: root.expanded && root.payload !== null
        Layout.fillWidth: true
        Layout.leftMargin: 8
        Layout.rightMargin: 8
        spacing: 8

        RowLayout {
            Layout.fillWidth: true
            Label {
                text: root.payload ? root.payload.heading : ""
                font.weight: Font.DemiBold
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: root.payload && root.payload.maybe
                text: qsTr("may")
                color: palette.placeholderText
            }
            Button {
                visible: root.payload && root.payload.docs.length > 0
                text: qsTr("Docs")
                onClicked: Qt.openUrlExternally(root.payload.docs)
            }
        }

        Repeater {
            model: root.payload ? root.payload.gates : []
            delegate: RowLayout {
                required property var modelData
                Layout.fillWidth: true
                Label {
                    text: modelData.chip
                    font.pointSize: Application.font.pointSize * 0.85
                    color: modelData.chip === "sent" ? "#2d8a57" : palette.placeholderText
                }
                Label {
                    visible: modelData.label.length > 0
                    text: modelData.label
                    font.weight: Font.DemiBold
                    textFormat: Text.PlainText
                }
                Label {
                    text: modelData.text
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }

        component AttributeGroup: ColumnLayout {
            property string heading
            property var rows
            Layout.fillWidth: true
            spacing: 3
            Label {
                visible: rows && rows.length > 0
                text: heading
                font.weight: Font.DemiBold
                color: palette.placeholderText
            }
            Repeater {
                model: rows || []
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Label {
                        text: modelData.key
                        font.family: "monospace"
                        textFormat: Text.PlainText
                    }
                    Label {
                        text: "— " + modelData.what
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                    Label {
                        visible: modelData.maybe
                        text: qsTr("may")
                        color: palette.placeholderText
                    }
                    Label {
                        visible: modelData.content && modelData.sent.length > 0
                        text: modelData.sent + (modelData.gate.length > 0 ? " · " + modelData.gate : "")
                        color: modelData.sent === "yes" ? "#2d8a57" : palette.placeholderText
                        font.pointSize: Application.font.pointSize * 0.8
                    }
                    Label {
                        visible: modelData.when.length > 0
                        text: qsTr("only in some cases: ") + modelData.when
                        textFormat: Text.PlainText
                        color: palette.placeholderText
                        wrapMode: Text.Wrap
                    }
                }
            }
        }

        AttributeGroup {
            heading: qsTr("Identity (on every record)")
            rows: root.payload ? root.payload.identity : []
        }
        AttributeGroup {
            heading: qsTr("Identity (only in some cases)")
            rows: root.payload ? root.payload.conditionalIdentity : []
        }
        AttributeGroup {
            heading: qsTr("Resource")
            rows: root.payload ? root.payload.resource : []
        }

        Repeater {
            model: root.payload ? root.payload.records : []
            delegate: ColumnLayout {
                required property var modelData
                Layout.fillWidth: true
                spacing: 4
                RowLayout {
                    Layout.fillWidth: true
                    Label {
                        text: modelData.title
                        font.family: "monospace"
                        font.weight: Font.DemiBold
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                    Label {
                        visible: modelData.observed
                        text: qsTr("seen")
                        color: palette.placeholderText
                    }
                    Label {
                        visible: modelData.maybe
                        text: qsTr("may")
                        color: palette.placeholderText
                    }
                }
                Label {
                    visible: modelData.what.length > 0
                    text: modelData.what + (modelData.unit.length > 0 ? " · " + modelData.unit : "")
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Repeater {
                    model: modelData.attrs
                    delegate: RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        Label {
                            text: modelData.key
                            font.family: "monospace"
                            textFormat: Text.PlainText
                        }
                        Label {
                            text: "— " + modelData.what
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        Label {
                            visible: modelData.maybe
                            text: qsTr("may")
                            color: palette.placeholderText
                        }
                        Label {
                            visible: modelData.content && modelData.sent.length > 0
                            text: modelData.sent + (modelData.gate.length > 0 ? " · " + modelData.gate : "")
                            color: modelData.sent === "yes" ? "#2d8a57" : palette.placeholderText
                            font.pointSize: Application.font.pointSize * 0.8
                        }
                    }
                }
            }
        }

        Label {
            visible: root.payload && root.payload.sample.length > 0
            text: qsTr("Sample")
            font.weight: Font.DemiBold
        }
        TextArea {
            visible: root.payload && root.payload.sample.length > 0
            text: root.payload ? root.payload.sample : ""
            readOnly: true
            selectByMouse: true
            wrapMode: TextEdit.WrapAnywhere
            textFormat: TextEdit.PlainText
            font.family: "monospace"
            font.pointSize: Application.font.pointSize * 0.85
            Layout.fillWidth: true
        }
        Button {
            visible: root.payload && root.payload.sample.length > 0
            text: qsTr("Copy")
            onClicked: CollectorController.copyText(root.payload.sample)
        }
    }
}
