import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary

ColumnLayout {
    id: root

    readonly property var collectorView: {
        try {
            const value = JSON.parse(CollectorController.viewJson);
            return {
                state: value.state || "off",
                message: value.message || "",
                endpoint: value.endpoint || "",
                claudeCode: value.claudeCode || [],
                codex: value.codex || [],
                notes: value.notes || [],
                alerts: value.alerts || [],
                batches: value.batches || [],
                errors: value.errors || []
            };
        } catch (error) {
            return ({ state: "off", message: "", endpoint: "", claudeCode: [], codex: [], notes: [], alerts: [], batches: [], errors: [] });
        }
    }

    spacing: 12

    RowLayout {
        Layout.fillWidth: true
        Label {
            text: qsTr("OTel debug collector")
            font.pointSize: Application.font.pointSize * 1.4
            font.weight: Font.DemiBold
            Layout.fillWidth: true
        }
        Button {
            visible: root.collectorView.state === "failed" || root.collectorView.state === "stopped"
            text: qsTr("Retry")
            onClicked: CollectorController.retry()
        }
    }

    Label {
        visible: root.collectorView.state === "off"
        text: qsTr("The collector is off. Enable it in Settings to start a local receiver.")
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }

    Button {
        visible: root.collectorView.state === "off"
        text: qsTr("Open Settings")
        onClicked: AppController.showSettings()
    }

    Label {
        visible: root.collectorView.message.length > 0
        text: root.collectorView.message
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        color: root.collectorView.state === "failed" ? palette.brightText : palette.placeholderText
        Layout.fillWidth: true
    }

    RowLayout {
        visible: root.collectorView.endpoint.length > 0
        Layout.fillWidth: true
        Label { text: qsTr("Listening") }
        TextField {
            id: endpoint
            text: root.collectorView.endpoint
            readOnly: true
            selectByMouse: true
            font.family: "monospace"
            Layout.fillWidth: true
        }
        Button {
            text: qsTr("Copy")
            onClicked: CollectorController.copyText(root.collectorView.endpoint)
        }
    }

    GroupBox {
        visible: root.collectorView.claudeCode.length > 0 || root.collectorView.codex.length > 0
        title: qsTr("Setup")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            spacing: 8
            component SetupBlock: ColumnLayout {
                property string heading
                property var lines
                Layout.fillWidth: true
                Label {
                    text: heading
                    font.weight: Font.DemiBold
                }
                TextArea {
                    text: (lines || []).join("\n")
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    Layout.fillWidth: true
                    implicitHeight: Math.min(120, Math.max(42, contentHeight + 12))
                }
                Button {
                    text: qsTr("Copy")
                    onClicked: CollectorController.copyText((lines || []).join("\n"))
                }
            }
            SetupBlock { heading: qsTr("Claude Code"); lines: root.collectorView.claudeCode }
            SetupBlock { heading: qsTr("Codex"); lines: root.collectorView.codex }
            Repeater {
                model: root.collectorView.notes
                delegate: Label {
                    required property string modelData
                    text: modelData
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }
    }

    GroupBox {
        title: qsTr("Red flags")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            Label {
                visible: root.collectorView.alerts.length === 0
                text: qsTr("No red flags received.")
                color: palette.placeholderText
            }
            Repeater {
                model: root.collectorView.alerts
                delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 2
                    RowLayout {
                        Layout.fillWidth: true
                        Label {
                            text: modelData.pattern
                            font.weight: Font.DemiBold
                            Layout.fillWidth: true
                        }
                        Label { text: modelData.signal; color: palette.placeholderText }
                        Label { text: "×" + modelData.count; color: palette.placeholderText }
                    }
                    Label {
                        text: [modelData.event, modelData.attribute, modelData.matched].filter(x => x.length > 0).join(" · ")
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }
        }
    }

    GroupBox {
        title: qsTr("Batches")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            Label {
                visible: root.collectorView.batches.length === 0
                text: qsTr("No batches received yet.")
                color: palette.placeholderText
            }
            Repeater {
                model: root.collectorView.batches
                delegate: ColumnLayout {
                    id: batchRow
                    required property var modelData
                    property bool expanded: false
                    Layout.fillWidth: true
                    spacing: 5
                    ToolButton {
                        Layout.fillWidth: true
                        text: (batchRow.expanded ? "▾ " : "▸ ")
                              + batchRow.modelData.signal + " · "
                              + (batchRow.modelData.catalog || batchRow.modelData.vendor)
                              + " · " + batchRow.modelData.records + qsTr(" records")
                        onClicked: batchRow.expanded = !batchRow.expanded
                    }
                    ColumnLayout {
                        visible: batchRow.expanded
                        Layout.fillWidth: true
                        Label {
                            text: batchRow.modelData.timestamp + " · " + batchRow.modelData.endpointPath
                            color: palette.placeholderText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        Label {
                            visible: batchRow.modelData.identity.length > 0
                            text: qsTr("Identity: ") + batchRow.modelData.identity.join(" · ")
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        Label {
                            visible: batchRow.modelData.resource.length > 0
                            text: qsTr("Resource: ") + batchRow.modelData.resource.join(" · ")
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        Repeater {
                            model: batchRow.modelData.summary
                            delegate: ColumnLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                RowLayout {
                                    Layout.fillWidth: true
                                    Label {
                                        text: modelData.name + " ×" + modelData.count
                                        font.family: "monospace"
                                        font.weight: Font.DemiBold
                                        Layout.fillWidth: true
                                    }
                                    Label {
                                        visible: !modelData.known
                                        text: qsTr("not in catalog")
                                        color: "#c77612"
                                    }
                                }
                                Label {
                                    visible: modelData.what.length > 0
                                    text: modelData.what
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
                                            text: modelData.group.length > 0 ? modelData.group : qsTr("unknown")
                                            color: modelData.group === "content" ? "#c77612" : palette.placeholderText
                                            font.pointSize: Application.font.pointSize * 0.8
                                        }
                                        Label {
                                            text: modelData.key
                                            font.family: "monospace"
                                            Layout.fillWidth: true
                                        }
                                        Label {
                                            visible: modelData.flag.length > 0
                                            text: modelData.flag
                                            color: palette.placeholderText
                                        }
                                        Label {
                                            visible: !modelData.known
                                            text: qsTr("not in catalog")
                                            color: "#c77612"
                                        }
                                    }
                                }
                            }
                        }
                        Label {
                            visible: batchRow.modelData.notInCatalog > 0
                            text: qsTr("%1 items not in catalog").arg(batchRow.modelData.notInCatalog)
                            color: "#c77612"
                        }
                        Label {
                            visible: batchRow.modelData.resourcesOmitted
                            text: qsTr("Raw records were omitted to keep the output within its size limit.")
                            color: palette.placeholderText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        ToolButton {
                            visible: batchRow.modelData.rawRecords.length > 2
                            text: qsTr("Raw records")
                            onClicked: raw.visible = !raw.visible
                        }
                        TextArea {
                            id: raw
                            visible: false
                            text: batchRow.modelData.rawRecords
                            readOnly: true
                            selectByMouse: true
                            wrapMode: TextEdit.WrapAnywhere
                            textFormat: TextEdit.PlainText
                            font.family: "monospace"
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }
    }

    GroupBox {
        visible: root.collectorView.errors.length > 0
        title: qsTr("Collector messages")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            Repeater {
                model: root.collectorView.errors
                delegate: Label {
                    required property var modelData
                    text: modelData.source + ": " + modelData.message
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }
    }
}
