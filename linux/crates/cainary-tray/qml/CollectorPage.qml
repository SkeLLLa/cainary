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
                takeover: value.takeover || [],
                mode: value.mode || "receiver",
                tlsHosts: value.tlsHosts || [],
                caPath: value.caPath || "",
                caSha256: value.caSha256 || "",
                stderrTail: value.stderrTail || "",
                alerts: value.alerts || [],
                batches: value.batches || [],
                errors: value.errors || [],
                trust: value.trust || ({ busy: false, message: "", status: null, preview: null, result: null, noWriteAvailable: false, noWriteCommand: "" })
            };
        } catch (error) {
            return ({ state: "off", message: "", endpoint: "", claudeCode: [], codex: [], notes: [], takeover: [], mode: "receiver", tlsHosts: [], caPath: "", caSha256: "", stderrTail: "", alerts: [], batches: [], errors: [], trust: ({ busy: false, message: "", status: null, preview: null, result: null, noWriteAvailable: false, noWriteCommand: "" }) });
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
            SetupBlock {
                visible: root.collectorView.takeover.length > 0
                heading: qsTr("HTTPS takeover")
                lines: root.collectorView.takeover
            }
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
        title: qsTr("HTTPS takeover trust")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            Label {
                text: qsTr("Hosts: ") + root.collectorView.tlsHosts.join(", ")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: root.collectorView.caSha256.length > 0
                text: qsTr("Local CA SHA-256: ") + root.collectorView.caSha256
                font.family: "monospace"
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("Let Claude Code trust the collector…")
                    enabled: !root.collectorView.trust.busy
                    onClicked: CollectorController.previewClaudeTrust()
                }
                Button {
                    text: qsTr("Undo Claude Code trust")
                    enabled: !root.collectorView.trust.busy
                        && root.collectorView.trust.status
                        && root.collectorView.trust.status.claudeCode.state === "applied"
                    onClicked: CollectorController.undoClaudeTrust()
                }
            }
            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("Prepare Codex bundle")
                    enabled: !root.collectorView.trust.busy
                    onClicked: CollectorController.prepareCodexBundle()
                }
                Button {
                    text: qsTr("Remove")
                    enabled: !root.collectorView.trust.busy
                        && root.collectorView.trust.status
                        && root.collectorView.trust.status.codex.state === "ready"
                    onClicked: CollectorController.undoCodexBundle()
                }
            }
            Label {
                visible: root.collectorView.trust.busy
                text: qsTr("Working…")
                color: palette.placeholderText
            }
            Label {
                visible: root.collectorView.trust.message.length > 0
                text: root.collectorView.trust.message
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            TextArea {
                visible: root.collectorView.trust.status
                    && root.collectorView.trust.status.codex.command
                    && root.collectorView.trust.status.codex.state === "ready"
                text: visible ? root.collectorView.trust.status.codex.command : ""
                readOnly: true
                selectByMouse: true
                wrapMode: TextEdit.WrapAnywhere
                textFormat: TextEdit.PlainText
                font.family: "monospace"
                Layout.fillWidth: true
            }
            Button {
                visible: root.collectorView.trust.status
                    && root.collectorView.trust.status.codex.command
                    && root.collectorView.trust.status.codex.state === "ready"
                text: qsTr("Copy Codex command")
                onClicked: CollectorController.copyText(root.collectorView.trust.status.codex.command)
            }
            ColumnLayout {
                visible: root.collectorView.trust.noWriteAvailable
                Layout.fillWidth: true
                Label {
                    text: qsTr("No-write alternative for Claude Code")
                    font.weight: Font.DemiBold
                }
                TextArea {
                    text: root.collectorView.trust.noWriteCommand
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    Layout.fillWidth: true
                    implicitHeight: Math.max(42, contentHeight + 12)
                }
                Button {
                    text: qsTr("Copy no-write command")
                    onClicked: CollectorController.copyText(root.collectorView.trust.noWriteCommand)
                }
            }
            Label {
                visible: !root.collectorView.trust.noWriteAvailable
                text: qsTr("Start the HTTPS takeover once to create the certificate.")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                color: palette.placeholderText
                Layout.fillWidth: true
            }
            Text {
                visible: root.collectorView.trust.result
                    && root.collectorView.trust.result.target.length > 0
                text: root.collectorView.trust.result
                    ? root.collectorView.trust.result.target + " · " + root.collectorView.trust.result.action
                    : ""
                textFormat: Text.PlainText
                color: palette.placeholderText
                Layout.fillWidth: true
            }
            Label {
                visible: root.collectorView.trust.result
                    && root.collectorView.trust.result.message.length > 0
                text: root.collectorView.trust.result
                    ? root.collectorView.trust.result.message : ""
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }

    Dialog {
        id: trustDialog
        modal: true
        width: 480
        title: qsTr("Let Claude Code trust the local collector?")
        property bool dismissed: false
        visible: root.collectorView.trust.preview !== null && !dismissed
        onAccepted: {
            dismissed = true;
            CollectorController.applyClaudeTrust();
        }
        onRejected: {
            dismissed = true;
            CollectorController.cancelClaudeTrustPreview();
        }
        footer: DialogButtonBox {
            Button {
                text: qsTr("Cancel")
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
            }
            Button {
                text: qsTr("Confirm")
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            }
        }
        contentItem: ColumnLayout {
            spacing: 10
            Label {
                text: root.collectorView.trust.preview
                    ? root.collectorView.trust.preview.message : ""
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collectorView.trust.preview && root.collectorView.trust.preview.key)
                text: root.collectorView.trust.preview
                    ? qsTr("Change: %1\nFrom: %2\nTo: %3")
                        .arg(root.collectorView.trust.preview.key || "")
                        .arg(root.collectorView.trust.preview.from || qsTr("not set"))
                        .arg(root.collectorView.trust.preview.to || "") : ""
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collectorView.trust.preview && root.collectorView.trust.preview.settingsPath)
                text: qsTr("Settings: ") + (root.collectorView.trust.preview ? root.collectorView.trust.preview.settingsPath : "")
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collectorView.trust.preview && root.collectorView.trust.preview.backupPath)
                text: qsTr("Backup: ") + (root.collectorView.trust.preview ? root.collectorView.trust.preview.backupPath : "")
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                text: qsTr("Your org's collector receives nothing while the takeover is active.")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }

    Connections {
        target: CollectorController
        function onViewJsonChanged() {
            if (root.collectorView.trust.preview === null)
                trustDialog.dismissed = false;
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
        visible: root.collectorView.stderrTail.length > 0
        title: qsTr("Collector listen error (copyable)")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.fill: parent
            TextArea {
                text: root.collectorView.stderrTail
                readOnly: true
                selectByMouse: true
                wrapMode: TextEdit.WrapAnywhere
                textFormat: TextEdit.PlainText
                font.family: "monospace"
                Layout.fillWidth: true
            }
            Button {
                text: qsTr("Copy error details")
                onClicked: CollectorController.copyText(root.collectorView.stderrTail)
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
