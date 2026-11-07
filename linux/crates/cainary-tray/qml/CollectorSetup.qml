pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"

// Live › OTel collector › Setup: how to point Claude Code and Codex at the collector, the HTTPS
// takeover trust flow, and the collector's own settings.
ScrollView {
    id: root

    required property CollectorData collector
    required property CollectorSettingsModel model
    property var endpointHosts: []

    component SetupBlock: ColumnLayout {
        id: block
        property string heading
        property var lines
        Layout.fillWidth: true
        Label {
            text: block.heading
            font.weight: Font.DemiBold
        }
        TextArea {
            text: (block.lines || []).join("\n")
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
            onClicked: CollectorController.copyText((block.lines || []).join("\n"))
        }
    }


    contentWidth: availableWidth
    topPadding: 4
    bottomPadding: 12
    clip: true

    ColumnLayout {
        x: 12
        width: root.availableWidth - 24
        spacing: 12

        CollectorFailure {
            failure: root.collector.view.failure
            privilege: root.collector.view.privilege
            effectivePort: root.model.value.tls ? root.model.value.tls_port : root.model.value.port
            onAddHostRequested: takeover.addHostAndFocus()
            onTryPortRequested: port => root.model.change(next => {
                if (next.tls)
                    next.tls_port = port;
                else
                    next.port = port;
            })
            Layout.fillWidth: true
        }

        GroupBox {
            visible: root.collector.view.stderrTail.length > 0
            title: qsTr("Collector listen error (copyable)")
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
            }
        }

        GroupBox {
            title: qsTr("Receiver")
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                RowLayout {
                    visible: root.collector.view.endpoint.length > 0
                    Layout.fillWidth: true
                    Label { text: qsTr("Listening") }
                    TextField {
                        text: root.collector.view.endpoint
                        readOnly: true
                        selectByMouse: true
                        font.family: "monospace"
                        Layout.fillWidth: true
                    }
                    Button {
                        text: qsTr("Copy")
                        onClicked: CollectorController.copyText(root.collector.view.endpoint)
                    }
                }
                ReceiverSettings {
                    model: root.model
                    privilege: root.collector.privilegedFailure ? ({ state: "none" }) : root.collector.view.privilege
                    Layout.fillWidth: true
                }
            }
        }

        GroupBox {
            visible: root.collector.view.claudeCode.length > 0 || root.collector.view.codex.length > 0
            title: qsTr("Point an agent at it")
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 8
                SetupBlock { heading: qsTr("Claude Code"); lines: root.collector.view.claudeCode }
                SetupBlock { heading: qsTr("Codex"); lines: root.collector.view.codex }
                Repeater {
                    // The takeover warning lives in step 3 while the takeover is on.
                    model: root.collector.view.notes.filter(n => !/receives nothing/i.test(n))
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
            title: qsTr("HTTPS takeover")
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                TakeoverSettings {
                    id: takeover
                    model: root.model
                    endpointHosts: root.endpointHosts
                    privilege: root.collector.privilegedFailure ? ({ state: "none" }) : root.collector.view.privilege
                    Layout.fillWidth: true
                    onHostFocused: field => {
                        const flick = root.contentItem;
                        const y = field.mapToItem(flick.contentItem, 0, 0).y;
                        flick.contentY = Math.max(0, Math.min(y - 80, flick.contentHeight - flick.height));
                    }
                }
                SetupBlock {
                    visible: root.collector.view.takeover.length > 0
                    heading: qsTr("Hosts file and trust settings")
                    lines: root.collector.view.takeover
                }
                Label {
                    visible: root.collector.view.caSha256.length > 0
                    text: qsTr("Local CA SHA-256: ") + root.collector.view.caSha256
                    font.family: "monospace"
                    wrapMode: Text.WrapAnywhere
                    Layout.fillWidth: true
                }
                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Let Claude Code trust the collector…")
                        enabled: !root.collector.view.trust.busy
                        onClicked: CollectorController.previewClaudeTrust()
                    }
                    Button {
                        text: qsTr("Undo Claude Code trust")
                        enabled: !root.collector.view.trust.busy
                            && root.collector.view.trust.status
                            && root.collector.view.trust.status.claudeCode.state === "applied"
                        onClicked: CollectorController.undoClaudeTrust()
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Prepare Codex bundle")
                        enabled: !root.collector.view.trust.busy
                        onClicked: CollectorController.prepareCodexBundle()
                    }
                    Button {
                        text: qsTr("Remove")
                        enabled: !root.collector.view.trust.busy
                            && root.collector.view.trust.status
                            && root.collector.view.trust.status.codex.state === "ready"
                        onClicked: CollectorController.undoCodexBundle()
                    }
                }
                Label {
                    visible: root.collector.view.trust.busy
                    text: qsTr("Working…")
                    color: palette.placeholderText
                }
                Label {
                    visible: root.collector.view.trust.message.length > 0
                    text: root.collector.view.trust.message
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                TextArea {
                    visible: root.collector.view.trust.status
                        && root.collector.view.trust.status.codex.command
                        && root.collector.view.trust.status.codex.state === "ready"
                    text: visible ? root.collector.view.trust.status.codex.command : ""
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    Layout.fillWidth: true
                }
                Button {
                    visible: root.collector.view.trust.status
                        && root.collector.view.trust.status.codex.command
                        && root.collector.view.trust.status.codex.state === "ready"
                    text: qsTr("Copy Codex command")
                    onClicked: CollectorController.copyText(root.collector.view.trust.status.codex.command)
                }
                ColumnLayout {
                    visible: root.collector.view.trust.noWriteAvailable
                    Layout.fillWidth: true
                    Label {
                        text: qsTr("No-write alternative for Claude Code")
                        font.weight: Font.DemiBold
                    }
                    TextArea {
                        text: root.collector.view.trust.noWriteCommand
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
                        onClicked: CollectorController.copyText(root.collector.view.trust.noWriteCommand)
                    }
                }
                Label {
                    visible: !root.collector.view.trust.noWriteAvailable
                    text: qsTr("Start the HTTPS takeover once to create the certificate.")
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    color: palette.placeholderText
                    Layout.fillWidth: true
                }
                Text {
                    visible: root.collector.view.trust.result
                        && root.collector.view.trust.result.target.length > 0
                    text: root.collector.view.trust.result
                        ? root.collector.view.trust.result.target + " · " + root.collector.view.trust.result.action
                        : ""
                    textFormat: Text.PlainText
                    color: palette.placeholderText
                    Layout.fillWidth: true
                }
                Label {
                    visible: root.collector.view.trust.result
                        && root.collector.view.trust.result.message.length > 0
                    text: root.collector.view.trust.result
                        ? root.collector.view.trust.result.message : ""
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }

        GroupBox {
            title: qsTr("Red-flag rules")
            Layout.fillWidth: true
            RedFlagRules { anchors.fill: parent; model: root.model; showNotify: false }
        }
    }

    Dialog {
        id: trustDialog
        modal: true
        parent: Overlay.overlay
        anchors.centerIn: Overlay.overlay
        width: Math.min(480, parent.width - 48)
        title: qsTr("Let Claude Code trust the local collector?")
        property bool dismissed: false
        visible: root.collector.view.trust.preview !== null && !dismissed
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
                text: root.collector.view.trust.preview
                    ? root.collector.view.trust.preview.message : ""
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.key)
                text: root.collector.view.trust.preview
                    ? qsTr("Change: %1\nFrom: %2\nTo: %3")
                        .arg(root.collector.view.trust.preview.key || "")
                        .arg(root.collector.view.trust.preview.from || qsTr("not set"))
                        .arg(root.collector.view.trust.preview.to || "") : ""
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.settingsPath)
                text: qsTr("Settings: ") + (root.collector.view.trust.preview ? root.collector.view.trust.preview.settingsPath : "")
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.backupPath)
                text: qsTr("Backup: ") + (root.collector.view.trust.preview ? root.collector.view.trust.preview.backupPath : "")
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
            if (root.collector.view.trust.preview === null)
                trustDialog.dismissed = false;
        }
    }
}
