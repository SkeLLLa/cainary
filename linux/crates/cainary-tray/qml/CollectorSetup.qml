pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// Live › OTel collector › Setup: how agents reach the collector (point them here, or the HTTPS
// takeover), the lines to give them, and where received data goes. The collector's own output is
// on Logs and the red-flag rules are on Red flags.
ScrollView {
    id: root

    required property CollectorData collector
    required property CollectorSettingsModel model
    property var endpointHosts: []
    // Takeover step key → whether the user opened it; the page keeps it across tab switches.
    property var openSteps: ({})

    signal showLogsRequested
    signal stepToggled(string key, bool open)

    readonly property bool takeover: model.value.tls
    readonly property var view: collector.view
    // A failure whose fix is in a step shows there; any other shows on top.
    readonly property var topFailure: {
        if (view.failure === null || collector.portFailure !== null || (takeover && collector.hostFailure !== null))
            return null;
        return view.failure;
    }
    readonly property var privilege: collector.privilegedFailure ? ({ state: "none" }) : view.privilege
    readonly property bool linesAvailable: view.claudeCode.length > 0 || view.codex.length > 0

    component Heading: Label {
        font.pointSize: Application.font.pointSize * 1.15
        font.weight: Font.DemiBold
        Layout.topMargin: Style.space.s
    }
    component Hint: Label {
        color: palette.placeholderText
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
        Layout.leftMargin: 28
    }

    function turnOn() {
        root.model.change(next => { next.enabled = true; });
    }

    contentWidth: availableWidth
    topPadding: 4
    bottomPadding: 12
    clip: true

    ColumnLayout {
        x: 12
        width: root.availableWidth - 24
        spacing: Style.space.l

        // A failure no step can fix.
        Callout {
            visible: root.topFailure !== null
            tone: "error"
            title: root.topFailure ? root.topFailure.message : ""
            Layout.fillWidth: true
            Button {
                text: qsTr("Show logs")
                onClicked: root.showLogsRequested()
            }
        }

        Heading { text: qsTr("How agents reach the collector") }
        ColumnLayout {
            spacing: 0
            Layout.fillWidth: true
            ButtonGroup { id: modeChoice }
            RadioButton {
                text: qsTr("Point agents here")
                ButtonGroup.group: modeChoice
                checked: !root.takeover
                onToggled: if (checked) root.model.change(next => { next.tls = false; })
            }
            Hint { text: qsTr("Change each agent's OTel endpoint to this collector. Doesn't work when your organization locks the endpoint.") }
            RadioButton {
                text: qsTr("HTTPS takeover")
                ButtonGroup.group: modeChoice
                checked: root.takeover
                onToggled: if (checked) root.model.change(next => { next.tls = true; })
                Layout.topMargin: Style.space.xs
            }
            Hint {
                text: qsTr("Answer for your organization's collector host names, so agents keep their configured endpoint. Needs a few administrator steps.")
                    + (root.endpointHosts.length > 0
                        ? " " + qsTr("The latest scan found telemetry endpoints at %1.").arg(root.endpointHosts.join(", ")) : "")
            }
        }

        // Point agents here
        ColumnLayout {
            visible: !root.takeover
            spacing: Style.space.m
            Layout.fillWidth: true

            // The takeover's undo is hidden once switched back, but its /etc/hosts lines stay.
            Callout {
                id: leftoverHosts
                readonly property var hostsFile: root.view.hostsFile
                readonly property bool leftover: hostsFile.block === "current" || hostsFile.block === "stale"
                readonly property var removed: hostsFile.result !== null && hostsFile.result.op === "clear"
                    && hostsFile.result.message.length > 0 ? hostsFile.result : null
                visible: leftover || removed !== null
                tone: leftover ? "warning" : "info"
                title: leftover ? qsTr("/etc/hosts still sends the takeover host names to this computer")
                    : qsTr("Takeover lines removed")
                body: leftover ? qsTr("Other programs can't reach those names until cAInary's lines are removed.")
                    : removed ? removed.message : ""
                Layout.fillWidth: true

                RowLayout {
                    visible: leftoverHosts.leftover
                    spacing: Style.space.m
                    Button {
                        text: qsTr("Remove from /etc/hosts…")
                        enabled: root.view.hostsFile.canRemove
                        onClicked: CollectorController.removeHostsLines()
                    }
                    Label {
                        visible: root.view.hostsFile.busy
                        text: qsTr("Enter your password in the system dialog.")
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }

            Heading { text: qsTr("Point agents here") }
            ReceiverPort {
                model: root.model
                privilege: root.privilege
                Layout.fillWidth: true
            }
            CollectorFailure {
                visible: root.collector.portFailure !== null
                failure: root.collector.portFailure
                privilege: root.view.privilege
                effectivePort: root.model.value.port
                onTryPortRequested: port => root.model.change(next => { next.port = port; })
                Layout.fillWidth: true
            }
            RowLayout {
                visible: root.view.endpoint.length > 0 && root.linesAvailable
                spacing: Style.space.m
                Layout.fillWidth: true
                Label { text: qsTr("Endpoint") }
                TextField {
                    text: root.view.endpoint
                    readOnly: true
                    selectByMouse: true
                    font.family: "monospace"
                    Layout.fillWidth: true
                }
                Button {
                    text: qsTr("Copy")
                    Accessible.name: qsTr("Copy the endpoint")
                    onClicked: CollectorController.copyText(root.view.endpoint)
                }
            }
            RowLayout {
                visible: !root.linesAvailable
                spacing: Style.space.m
                Layout.fillWidth: true
                Label {
                    text: root.view.state === "off"
                        ? qsTr("The collector is off. Turn it on to get the lines for Claude Code and Codex.")
                        : qsTr("The lines for Claude Code and Codex appear once the collector is listening.")
                    textFormat: Text.PlainText
                    color: palette.placeholderText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Button {
                    visible: root.view.state === "off"
                    text: qsTr("Turn on")
                    onClicked: root.turnOn()
                }
            }
            Label {
                visible: root.view.claudeCode.length > 0
                text: qsTr("Claude Code: start it from a shell with these variables set")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            CommandBlock {
                visible: root.view.claudeCode.length > 0
                lines: root.view.claudeCode
                copyName: qsTr("the Claude Code variables")
                Layout.fillWidth: true
            }
            Label {
                visible: root.view.codex.length > 0
                text: qsTr("Codex: add to ~/.codex/config.toml [otel], or pass each line as codex -c '<line>'")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            CommandBlock {
                visible: root.view.codex.length > 0
                lines: root.view.codex
                copyName: qsTr("the Codex lines")
                Layout.fillWidth: true
            }
            Disclosure {
                visible: root.view.notes.length > 0
                title: qsTr("If nothing arrives")
                Repeater {
                    model: root.view.notes
                    delegate: Label {
                        required property string modelData
                        text: "• " + modelData
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }
        }

        // HTTPS takeover
        TakeoverGuide {
            visible: root.takeover
            collector: root.collector
            model: root.model
            endpointHosts: root.endpointHosts
            openSteps: root.openSteps
            Layout.fillWidth: true
            onStepToggled: (key, open) => root.stepToggled(key, open)
            onTurnOnRequested: root.turnOn()
            onHostFocused: field => {
                const flick = root.contentItem;
                const y = field.mapToItem(flick.contentItem, 0, 0).y;
                flick.contentY = Math.max(0, Math.min(y - 80, flick.contentHeight - flick.height));
            }
        }

        Heading { text: qsTr("Received data") }
        ReceiverSettings {
            model: root.model
            showPort: false
            Layout.fillWidth: true
        }
    }
}
