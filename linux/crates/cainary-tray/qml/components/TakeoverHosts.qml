pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// The host names the HTTPS takeover answers for (step 1 of the takeover): one field each, errors,
// and one-click suggestions from the latest scan.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    // Telemetry endpoint hosts from the latest scan, offered as one-click additions.
    property var endpointHosts: []
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color warning: Style.warningColor(dark)
    // The host field that should take focus once the row for it exists.
    property int focusIndex: -1

    // A host field was focused (so the page can scroll to it).
    signal hostFocused(Item field)

    // Focuses the first empty host name, adding a row when there is none.
    function addHostAndFocus() {
        const hosts = root.model.value.tls_hosts;
        const empty = hosts.findIndex(item => item === "");
        if (empty >= 0 && hostRepeater.itemAt(empty)) {
            hostRepeater.itemAt(empty).focusField();
            return;
        }
        if (hosts.length >= 32)
            return;
        root.focusIndex = hosts.length;
        root.model.change(next => { next.tls_hosts.push(""); });
    }

    Repeater {
        id: hostRepeater
        model: root.model.value.tls_hosts
        delegate: ColumnLayout {
            id: host
            required property int index
            required property var modelData
            Layout.fillWidth: true
            function focusField() {
                field.forceActiveFocus();
                root.hostFocused(field);
            }
            Component.onCompleted: {
                if (root.focusIndex === host.index) {
                    root.focusIndex = -1;
                    host.focusField();
                }
            }
            RowLayout {
                Layout.fillWidth: true
                TextField {
                    id: field
                    text: host.modelData
                    placeholderText: qsTr("otel.example.com")
                    onEditingFinished: root.model.change(next => { next.tls_hosts[host.index] = text; })
                    Layout.fillWidth: true
                }
                ToolButton {
                    text: "−"
                    Accessible.name: qsTr("Remove host name")
                    onClicked: root.model.change(next => { next.tls_hosts.splice(host.index, 1); })
                }
            }
            Label {
                visible: host.index < root.model.value.tlsHostErrors.length
                    && root.model.value.tlsHostErrors[host.index] !== ""
                text: host.index < root.model.value.tlsHostErrors.length
                    ? root.model.value.tlsHostErrors[host.index] : ""
                color: root.warning
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }
    Label {
        visible: root.model.value.tls_hosts.length === 0
        text: qsTr("Add at least one DNS host name to enable the takeover.")
        color: root.warning
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Flow {
        visible: root.endpointHosts.length > 0
        Layout.fillWidth: true
        spacing: 6
        Repeater {
            model: root.endpointHosts
            delegate: Button {
                required property string modelData
                text: qsTr("Add %1").arg(modelData)
                visible: root.model.value.tls_hosts.length < 32
                    && root.model.value.tls_hosts.findIndex(item => item.toLowerCase() === modelData) < 0
                onClicked: root.model.addTlsHost(modelData)
            }
        }
    }
    Label {
        visible: root.endpointHosts.length > 0
        text: qsTr("Suggestions from Claude Code and Codex telemetry endpoints in the latest scan.")
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Button {
        text: qsTr("Add host name")
        enabled: root.model.value.tls_hosts.length < 32
        onClicked: root.model.change(next => { next.tls_hosts.push(""); })
    }
}
