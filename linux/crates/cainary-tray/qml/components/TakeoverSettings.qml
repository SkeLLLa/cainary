pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// The HTTPS takeover switch, its port and the host names it answers for.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    // Telemetry endpoint hosts from the latest scan, offered as one-click additions.
    property var endpointHosts: []
    property var privilege: ({ state: "none" })
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

    Switch {
        text: qsTr("Use HTTPS takeover")
        checked: root.model.value.tls
        onToggled: root.model.change(next => { next.tls = checked; })
    }
    Label {
        visible: root.model.value.tls
        text: qsTr("Your organization's collector receives nothing while the takeover is on.")
        color: root.warning
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    RowLayout {
        enabled: root.model.value.tls
        Label { text: qsTr("Port") }
        SpinBox {
            from: 1
            to: 65535
            value: Math.max(1, root.model.value.tls_port || 8443)
            editable: true
            onValueModified: root.model.change(next => { next.tls_port = value; })
        }
        Item { Layout.fillWidth: true }
    }
    PrivilegedPortNote {
        visible: root.model.value.tls && (root.privilege.state || "none") !== "none"
        privilege: root.privilege
        Layout.fillWidth: true
    }
    Label { text: qsTr("Host names"); font.weight: Font.DemiBold }
    Repeater {
        id: hostRepeater
        model: root.model.value.tls_hosts
        delegate: ColumnLayout {
            id: host
            required property int index
            required property var modelData
            enabled: root.model.value.tls
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
        visible: root.model.value.tls && root.model.value.tls_hosts.length === 0
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
                enabled: root.model.value.tls
                    && root.model.value.tls_hosts.length < 32
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
        enabled: root.model.value.tls && root.model.value.tls_hosts.length < 32
        onClicked: root.model.change(next => { next.tls_hosts.push(""); })
    }
}
