import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The port the HTTPS takeover listens on (step 2 of the takeover): the standard 443, which needs
// administrator permission, or another port that a redirect from 443 points at. Also the port
// helper note and, when the port is taken, the next free port.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    property var privilege: ({ state: "none" })

    readonly property int port: Math.max(1, root.model.value.tls_port || 443)
    readonly property bool standard: port === 443

    spacing: 4

    ButtonGroup { id: portChoice }
    RadioButton {
        text: qsTr("443, no redirect needed. Asks for administrator permission once per session.")
        ButtonGroup.group: portChoice
        checked: root.standard
        onToggled: if (checked) root.model.change(next => { next.tls_port = 443; })
        Layout.fillWidth: true
    }
    RowLayout {
        spacing: 8
        RadioButton {
            id: other
            text: qsTr("Another port, with a redirect from 443")
            ButtonGroup.group: portChoice
            checked: !root.standard
            onToggled: if (checked && root.standard) root.model.change(next => { next.tls_port = 8443; })
        }
        SpinBox {
            // A port number, not a quantity: no thousands separator.
            textFromValue: (value, locale) => String(value)
            valueFromText: (text, locale) => parseInt(text, 10) || 0
            from: 1
            to: 65535
            value: root.port
            editable: true
            enabled: other.checked
            onValueModified: root.model.change(next => { next.tls_port = value; })
        }
        Item { Layout.fillWidth: true }
    }
    PrivilegedPortNote {
        privilege: root.privilege
        Layout.fillWidth: true
    }
}
