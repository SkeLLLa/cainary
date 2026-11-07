import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The plain HTTP port ("Point agents here") with the port helper note for ports below 1024.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    property var privilege: ({ state: "none" })

    RowLayout {
        Label { text: qsTr("Port") }
        SpinBox {
            // A port number, not a quantity: no thousands separator.
            textFromValue: (value, locale) => String(value)
            valueFromText: (text, locale) => parseInt(text, 10) || 0
            from: 1
            to: 65535
            value: Math.max(1, root.model.value.port || 4318)
            editable: true
            onValueModified: root.model.change(next => { next.port = value; })
        }
        Item { Layout.fillWidth: true }
    }
    PrivilegedPortNote {
        privilege: root.privilege
        Layout.fillWidth: true
    }
}
