import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary

// The collector's plain receiver: port and where batches go besides the UI.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    property var privilege: ({ state: "none" })
    readonly property string access: privilege.state || "none"

    RowLayout {
        visible: !root.model.value.tls
        Label { text: qsTr("Port") }
        SpinBox {
            from: 1
            to: 65535
            value: Math.max(1, root.model.value.port || 4318)
            editable: true
            onValueModified: root.model.change(next => { next.port = value; })
        }
        Item { Layout.fillWidth: true }
    }
    PrivilegedPortNote {
        visible: !root.model.value.tls && root.access !== "none"
        privilege: root.privilege
        Layout.fillWidth: true
    }
    Label {
        visible: root.model.value.tls
        text: qsTr("The HTTPS takeover below sets the port while it is on.")
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }

    ButtonGroup { id: logChoice }
    RadioButton {
        text: qsTr("Show in UI only")
        ButtonGroup.group: logChoice
        checked: !root.model.value.log_to_file
        onToggled: if (checked) root.model.change(next => { next.log_to_file = false; })
    }
    RadioButton {
        text: qsTr("Also save to:")
        ButtonGroup.group: logChoice
        checked: root.model.value.log_to_file
        onToggled: if (checked) root.model.change(next => { next.log_to_file = true; })
    }
    RowLayout {
        enabled: root.model.value.log_to_file
        Layout.fillWidth: true
        TextField {
            text: root.model.value.log_path
            placeholderText: qsTr("Suggested: ") + (root.model.value.logPathSuggestion || "~/.local/state/cainary/otel-debug.jsonl")
            onEditingFinished: root.model.change(next => { next.log_path = text; })
            Layout.fillWidth: true
        }
        Button {
            visible: SettingsController.fileChooserAvailable
            text: qsTr("Choose…")
            onClicked: SettingsController.chooseCollectorLogFile()
        }
    }
    Label {
        visible: !SettingsController.fileChooserAvailable
        text: qsTr("The desktop file chooser portal isn't available; enter a path above.")
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
}
