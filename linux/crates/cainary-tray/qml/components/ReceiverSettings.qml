import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary

// Received data: where batches go besides the UI window.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    property var privilege: ({ state: "none" })
    // Shows the plain port too, as the page does today. The new Setup page sets this to false.
    property bool showPort: true

    // The plain port moves to the "Point agents here" section; until the page does that it stays here.
    ReceiverPort {
        visible: root.showPort && !root.model.value.tls
        model: root.model
        privilege: root.privilege
        Layout.fillWidth: true
    }
    Label {
        visible: root.showPort && root.model.value.tls
        text: qsTr("The HTTPS takeover below sets the port while it is on.")
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }

    ButtonGroup { id: logChoice }
    RadioButton {
        text: qsTr("Show in this window only")
        ButtonGroup.group: logChoice
        checked: !root.model.value.log_to_file
        onToggled: if (checked) root.model.change(next => { next.log_to_file = false; })
    }
    RadioButton {
        text: qsTr("Also save to a file")
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
