import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "style.js" as Style

// What a port below 1024 needs: that it asks for administrator permission, what is missing when
// the port helper isn't installed (copyable, never run), or the button that opens the port.
// `privilege` is the collector view's privilege object (tray-model's `portaccess`).
ColumnLayout {
    id: root

    property var privilege: ({ state: "none" })
    // The failure box above has its own heading.
    property bool showHeading: true

    readonly property string access: privilege.state || "none"
    readonly property var instructions: privilege.instructions || []
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color accent: Style.warningColor(dark)

    visible: access !== "none"
    spacing: 4

    Label {
        visible: root.showHeading && (root.privilege.heading || "").length > 0
        text: root.privilege.heading || ""
        textFormat: Text.PlainText
        font.weight: Font.DemiBold
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        visible: (root.privilege.detail || "").length > 0
        text: root.privilege.detail || ""
        textFormat: Text.PlainText
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        visible: (root.privilege.warning || "").length > 0
        text: root.privilege.warning || ""
        textFormat: Text.PlainText
        color: root.accent
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        visible: (root.privilege.error || "").length > 0
        text: root.privilege.error || ""
        textFormat: Text.PlainText
        color: root.accent
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    TextArea {
        visible: root.instructions.length > 0
        text: root.instructions.join("\n")
        readOnly: true
        selectByMouse: true
        wrapMode: TextEdit.WrapAnywhere
        textFormat: TextEdit.PlainText
        font.family: "monospace"
        Layout.fillWidth: true
        implicitHeight: Math.max(42, contentHeight + 12)
    }
    RowLayout {
        spacing: 8
        Button {
            visible: root.instructions.length > 0
            text: qsTr("Copy")
            onClicked: CollectorController.copyText(root.instructions.join("\n"))
        }
        Button {
            visible: root.privilege.canOpen === true
            enabled: root.privilege.busy !== true
            text: qsTr("Open port %1").arg(root.privilege.port || 0)
            onClicked: CollectorController.openPrivilegedPort()
        }
    }
}
