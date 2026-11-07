import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// Why the collector can't run, with the one action that fixes it: a host name for the HTTPS
// takeover, the next free port, or opening a port below 1024. Other failures just say why.
Rectangle {
    id: root

    // { code, message, port } from the collector view.
    property var failure: null
    property var privilege: null
    // The port the collector tries to listen on, for "Try port N+1" when it didn't say.
    property int effectivePort: 0

    signal addHostRequested()
    signal tryPortRequested(int port)

    readonly property string code: failure && failure.code ? failure.code : ""
    readonly property int port: failure && failure.port ? failure.port : effectivePort
    readonly property bool privilegedCode: code === "port-privileged" || code === "listen-fd"
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color accent: Style.warningColor(dark)

    visible: failure !== null && failure !== undefined
    implicitHeight: content.implicitHeight + 16
    radius: 6
    color: Qt.alpha(accent, 0.12)

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: 8
        spacing: 6

        Label {
            text: root.failure ? root.failure.message : ""
            textFormat: Text.PlainText
            font.weight: Font.DemiBold
            color: root.accent
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Button {
            visible: root.code === "tls-no-host"
            text: qsTr("Add host name")
            onClicked: root.addHostRequested()
        }
        Button {
            visible: root.code === "port-in-use" && root.port > 0 && root.port < 65535
            text: qsTr("Try port %1").arg(root.port + 1)
            onClicked: root.tryPortRequested(root.port + 1)
        }
        PrivilegedPortNote {
            visible: root.privilegedCode && root.privilege !== null && root.privilege.state !== "none"
            privilege: root.privilege || ({ state: "none" })
            showHeading: false
            Layout.fillWidth: true
        }
    }
}
