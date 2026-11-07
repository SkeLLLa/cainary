import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary

// Read-only lines of commands or file content with a Copy button. Never height-capped, so
// nothing is cut off; long lines wrap.
Rectangle {
    id: root

    property var lines: []
    // Adds a muted "$" column (a hanging indent), for commands rather than file lines.
    property bool shell: false
    // What Copy copies, for the accessible name: "Copy <copyName>".
    property string copyName: ""

    implicitHeight: rows.implicitHeight + 14
    color: palette.base
    border.color: Qt.alpha(palette.windowText, 0.18)
    radius: 3

    ColumnLayout {
        id: rows
        x: 10
        y: 7
        width: parent.width - copy.width - 20
        spacing: root.shell ? 5 : 1
        Repeater {
            model: root.lines
            delegate: RowLayout {
                id: line
                required property string modelData
                spacing: 6
                Layout.fillWidth: true
                Text {
                    visible: root.shell
                    text: "$"
                    font.family: "monospace"
                    font.pointSize: Application.font.pointSize
                    color: palette.placeholderText
                    Layout.alignment: Qt.AlignTop
                }
                TextEdit {
                    text: line.modelData
                    readOnly: true
                    selectByMouse: true
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    font.pointSize: Application.font.pointSize
                    color: palette.text
                    selectionColor: palette.highlight
                    selectedTextColor: palette.highlightedText
                    wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
                    Layout.fillWidth: true
                }
            }
        }
    }

    Button {
        id: copy
        text: copied ? qsTr("Copied") : qsTr("Copy")
        flat: true
        property bool copied: false
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: 3
        Accessible.name: qsTr("Copy %1").arg(root.copyName)
        onClicked: {
            CollectorController.copyText(root.lines.join("\n"));
            copied = true;
            reset.restart();
            if (typeof Accessible.announce === "function")
                Accessible.announce(qsTr("Copied"));
        }
        Timer {
            id: reset
            interval: 1500
            onTriggered: copy.copied = false
        }
    }
}
