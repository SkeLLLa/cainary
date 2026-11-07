import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// A text header with a chevron that shows or hides its children. `expanded` is the initial state;
// the header flips it from then on.
ColumnLayout {
    id: root

    property string title: ""
    property bool expanded: false
    property bool bold: false
    default property alias body: inner.data

    spacing: Style.space.s
    Layout.fillWidth: true

    Item {
        id: header
        implicitHeight: Math.max(row.implicitHeight, 24)
        implicitWidth: row.implicitWidth

        Accessible.role: Accessible.Button
        Accessible.name: root.title
        Accessible.description: root.expanded ? qsTr("Expanded") : qsTr("Collapsed")
        Accessible.onPressAction: root.activate()
        activeFocusOnTab: true
        Keys.onSpacePressed: root.activate()
        Keys.onReturnPressed: root.activate()

        TapHandler {
            cursorShape: Qt.PointingHandCursor
            onTapped: root.activate()
        }
        Rectangle {
            anchors.fill: parent
            anchors.margins: -2
            visible: header.activeFocus
            color: "transparent"
            border.color: palette.highlight
            radius: 3
        }
        RowLayout {
            id: row
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6
            GlyphIcon {
                glyph: root.expanded ? "chevron-down" : "chevron-right"
                size: 12
                color: root.bold ? palette.windowText : palette.link
            }
            Label {
                text: root.title
                textFormat: Text.PlainText
                font.weight: root.bold ? Font.DemiBold : Font.Normal
                color: root.bold ? palette.windowText : palette.link
            }
        }
    }

    ColumnLayout {
        id: inner
        visible: root.expanded
        spacing: Style.space.s
        Layout.fillWidth: true
        Layout.leftMargin: 18
    }

    function activate() {
        root.expanded = !root.expanded;
    }
}
