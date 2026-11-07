import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "style.js" as Style

// One numbered step of a checklist: a header (number or check, title, status, disclosure arrow)
// that toggles the body. Children form the body. The caller owns `expanded` and updates it from
// `toggled`, so it can remember the choice.
ColumnLayout {
    id: root

    property int number: 1
    property int total: 0
    property string title: ""
    // Shown under the title while collapsed.
    property string summary: ""
    // "done" | "todo" | "waiting" | "unknown" | "off"
    property string stepState: "todo"
    property string statusText: ""
    property bool expanded: false
    default property alias body: inner.data

    // The header was activated; the caller flips `expanded`.
    signal toggled

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property bool done: stepState === "done"
    readonly property color stateColor: done ? Style.okColor(dark)
        : stepState === "todo" ? Style.warningColor(dark) : palette.placeholderText
    readonly property string stateGlyph: done ? "check"
        : stepState === "todo" ? "warning" : stepState === "waiting" ? "pending" : "unknown"
    // The status wraps under the title in a narrow window.
    readonly property bool narrow: width < 520

    spacing: Style.space.s
    Layout.fillWidth: true

    Item {
        id: header
        Layout.fillWidth: true
        implicitHeight: Math.max(headerRow.implicitHeight, 28)

        Accessible.role: Accessible.Button
        Accessible.name: (root.total > 0 ? qsTr("Step %1 of %2: %3.").arg(root.number).arg(root.total).arg(root.title)
                                         : qsTr("Step %1: %2.").arg(root.number).arg(root.title))
            + (root.statusText.length > 0 ? " " + root.statusText + "." : "")
        Accessible.description: root.expanded ? qsTr("Expanded") : qsTr("Collapsed")
        Accessible.onPressAction: root.toggled()
        activeFocusOnTab: true
        Keys.onSpacePressed: root.toggled()
        Keys.onReturnPressed: root.toggled()

        TapHandler {
            cursorShape: Qt.PointingHandCursor
            onTapped: root.toggled()
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
            id: headerRow
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: 10
            Rectangle {
                implicitWidth: 24
                implicitHeight: 24
                radius: 12
                color: root.done ? root.stateColor : "transparent"
                border.color: root.done ? root.stateColor : Qt.alpha(palette.windowText, 0.45)
                Layout.alignment: Qt.AlignTop
                Label {
                    visible: !root.done
                    anchors.centerIn: parent
                    text: root.number
                    font.weight: Font.DemiBold
                }
                GlyphIcon {
                    visible: root.done
                    anchors.centerIn: parent
                    glyph: "check"
                    size: 14
                    color: palette.window
                }
            }
            GridLayout {
                columns: root.narrow ? 1 : 2
                columnSpacing: 10
                rowSpacing: 0
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: 0
                    Layout.fillWidth: true
                    Label {
                        text: root.title
                        textFormat: Text.PlainText
                        font.weight: Font.DemiBold
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                    Label {
                        visible: !root.expanded && root.summary.length > 0
                        text: root.summary
                        textFormat: Text.PlainText
                        color: palette.placeholderText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
                RowLayout {
                    spacing: 4
                    visible: root.statusText.length > 0
                    Layout.alignment: root.narrow ? Qt.AlignLeft : (Qt.AlignRight | Qt.AlignTop)
                    GlyphIcon {
                        glyph: root.stateGlyph
                        size: 14
                        color: root.stateColor
                    }
                    Label {
                        text: root.statusText
                        textFormat: Text.PlainText
                        color: root.stateColor
                    }
                }
            }
            GlyphIcon {
                glyph: root.expanded ? "chevron-down" : "chevron-right"
                size: 14
                color: palette.windowText
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }
        }
    }

    ColumnLayout {
        id: inner
        visible: root.expanded
        spacing: Style.space.s
        Layout.fillWidth: true
        Layout.leftMargin: 34
    }
}
