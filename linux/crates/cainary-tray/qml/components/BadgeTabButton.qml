import QtQuick
import QtQuick.Controls

// A TabButton with an optional count pill after its label ("Red flags (6)"). `text` stays set for
// accessibility and mnemonics; the content item draws it. The width is stated explicitly because a
// layout-based contentItem's implicit size doesn't reach the button inside a TabBar.
TabButton {
    id: root

    property int count: 0
    property bool alert: false

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            row.implicitWidth + leftPadding + rightPadding)

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight

        Row {
            id: row
            anchors.centerIn: parent
            spacing: 6

            Label {
                anchors.verticalCenter: parent.verticalCenter
                text: root.text
                color: palette.buttonText
            }
            CountBadge {
                anchors.verticalCenter: parent.verticalCenter
                count: root.count
                alert: root.alert
            }
        }
    }
}
