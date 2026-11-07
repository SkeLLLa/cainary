import QtQuick
import QtQuick.Controls

// A TabButton with an optional count pill after its label ("Red flags (6)"). Set `label`, not
// `text`: Breeze (org.kde.desktop) paints `text` itself in the tab background, which would draw the
// label twice and ignore the badge. The content item draws the label here, so every style agrees,
// and `Accessible.name` carries it. The width is stated explicitly because Breeze sizes a tab from
// its `text` alone and a layout's implicit size doesn't reach the button inside a TabBar.
TabButton {
    id: root

    property string label
    property int count: 0
    property bool alert: false

    Accessible.name: label

    // Breeze zeroes the padding; keep the label off the tab's frame.
    leftPadding: 12
    rightPadding: 12
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
                text: root.label
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
