import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Stands in for a step body whose commands come from the collector, while it has not said hello.
RowLayout {
    id: root

    // The collector is on, so only waiting helps.
    property bool collectorOn: false

    signal turnOnRequested

    spacing: 8
    Layout.fillWidth: true

    Label {
        text: root.collectorOn ? qsTr("The commands appear once the collector is listening.")
                               : qsTr("Turn the collector on to get these commands.")
        textFormat: Text.PlainText
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Button {
        visible: !root.collectorOn
        text: qsTr("Turn on")
        onClicked: root.turnOnRequested()
    }
}
