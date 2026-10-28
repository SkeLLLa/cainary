import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "style.js" as Style

// A note and its links: "Support Ukraine", and the "Privacy tools" referral.
ColumnLayout {
    id: root

    property var support

    spacing: 4
    visible: support !== null && support !== undefined

    Label {
        text: root.support ? root.support.note : ""
        wrapMode: Text.Wrap
        Layout.fillWidth: true
        font.pointSize: Application.font.pointSize * 0.9
        color: root.palette.placeholderText
    }
    Flow {
        Layout.fillWidth: true
        spacing: 12
        Repeater {
            model: root.support ? root.support.links : []
            delegate: Label {
                id: link
                required property var modelData
                text: "<a href=\"" + modelData.url + "\">" + modelData.title + "</a>"
                textFormat: Text.StyledText
                linkColor: root.palette.link
                onLinkActivated: url => Style.openExternal(url)
                HoverHandler { cursorShape: Qt.PointingHandCursor }
            }
        }
    }
}
