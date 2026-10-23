import QtQuick
import QtQuick.Controls
import ua.SkeLLLa.cAInary
import "style.js" as Style

// The "⋯" menu shared by the popup and the details window.
Menu {
    id: root

    property bool canCopy: false
    property var support
    // Emitted before an item acts, so the popup can get out of the way.
    signal activated()

    MenuItem {
        text: qsTr("Copy report")
        enabled: root.canCopy
        onTriggered: {
            root.activated();
            AppController.copyReport();
        }
    }
    MenuSeparator {}
    MenuItem {
        text: qsTr("Settings…")
        onTriggered: {
            root.activated();
            AppController.showSettings();
        }
    }
    MenuItem {
        text: qsTr("About cAInary")
        onTriggered: {
            root.activated();
            AppController.showAbout();
        }
    }
    Menu {
        title: qsTr("Support Ukraine")
        Repeater {
            model: root.support ? root.support.links : []
            delegate: MenuItem {
                required property var modelData
                text: modelData.title
                onTriggered: {
                    root.activated();
                    Style.openExternal(modelData.url);
                }
            }
        }
    }
    MenuSeparator {}
    MenuItem {
        text: qsTr("Quit cAInary")
        onTriggered: AppController.quit()
    }
}
