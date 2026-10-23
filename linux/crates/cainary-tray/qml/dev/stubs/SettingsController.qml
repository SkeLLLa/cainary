pragma Singleton
import QtQuick

QtObject {
    property bool notifications: true
    property string refresh: "1h"
    property bool launchAtLogin: false
    property bool startMinimized: true
    property bool closeToTray: true
    property string iconStyle: "monochrome"
    property string launchAtLoginError: "Couldn't write the autostart file"
    property bool notificationsAvailable: false
    property string loadError: ""
}
