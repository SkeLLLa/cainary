import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// cAInary Settings: a separate window, as KDE apps do.
ApplicationWindow {
    id: win

    // Parsed AppController.staticJson, set by Main.qml.
    property var st: null

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color warning: Style.warningColor(dark)
    readonly property var iconStyles: [
        { key: "monochrome", text: qsTr("Monochrome, colored badge") },
        { key: "full-monochrome", text: qsTr("Monochrome") },
        { key: "color", text: qsTr("Color") }
    ]
    readonly property var intervals: [
        { key: "5m", text: qsTr("5 minutes") },
        { key: "10m", text: qsTr("10 minutes") },
        { key: "30m", text: qsTr("30 minutes") },
        { key: "1h", text: qsTr("Hour") },
        { key: "daily", text: qsTr("Daily") }
    ]

    function present() {
        show();
        raise();
        requestActivate();
    }

    objectName: "settings"
    palette.window: sys.window
    palette.windowText: sys.windowText
    palette.base: sys.base
    palette.alternateBase: sys.alternateBase
    palette.text: sys.text
    palette.button: sys.button
    palette.buttonText: sys.buttonText
    palette.highlight: sys.highlight
    palette.highlightedText: sys.highlightedText
    palette.mid: sys.mid
    palette.midlight: sys.midlight
    palette.dark: sys.dark
    palette.light: sys.light
    palette.shadow: sys.shadow
    palette.link: sys.link
    palette.toolTipBase: sys.toolTipBase
    palette.toolTipText: sys.toolTipText
    palette.placeholderText: Qt.alpha(sys.windowText, 0.6)
    title: qsTr("cAInary Settings")
    width: 480
    height: Math.min(content.implicitHeight + 40, 720)
    minimumWidth: 420

    SystemColors { id: sys }

    Shortcut { sequences: ["Ctrl+W", "Esc"]; onActivated: win.close() }

    ScrollView {
        id: scroll
        anchors.fill: parent
        contentWidth: availableWidth

        ColumnLayout {
            id: content
            width: scroll.availableWidth
            spacing: 14

            component Section: GroupBox {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
            }

            Label {
                visible: SettingsController.loadError !== ""
                text: qsTr("Your settings file couldn't be read, so defaults are in use. Changing a setting will replace it.")
                color: win.warning
                wrapMode: Text.Wrap
                Layout.fillWidth: true
                Layout.topMargin: 20
                Layout.leftMargin: 20
                Layout.rightMargin: 20
            }

            Section {
                title: qsTr("Notifications")
                Layout.topMargin: SettingsController.loadError !== "" ? 0 : 20
                ColumnLayout {
                    anchors.fill: parent
                    Switch {
                        text: qsTr("Notify about changes")
                        checked: SettingsController.notifications
                        onToggled: SettingsController.notifications = checked
                    }
                    Label {
                        visible: !SettingsController.notificationsAvailable
                        text: qsTr("Notifications aren't available on this desktop.")
                        color: win.warning
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }

            Section {
                title: qsTr("Refresh")
                RowLayout {
                    anchors.fill: parent
                    spacing: 12
                    Label { text: qsTr("Scan every") }
                    ComboBox {
                        textRole: "text"
                        model: win.intervals
                        Layout.fillWidth: true
                        currentIndex: Math.max(0, win.intervals.findIndex(i => i.key === SettingsController.refresh))
                        onActivated: index => SettingsController.refresh = win.intervals[index].key
                    }
                }
            }

            Section {
                title: qsTr("Startup")
                ColumnLayout {
                    anchors.fill: parent
                    Switch {
                        text: qsTr("Launch at login")
                        checked: SettingsController.launchAtLogin
                        onToggled: SettingsController.launchAtLogin = checked
                    }
                    CheckBox {
                        text: qsTr("Start minimized to the tray")
                        checked: SettingsController.startMinimized
                        onToggled: SettingsController.startMinimized = checked
                    }
                    CheckBox {
                        text: qsTr("Close button minimizes to the tray")
                        checked: SettingsController.closeToTray
                        onToggled: SettingsController.closeToTray = checked
                    }
                    Label {
                        visible: SettingsController.launchAtLoginError.length > 0
                        text: SettingsController.launchAtLoginError
                        color: win.warning
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }

            Section {
                title: qsTr("Tray icon")
                ColumnLayout {
                    anchors.fill: parent
                    RowLayout {
                        spacing: 12
                        Label { text: qsTr("Style") }
                        ComboBox {
                            textRole: "text"
                            model: win.iconStyles
                            Layout.fillWidth: true
                            currentIndex: Math.max(0, win.iconStyles.findIndex(i => i.key === SettingsController.iconStyle))
                            onActivated: index => SettingsController.iconStyle = win.iconStyles[index].key
                        }
                    }
                    Label {
                        text: qsTr("Monochrome icons follow the panel's text color.")
                        color: win.palette.placeholderText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
            }

            Section {
                title: qsTr("Support Ukraine")
                SupportLinks {
                    anchors.fill: parent
                    support: win.st ? win.st.support : null
                }
            }

            Section {
                title: qsTr("Privacy tools")
                SupportLinks {
                    anchors.fill: parent
                    support: win.st ? win.st.privacy : null
                }
            }

            Section {
                title: qsTr("Version")
                Layout.bottomMargin: 20
                ColumnLayout {
                    anchors.fill: parent
                    spacing: 4
                    component Row: RowLayout {
                        property alias label: key.text
                        property alias value: val.text
                        spacing: 8
                        Label {
                            id: key
                            color: win.palette.placeholderText
                            Layout.preferredWidth: 80
                        }
                        Label {
                            id: val
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                    }
                    Row {
                        label: qsTr("Version")
                        value: win.st ? win.st.build.version + " (" + win.st.build.commit + ")" : ""
                        Layout.fillWidth: true
                    }
                    Row {
                        label: qsTr("Built")
                        value: win.st ? win.st.build.built : ""
                        Layout.fillWidth: true
                    }
                    Row {
                        label: qsTr("Scanner")
                        value: AppController.cliVersion.length > 0
                               ? AppController.cliVersion.replace(/^cainary /, "") : qsTr("not found")
                        Layout.fillWidth: true
                    }
                    RowLayout {
                        spacing: 12
                        Layout.topMargin: 6
                        Label {
                            visible: win.st !== null
                            text: "<a href=\"" + (win.st ? win.st.about.repo : "") + "\">" + qsTr("Source code") + "</a>"
                            textFormat: Text.StyledText
                            linkColor: win.palette.link
                            onLinkActivated: url => Style.openExternal(url)
                        }
                        Item { Layout.fillWidth: true }
                        Button {
                            text: qsTr("About cAInary…")
                            onClicked: AppController.showAbout()
                        }
                    }
                }
            }
        }
    }
}
