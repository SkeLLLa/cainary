import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// cAInary's app-wide settings. The Details window shows it as its "Settings" destination; the
// collector's own settings live with the collector (Live › OTel collector › Setup) there.
ColumnLayout {
    id: page

    // Parsed AppController.staticJson.
    property var st: null
    property var endpointHosts: []
    // Horizontal margin of every section.
    property int margin: 20
    signal collectorSetupRequested()

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

    spacing: 14

    CollectorSettingsModel { id: collector }

    component Section: GroupBox {
        Layout.fillWidth: true
        Layout.leftMargin: page.margin
        Layout.rightMargin: page.margin
    }

    Label {
        visible: SettingsController.loadError !== ""
        text: qsTr("Your settings file couldn't be read, so defaults are in use. Changing a setting will replace it.")
        color: page.warning
        wrapMode: Text.Wrap
        Layout.fillWidth: true
        Layout.leftMargin: page.margin
        Layout.rightMargin: page.margin
    }

    Section {
        title: qsTr("Notifications")
        ColumnLayout {
            anchors.fill: parent
            Switch {
                text: qsTr("Notify about changes")
                checked: SettingsController.notifications
                onToggled: SettingsController.notifications = checked
            }
            Switch {
                text: qsTr("Notify about red flags")
                checked: collector.value.notify
                onToggled: collector.change(next => { next.notify = checked; })
            }
            Label {
                visible: !SettingsController.notificationsAvailable
                text: qsTr("Notifications aren't available on this desktop.")
                color: page.warning
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }

    Section {
        title: qsTr("OTel debug collector")
        ColumnLayout {
            anchors.fill: parent
            RowLayout {
                Layout.fillWidth: true
                Label {
                    text: qsTr("Port, HTTPS takeover and red-flag rules are set up next to the feed.")
                    color: page.palette.placeholderText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Button {
                    text: qsTr("Collector setup →")
                    onClicked: page.collectorSetupRequested()
                }
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
                model: page.intervals
                Layout.fillWidth: true
                currentIndex: Math.max(0, page.intervals.findIndex(i => i.key === SettingsController.refresh))
                onActivated: index => SettingsController.refresh = page.intervals[index].key
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
                color: page.warning
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
                    model: page.iconStyles
                    Layout.fillWidth: true
                    currentIndex: Math.max(0, page.iconStyles.findIndex(i => i.key === SettingsController.iconStyle))
                    onActivated: index => SettingsController.iconStyle = page.iconStyles[index].key
                }
            }
            Label {
                text: qsTr("Monochrome icons follow the panel's text color.")
                color: page.palette.placeholderText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }

    Section {
        title: qsTr("Support Ukraine")
        SupportLinks {
            anchors.fill: parent
            support: page.st ? page.st.support : null
        }
    }

    Section {
        title: qsTr("Privacy tools")
        SupportLinks {
            anchors.fill: parent
            support: page.st ? page.st.privacy : null
        }
    }

    Section {
        title: qsTr("Version")
        ColumnLayout {
            anchors.fill: parent
            spacing: 4
            component Row: RowLayout {
                property alias label: key.text
                property alias value: val.text
                spacing: 8
                Label {
                    id: key
                    color: page.palette.placeholderText
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
                value: page.st ? page.st.build.version + " (" + page.st.build.commit + ")" : ""
                Layout.fillWidth: true
            }
            Row {
                label: qsTr("Built")
                value: page.st ? page.st.build.built : ""
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
                    visible: page.st !== null
                    text: "<a href=\"" + (page.st ? page.st.about.repo : "") + "\">" + qsTr("Source code") + "</a>"
                    textFormat: Text.StyledText
                    linkColor: page.palette.link
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
