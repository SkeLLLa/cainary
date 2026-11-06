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
    readonly property var collector: {
        const defaults = { enabled: false, port: 4318, log_to_file: false, log_path: "", presets: [], notify: true, patterns: [], patternErrors: [], overLimit: false, logPathSuggestion: "" };
        try {
            const value = JSON.parse(SettingsController.collectorJson);
            return {
                enabled: value.enabled === true,
                port: value.port || 4318,
                log_to_file: value.log_to_file === true,
                log_path: value.log_path || "",
                presets: value.presets || [],
                notify: value.notify !== false,
                patterns: value.patterns || [],
                patternErrors: value.patternErrors || [],
                overLimit: value.overLimit === true,
                logPathSuggestion: value.logPathSuggestion || ""
            };
        } catch (error) {
            return defaults;
        }
    }
    readonly property var collectorPresets: [
        { key: "email", label: qsTr("Email addresses") },
        { key: "private-key", label: qsTr("Private keys") },
        { key: "jwt", label: qsTr("JWTs") },
        { key: "aws-access-key", label: qsTr("AWS access keys") },
        { key: "github-token", label: qsTr("GitHub tokens") },
        { key: "anthropic-key", label: qsTr("Anthropic keys") },
        { key: "openai-key", label: qsTr("OpenAI keys") },
        { key: "slack-token", label: qsTr("Slack tokens") }
    ]

    function changeCollector(change) {
        const next = JSON.parse(JSON.stringify(win.collector));
        change(next);
        SettingsController.setCollector(JSON.stringify(next));
    }

    function updatePattern(index, key, value) {
        changeCollector(next => { next.patterns[index][key] = value; });
    }

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
                title: qsTr("OTel debug collector")
                ColumnLayout {
                    anchors.fill: parent
                    Switch {
                        text: qsTr("Enable local OTel debug collector")
                        checked: win.collector.enabled
                        onToggled: win.changeCollector(next => { next.enabled = checked; })
                    }
                    RowLayout {
                        Label { text: qsTr("Port") }
                        SpinBox {
                            from: 1024
                            to: 65535
                            value: Math.max(1024, win.collector.port || 4318)
                            editable: true
                            onValueModified: win.changeCollector(next => { next.port = value; })
                        }
                        Item { Layout.fillWidth: true }
                    }

                    ButtonGroup { id: logChoice }
                    RadioButton {
                        text: qsTr("Show in UI only")
                        ButtonGroup.group: logChoice
                        checked: !win.collector.log_to_file
                        onToggled: if (checked) win.changeCollector(next => { next.log_to_file = false; })
                    }
                    RadioButton {
                        text: qsTr("Also save to:")
                        ButtonGroup.group: logChoice
                        checked: win.collector.log_to_file
                        onToggled: if (checked) win.changeCollector(next => { next.log_to_file = true; })
                    }
                    RowLayout {
                        enabled: win.collector.log_to_file
                        TextField {
                            text: win.collector.log_path
                            placeholderText: qsTr("Suggested: ") + (win.collector.logPathSuggestion || "~/.local/state/cainary/otel-debug.jsonl")
                            onEditingFinished: win.changeCollector(next => { next.log_path = text; })
                            Layout.fillWidth: true
                        }
                        Button {
                            visible: SettingsController.fileChooserAvailable
                            text: qsTr("Choose…")
                            onClicked: SettingsController.chooseCollectorLogFile()
                        }
                    }
                    Label {
                        visible: !SettingsController.fileChooserAvailable
                        text: qsTr("The desktop file chooser portal isn't available; enter a path above.")
                        color: win.palette.placeholderText
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }

                    Label { text: qsTr("Red-flag presets"); font.weight: Font.DemiBold }
                    Repeater {
                        model: win.collectorPresets
                        delegate: CheckBox {
                            required property var modelData
                            text: modelData.label
                            checked: win.collector.presets.indexOf(modelData.key) >= 0
                            onToggled: win.changeCollector(next => {
                                const i = next.presets.indexOf(modelData.key);
                                if (checked && i < 0)
                                    next.presets.push(modelData.key);
                                else if (!checked && i >= 0)
                                    next.presets.splice(i, 1);
                            })
                        }
                    }

                    Label { text: qsTr("Custom patterns"); font.weight: Font.DemiBold }
                    Repeater {
                        model: win.collector.patterns
                        delegate: ColumnLayout {
                            required property int index
                            required property var modelData
                            Layout.fillWidth: true
                            RowLayout {
                                Layout.fillWidth: true
                                TextField {
                                    text: modelData.name
                                    placeholderText: qsTr("Name")
                                    onEditingFinished: win.updatePattern(index, "name", text)
                                    Layout.preferredWidth: 110
                                }
                                TextField {
                                    text: modelData.pattern
                                    placeholderText: qsTr("Pattern")
                                    onEditingFinished: win.updatePattern(index, "pattern", text)
                                    Layout.fillWidth: true
                                }
                                CheckBox {
                                    text: qsTr("Regex")
                                    checked: modelData.kind === "regex"
                                    onToggled: win.updatePattern(index, "kind", checked ? "regex" : "text")
                                }
                                CheckBox {
                                    text: qsTr("Match case")
                                    checked: modelData.case_sensitive
                                    onToggled: win.updatePattern(index, "case_sensitive", checked)
                                }
                                ToolButton {
                                    text: "−"
                                    Accessible.name: qsTr("Remove pattern")
                                    onClicked: win.changeCollector(next => { next.patterns.splice(index, 1); })
                                }
                            }
                            Label {
                                visible: index < win.collector.patternErrors.length
                                    && win.collector.patternErrors[index] !== ""
                                text: index < win.collector.patternErrors.length
                                    ? win.collector.patternErrors[index] + qsTr(" This pattern is not used.") : ""
                                color: win.warning
                                wrapMode: Text.Wrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                    Label {
                        visible: win.collector.overLimit
                        text: qsTr("The enabled presets and valid patterns exceed the collector limit of 64. Turn off a preset or remove a pattern.")
                        color: win.warning
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                    Button {
                        text: qsTr("Add pattern")
                        enabled: win.collector.patterns.length < 64
                        onClicked: win.changeCollector(next => {
                            next.patterns.push({ name: "", kind: "text", pattern: "", case_sensitive: false });
                        })
                    }
                    CheckBox {
                        text: qsTr("Notify about red flags")
                        checked: win.collector.notify
                        onToggled: win.changeCollector(next => { next.notify = checked; })
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
