import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// Live › OTel collector: a header with the on/off switch, then Feed, Red flags, Setup and Logs tabs.
ColumnLayout {
    id: root

    required property CollectorData collector
    // Telemetry endpoint hosts from the latest scan, offered in the takeover settings.
    property var endpointHosts: []
    // "feed" | "flags" | "setup" | "logs"; "" = the default (listening → feed, else setup).
    property string tab: ""
    // The tab shown: the chosen one, else the default.
    readonly property string current: tab !== "" ? tab : collector.state === "listening" ? "feed" : "setup"
    readonly property var tabs: ["feed", "flags", "setup", "logs"]
    readonly property int currentIndex: tabs.indexOf(current)
    // Takeover steps the user opened or closed on Setup, kept for the session.
    property var openSteps: ({})

    signal flagsSeen()

    // ":collector" → default tab, ":collector:feed|flags|setup|logs", ":collector:trust-preview" → setup,
    // ":collector:rules" → Red flags with the rules editor open, ":collector:<pattern>" → the Red flags tab scrolled to that pattern.
    function open(selection) {
        const sub = selection.startsWith(":collector:") ? selection.slice(":collector:".length) : "";
        flags.pattern = "";
        if (sub === "" || sub === "default")
            return;
        else if (root.tabs.includes(sub))
            tab = sub;
        else if (sub === "trust-preview")
            tab = "setup";
        else if (sub.startsWith("setup:")) {
            // ":collector:setup:point,undo" opens those takeover steps (the QML harness shows them).
            tab = "setup";
            const next = {};
            sub.slice("setup:".length).split(",").forEach(key => { next[key] = true; });
            root.openSteps = next;
        }
        else if (sub === "rules") {
            tab = "flags";
            flags.showRules();
        }
        else {
            flags.pattern = sub;
            tab = "flags";
        }
    }

    onCurrentChanged: if (current === "flags") flagsSeen()

    spacing: 0

    CollectorSettingsModel { id: settings }

    // Header
    RowLayout {
        Layout.fillWidth: true
        Layout.margins: 12
        Layout.bottomMargin: 8
        spacing: 8

        Label {
            text: qsTr("OTel debug collector")
            font.pointSize: Application.font.pointSize * 1.4
            font.weight: Font.DemiBold
        }
        StatusDot { sourceState: root.collector.state; Layout.leftMargin: 6 }
        Label {
            text: root.collector.stateText
            color: palette.placeholderText
        }
        Label {
            visible: root.collector.view.endpoint.length > 0
            text: root.collector.view.endpoint
            font.family: "monospace"
            color: palette.placeholderText
            elide: Text.ElideMiddle
            Layout.fillWidth: true
        }
        Item { visible: root.collector.view.endpoint.length === 0; Layout.fillWidth: true }
        Button {
            visible: root.collector.state === "failed" || root.collector.state === "stopped"
            text: qsTr("Retry")
            onClicked: CollectorController.retry()
        }
        Switch {
            checked: settings.value.enabled
            text: checked ? qsTr("On") : qsTr("Off")
            Accessible.name: qsTr("Collector enabled")
            onToggled: settings.change(next => { next.enabled = checked; })
        }
    }

    Label {
        visible: root.collector.statusLine.length > 0
        text: root.collector.statusLine
        textFormat: Text.PlainText
        color: root.collector.view.failure ? Style.warningColor(palette.window.hslLightness < 0.5) : palette.placeholderText
        elide: Text.ElideRight
        Layout.fillWidth: true
        Layout.leftMargin: 12
        Layout.rightMargin: 12
        Layout.bottomMargin: 8
    }

    TabBar {
        id: bar
        Layout.fillWidth: true
        currentIndex: root.currentIndex
        onCurrentIndexChanged: root.tab = root.tabs[currentIndex]

        TabButton { text: qsTr("Feed") }
        BadgeTabButton { label: qsTr("Red flags"); count: root.collector.flagCount; alert: true }
        TabButton { text: qsTr("Setup") }
        BadgeTabButton { label: qsTr("Logs"); count: root.collector.view.errors.length + (root.collector.view.stderrTail.length > 0 ? 1 : 0) }
    }

    StackLayout {
        currentIndex: root.currentIndex
        Layout.fillWidth: true
        Layout.fillHeight: true

        CollectorFeed {
            id: feed
            collector: root.collector
            onTurnOnRequested: settings.change(next => { next.enabled = true; })
            onSetupRequested: root.tab = "setup"
        }
        CollectorFlags {
            id: flags
            collector: root.collector
            model: settings
            onShowInFeed: pattern => {
                feed.pattern = pattern;
                root.tab = "feed";
            }
        }
        CollectorSetup {
            collector: root.collector
            model: settings
            endpointHosts: root.endpointHosts
            openSteps: root.openSteps
            onStepToggled: (key, open) => {
                const next = Object.assign({}, root.openSteps);
                next[key] = open;
                root.openSteps = next;
            }
            onShowLogsRequested: root.tab = "logs"
        }
        CollectorLogs {
            collector: root.collector
        }
    }
}
