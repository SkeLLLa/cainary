pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// The details window: grouped scan and live sources on the left, the selected pane on the right.
ApplicationWindow {
    id: win

    // Parsed AppController.viewJson / staticJson, set by Main.qml.
    property var view: null
    property var st: null

    // An entry id, a named destination, or "" for the default.
    property string selection: ""
    property CollectorData collectorData: null
    readonly property bool scanExpanded: v === null ? true : !v.scanCollapsed
    readonly property bool liveExpanded: v === null ? true : !v.liveCollapsed
    property bool collectorPaneCreated: false
    property string rememberedCollectorTab: ""
    property int seenFlagCount: 0
    readonly property var v: view
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property bool hasChanges: v !== null && v.changes !== null && v.changes.rows.length > 0
    readonly property string effective: {
        if (selection === ":settings")
            return selection;
        if (selection === ":sources")
            return selection;
        if (selection === ":collector" || selection.startsWith(":collector:"))
            return ":collector";
        if (selection === ":changes" && hasChanges)
            return selection;
        if (v === null)
            return "";
        if (selection.length > 0 && v.entries[selection] !== undefined)
            return selection;
        return v.defaultSelection;
    }
    readonly property var entry: v !== null && v.entries[effective] !== undefined ? v.entries[effective] : null
    readonly property bool isCollector: effective === ":collector"
    readonly property bool isSettings: effective === ":settings"
    readonly property bool isScanDestination: !isCollector && !isSettings
    readonly property bool stale: isScanDestination && v !== null && v.failure !== null && v.hasReport
    readonly property bool failedFirst: v !== null && v.failure !== null && !v.hasReport
    readonly property int unseenFlagCount: collectorData
        ? Math.max(0, collectorData.flagCount - seenFlagCount) : 0
    readonly property string collectorDefaultTab: collectorData && collectorData.state === "listening"
        ? "feed" : "setup"

    // Closing hides the window and leaves the tray running, unless the setting is off or
    // there's no tray to come back from.
    onClosing: {
        if (!(SettingsController.closeToTray && AppController.trayAvailable))
            AppController.quit();
    }

    function showSelection(sel) {
        const page = collectorPageLoader.item;
        selection = sel;
        if (sel.startsWith(":collector:") || sel === ":collector") {
            collectorPaneCreated = true;
            if (page)
                openCollectorSelection(page, sel);
        }
        show();
        raise();
        requestActivate();
    }

    function openCollectorSelection(page, sel) {
        if (sel === ":collector")
            page.tab = rememberedCollectorTab !== "" ? rememberedCollectorTab : collectorDefaultTab;
        page.open(sel);
        if (page.current === "flags")
            seenFlagCount = collectorData ? collectorData.flagCount : 0;
    }

    function setSectionCollapsed(section, collapsed) {
        SettingsController.setSidebarCollapsed(section, collapsed);
    }

    // Ctrl+number focuses an interactive row that's currently in the sidebar model.
    function focusSidebarRow(number) {
        let shortcutRow = 0;
        for (let index = 0; index < sidebar.length; index++) {
            const row = sidebar[index];
            if (row.kind === "subheader" || (row.kind === "entry" && !row.row.installed))
                continue;
            shortcutRow++;
            if (shortcutRow !== number)
                continue;
            side.currentIndex = index;
            side.positionViewAtIndex(index, ListView.Contain);
            side.forceActiveFocus(Qt.ShortcutFocusReason);
            if (side.currentItem)
                side.currentItem.forceActiveFocus(Qt.ShortcutFocusReason);
            return;
        }
        if (++shortcutRow === number)
            settingsRow.forceActiveFocus(Qt.ShortcutFocusReason);
    }

    Component.onCompleted: {
        if (selection === ":collector" || selection.startsWith(":collector:"))
            collectorPaneCreated = true;
    }

    // Sidebar rows are rebuilt when either section's disclosure state changes.
    readonly property var sidebar: {
        const items = [];
        if (hasChanges)
            items.push({ kind: "changes", id: ":changes", count: v.changes.rows.length });
        items.push({ kind: "section", section: "scan", text: qsTr("Scan"), expanded: scanExpanded });
        if (scanExpanded && v !== null) {
            if (v.apps.length > 0 && v.others.length > 0)
                items.push({ kind: "subheader", text: qsTr("AI apps") });
            for (const app of v.apps) {
                if (app.installed)
                    items.push({ kind: "entry", id: app.id, row: app });
            }
            if (v.notInstalledCount > 0) {
                items.push({ kind: "notInstalled", count: v.notInstalledCount, expanded: v.notInstalledExpanded });
                if (v.notInstalledExpanded) {
                    for (const app of v.apps) {
                        if (!app.installed)
                            items.push({ kind: "entry", id: app.id, row: app });
                    }
                }
            }
            if (v.others.length > 0) {
                items.push({ kind: "subheader", text: qsTr("Other monitoring") });
                for (const other of v.others)
                    items.push({ kind: "entry", id: other.id, row: other });
            }
            items.push({ kind: "sources", id: ":sources" });
        }
        items.push({ kind: "section", section: "live", text: qsTr("Live"), expanded: liveExpanded });
        if (liveExpanded)
            items.push({ kind: "collector", id: ":collector" });
        return items;
    }

    objectName: "details"
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
    title: qsTr("cAInary")
    width: 900
    height: 600
    minimumWidth: 640
    minimumHeight: 440

    SystemColors { id: sys }

    Shortcut { sequences: ["Ctrl+R"]; onActivated: AppController.refresh() }
    Shortcut { sequences: ["Ctrl+,"]; onActivated: win.showSelection(":settings") }
    Shortcut { sequences: ["Ctrl+L"]; onActivated: win.showSelection(":collector:feed") }
    Shortcut { sequences: ["Ctrl+1"]; onActivated: win.focusSidebarRow(1) }
    Shortcut { sequences: ["Ctrl+2"]; onActivated: win.focusSidebarRow(2) }
    Shortcut { sequences: ["Ctrl+3"]; onActivated: win.focusSidebarRow(3) }
    Shortcut { sequences: ["Ctrl+4"]; onActivated: win.focusSidebarRow(4) }
    Shortcut { sequences: ["Ctrl+5"]; onActivated: win.focusSidebarRow(5) }
    Shortcut { sequences: ["Ctrl+6"]; onActivated: win.focusSidebarRow(6) }
    Shortcut { sequences: ["Ctrl+7"]; onActivated: win.focusSidebarRow(7) }
    Shortcut { sequences: ["Ctrl+8"]; onActivated: win.focusSidebarRow(8) }
    Shortcut { sequences: ["Ctrl+9"]; onActivated: win.focusSidebarRow(9) }
    Shortcut { sequences: ["Ctrl+W", "Esc"]; onActivated: win.close() }
    Shortcut { sequences: ["Ctrl+Q"]; onActivated: AppController.quit() }

    header: ToolBar {
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 4
            Item { Layout.fillWidth: true }
            ToolButton {
                id: statusPill
                visible: win.collectorData !== null && win.collectorData.enabled
                text: "● " + win.collectorData.stateText
                    + (win.collectorData.port.length > 0 ? " " + win.collectorData.port : "")
                    + (win.collectorData.flagCount > 0 ? " · ⚑ " + win.collectorData.flagCount : "")
                Accessible.name: text
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Open live telemetry")
                onClicked: win.showSelection(win.unseenFlagCount > 0 ? ":collector:flags" : ":collector:feed")
                background: Rectangle {
                    radius: height / 2
                    color: statusPill.hovered ? Qt.alpha(statusPill.palette.highlight, 0.12)
                                              : Qt.alpha(statusPill.palette.buttonText, 0.08)
                }
            }
            ToolButton {
                icon.name: "view-refresh"
                icon.source: "icons/refresh.svg"
                icon.color: palette.buttonText
                text: "⟳"
                display: AbstractButton.IconOnly
                visible: !AppController.busy
                Accessible.name: qsTr("Refresh")
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Refresh")
                onClicked: AppController.refresh()
            }
            BusyIndicator {
                visible: AppController.busy
                running: visible
                implicitWidth: 32
                implicitHeight: 32
            }
            ToolButton {
                text: "⋯"
                font.pixelSize: 18
                Accessible.name: qsTr("More")
                onClicked: moreMenu.popup(0, height)
                AppMenu {
                    id: moreMenu
                    canCopy: win.v !== null && win.v.canCopy
                    support: win.st ? win.st.support : null
                    showSettings: false
                }
            }
        }
    }

    SplitView {
        anchors.fill: parent

        Pane {
            SplitView.minimumWidth: 220
            SplitView.preferredWidth: 250
            padding: 0

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                ListView {
                    id: side
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    focus: true
                    model: win.sidebar
                    ScrollBar.vertical: ScrollBar {}

                    delegate: ItemDelegate {
                        id: item
                        required property var modelData
                        readonly property bool isSection: modelData.kind === "section"
                        readonly property bool isSubheader: modelData.kind === "subheader"
                        readonly property bool isNotInstalled: modelData.kind === "notInstalled"
                        readonly property string accessibleText: {
                            if (isSection)
                                return modelData.text + (modelData.expanded ? qsTr(", expanded") : qsTr(", collapsed"));
                            if (isNotInstalled)
                                return qsTr("%1 not installed").arg(modelData.count)
                                    + (modelData.expanded ? qsTr(", expanded") : qsTr(", collapsed"));
                            if (modelData.kind === "collector")
                                return qsTr("OTel collector, %1, %2 unseen red flags")
                                    .arg(win.collectorData ? win.collectorData.stateText : qsTr("Off"))
                                    .arg(win.unseenFlagCount);
                            if (modelData.kind === "changes")
                                return qsTr("Changes, %1").arg(modelData.count);
                            if (modelData.kind === "sources")
                                return qsTr("Checked locations");
                            if (modelData.kind === "entry")
                                return modelData.row.a11y || modelData.row.name;
                            return modelData.text || "";
                        }
                        width: ListView.view.width
                        enabled: !isSubheader && (modelData.kind !== "entry" || modelData.row.installed)
                        opacity: modelData.kind === "entry" && !modelData.row.installed ? 0.55 : 1
                        highlighted: modelData.id !== undefined && modelData.id === win.effective
                        topPadding: isSection || isSubheader ? 8 : 5
                        bottomPadding: isSection || isSubheader ? 2 : 5
                        implicitHeight: isSubheader ? 28 : 36
                        Accessible.name: accessibleText
                        Accessible.description: isSection || isNotInstalled
                            ? qsTr("Press to %1").arg(modelData.expanded ? qsTr("collapse") : qsTr("expand")) : ""
                        onClicked: {
                            if (isSection) {
                                win.setSectionCollapsed(modelData.section, modelData.expanded);
                            } else if (isNotInstalled) {
                                AppController.setNotInstalledExpanded(!modelData.expanded);
                            } else {
                                win.showSelection(modelData.id);
                            }
                        }
                        Keys.onLeftPressed: event => {
                            if (isSection) {
                                win.setSectionCollapsed(modelData.section, true);
                                event.accepted = true;
                            }
                        }
                        Keys.onRightPressed: event => {
                            if (isSection) {
                                win.setSectionCollapsed(modelData.section, false);
                                event.accepted = true;
                            }
                        }

                        background: Rectangle {
                            color: item.highlighted ? item.palette.highlight
                                   : item.hovered ? Qt.alpha(item.palette.highlight, 0.12) : "transparent"
                            radius: 4
                        }

                        contentItem: RowLayout {
                            spacing: 8
                            Label {
                                visible: item.isSection || item.isNotInstalled
                                text: item.modelData.expanded ? "▾" : "▸"
                                color: item.palette.placeholderText
                                Layout.preferredWidth: 14
                            }
                            Item {
                                visible: !item.isSection && !item.isSubheader && !item.isNotInstalled
                                implicitWidth: 20
                                implicitHeight: 20
                                EntryIcon {
                                    visible: item.modelData.kind === "entry"
                                    anchors.fill: parent
                                    size: 20
                                    iconKey: item.modelData.row ? item.modelData.row.iconKey : ""
                                    name: item.modelData.row ? item.modelData.row.name : ""
                                    installed: item.modelData.row ? item.modelData.row.installed : true
                                }
                                Label {
                                    visible: item.modelData.kind === "changes" || item.modelData.kind === "sources"
                                    anchors.centerIn: parent
                                    text: item.modelData.kind === "changes" ? "±" : "☰"
                                    color: item.highlighted ? item.palette.highlightedText : item.palette.placeholderText
                                }
                                StatusDot {
                                    visible: item.modelData.kind === "collector"
                                    anchors.centerIn: parent
                                    sourceState: win.collectorData ? win.collectorData.state : "off"
                                    size: 10
                                }
                            }
                            Label {
                                text: item.isSection ? item.modelData.text.toUpperCase()
                                      : item.isSubheader ? item.modelData.text
                                      : item.isNotInstalled ? qsTr("%1 not installed").arg(item.modelData.count)
                                      : item.modelData.kind === "changes" ? qsTr("Changes")
                                      : item.modelData.kind === "sources" ? qsTr("Checked locations")
                                      : item.modelData.kind === "collector" ? qsTr("OTel collector")
                                      : item.modelData.row.name
                                font.weight: item.isSection || item.isSubheader ? Font.DemiBold : Font.Normal
                                font.pointSize: item.isSection ? Application.font.pointSize * 0.82 : Application.font.pointSize
                                color: item.isSection || item.isSubheader || item.isNotInstalled
                                    ? item.palette.placeholderText
                                    : item.highlighted ? item.palette.highlightedText : item.palette.text
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            LevelIcon {
                                visible: item.modelData.kind === "entry"
                                level: item.modelData.row ? item.modelData.row.level : "unknown"
                                size: 16
                            }
                            CountBadge {
                                visible: item.modelData.kind === "changes"
                                count: item.modelData.count || 0
                                onHighlight: item.highlighted
                            }
                            CountBadge {
                                visible: item.modelData.kind === "collector" && win.unseenFlagCount > 0
                                count: win.unseenFlagCount
                                alert: true
                                onHighlight: item.highlighted
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 1
                    color: sys.mid
                }

                ItemDelegate {
                    id: settingsRow
                    Layout.fillWidth: true
                    Accessible.name: qsTr("Settings")
                    highlighted: win.isSettings
                    onClicked: win.showSelection(":settings")
                    background: Rectangle {
                        color: settingsRow.highlighted ? settingsRow.palette.highlight
                               : settingsRow.hovered ? Qt.alpha(settingsRow.palette.highlight, 0.12) : "transparent"
                        radius: 4
                    }
                    contentItem: RowLayout {
                        spacing: 8
                        Label { text: "⚙"; color: settingsRow.highlighted ? settingsRow.palette.highlightedText : settingsRow.palette.placeholderText }
                        Label {
                            text: qsTr("Settings")
                            color: settingsRow.highlighted ? settingsRow.palette.highlightedText : settingsRow.palette.text
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }

        Pane {
            SplitView.fillWidth: true
            SplitView.minimumWidth: 320
            padding: 0

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                FailureBanner {
                    visible: win.stale
                    compact: true
                    failure: win.v ? win.v.failure : null
                    Layout.fillWidth: true
                    Layout.margins: 8
                }

                // First scan or first failure
                ColumnLayout {
                    visible: win.isScanDestination
                        && (win.v === null || AppController.phase === "scanning" || win.failedFirst)
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.margins: 24
                    spacing: 12
                    Item { Layout.fillHeight: true }
                    BusyIndicator {
                        visible: win.v === null || AppController.phase === "scanning"
                        running: visible
                        Layout.alignment: Qt.AlignHCenter
                    }
                    Label {
                        visible: win.v === null || AppController.phase === "scanning"
                        text: qsTr("Scanning…")
                        Layout.alignment: Qt.AlignHCenter
                    }
                    FailureBanner {
                        visible: win.failedFirst
                        failure: win.v ? win.v.failure : null
                        Layout.fillWidth: true
                    }
                    Item { Layout.fillHeight: true }
                }

                ScrollView {
                    id: scroll
                    visible: !win.isCollector
                        && (win.isSettings || (win.isScanDestination && win.v !== null && win.v.hasReport))
                    contentWidth: availableWidth
                    clip: true
                    opacity: win.stale ? 0.5 : 1
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    ColumnLayout {
                        width: scroll.availableWidth
                        spacing: 10

                        // Changes pane
                        ColumnLayout {
                            visible: win.effective === ":changes"
                            spacing: 8
                            Layout.fillWidth: true
                            Layout.margins: 16
                            RowLayout {
                                Layout.fillWidth: true
                                Label {
                                    text: win.v && win.v.changes ? win.v.changes.title : ""
                                    font.pointSize: Application.font.pointSize * 1.4
                                    font.weight: Font.DemiBold
                                    Layout.fillWidth: true
                                }
                                // Same action as the popup's; the pane closes once the changes clear.
                                Button {
                                    text: qsTr("Mark as seen")
                                    onClicked: AppController.markAsSeen()
                                }
                            }
                            Repeater {
                                model: win.v && win.v.changes ? win.v.changes.rows : []
                                delegate: ChangeRow {
                                    required property var modelData
                                    change: modelData
                                    Layout.fillWidth: true
                                }
                            }
                        }

                        ColumnLayout {
                            visible: win.isSettings
                            spacing: 12
                            Layout.fillWidth: true
                            Layout.margins: 16
                            SettingsPage {
                                st: win.st
                                endpointHosts: win.v ? (win.v.endpointHosts || []) : []
                                Layout.fillWidth: true
                                onCollectorSetupRequested: win.showSelection(":collector:setup")
                            }
                        }

                        // Checked locations pane
                        ColumnLayout {
                            visible: win.effective === ":sources"
                            spacing: 6
                            Layout.fillWidth: true
                            Layout.margins: 16
                            Label {
                                text: qsTr("Checked locations")
                                font.pointSize: Application.font.pointSize * 1.4
                                font.weight: Font.DemiBold
                            }
                            Repeater {
                                model: win.v ? win.v.sources : []
                                delegate: ColumnLayout {
                                    id: group
                                    required property var modelData
                                    spacing: 4
                                    Layout.fillWidth: true
                                    Label {
                                        text: group.modelData.surface
                                        font.weight: Font.DemiBold
                                        color: win.palette.placeholderText
                                        Layout.topMargin: 8
                                    }
                                    Repeater {
                                        model: group.modelData.rows
                                        delegate: RowLayout {
                                            id: loc
                                            required property var modelData
                                            spacing: 8
                                            Layout.fillWidth: true
                                            Item {
                                                implicitWidth: 16
                                                implicitHeight: 16
                                                Layout.alignment: Qt.AlignTop
                                                LevelIcon {
                                                    anchors.fill: parent
                                                    size: 16
                                                    visible: loc.modelData.icon === "neutral"
                                                    level: "not-installed"
                                                }
                                                Label {
                                                    anchors.centerIn: parent
                                                    visible: loc.modelData.icon === "problem"
                                                             || loc.modelData.icon === "present"
                                                    text: loc.modelData.icon === "problem" ? "⚠" : "✓"
                                                    color: loc.modelData.icon === "problem"
                                                           ? Style.warningColor(win.dark)
                                                           : Style.levelColor("ok", win.dark, win.palette.windowText)
                                                }
                                            }
                                            Label {
                                                text: loc.modelData.path
                                                font.family: "monospace"
                                                font.pointSize: Application.font.pointSize * 0.9
                                                wrapMode: Text.WrapAnywhere
                                                Layout.fillWidth: true
                                            }
                                            Label {
                                                text: loc.modelData.status
                                                font.pointSize: Application.font.pointSize * 0.85
                                                color: win.palette.placeholderText
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Entry pane
                        ColumnLayout {
                            visible: win.isScanDestination && win.entry !== null
                                && win.effective !== ":changes" && win.effective !== ":sources"
                            spacing: 10
                            Layout.fillWidth: true
                            Layout.margins: 16

                            RowLayout {
                                spacing: 12
                                EntryIcon {
                                    iconKey: win.entry ? win.entry.iconKey : ""
                                    name: win.entry ? win.entry.name : ""
                                    installed: win.entry ? win.entry.installed : true
                                    size: 32
                                    Layout.alignment: Qt.AlignTop
                                }
                                ColumnLayout {
                                    spacing: 2
                                    Layout.fillWidth: true
                                    RowLayout {
                                        spacing: 10
                                        Label {
                                            text: win.entry ? win.entry.name : ""
                                            font.pointSize: Application.font.pointSize * 1.4
                                            font.weight: Font.DemiBold
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        LevelChip {
                                            level: win.entry ? win.entry.level : "unknown"
                                            label: win.entry ? win.entry.label : ""
                                            meaning: win.legendMeaning(win.entry ? win.entry.level : "")
                                        }
                                    }
                                    Label {
                                        text: win.entry ? win.entry.summary : ""
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }
                                    Label {
                                        visible: text.length > 0
                                        text: win.entry ? win.entry.reach : ""
                                        wrapMode: Text.Wrap
                                        font.pointSize: Application.font.pointSize * 0.85
                                        color: win.palette.placeholderText
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                            Label {
                                visible: text.length > 0
                                text: win.entry ? win.entry.emptyText : ""
                                color: win.palette.placeholderText
                                wrapMode: Text.Wrap
                                Layout.fillWidth: true
                            }
                            Repeater {
                                model: win.entry ? win.entry.active : []
                                delegate: FindingRow {
                                    required property var modelData
                                    finding: modelData
                                    entryId: win.entry ? win.entry.id : ""
                                    Layout.fillWidth: true
                                }
                            }
                            Label {
                                visible: win.entry !== null && win.entry.inactive.length > 0
                                text: qsTr("Present but not in effect")
                                color: win.palette.placeholderText
                                font.weight: Font.DemiBold
                                Layout.topMargin: 8
                            }
                            Repeater {
                                model: win.entry ? win.entry.inactive : []
                                delegate: FindingRow {
                                    required property var modelData
                                    finding: modelData
                                    entryId: win.entry ? win.entry.id : ""
                                    Layout.fillWidth: true
                                }
                            }
                            Repeater {
                                model: win.entry ? win.entry.notes : []
                                delegate: RowLayout {
                                    required property string modelData
                                    spacing: 8
                                    Layout.fillWidth: true
                                    Rectangle {
                                        implicitWidth: 16
                                        implicitHeight: 16
                                        radius: 8
                                        color: "transparent"
                                        border.color: win.palette.placeholderText
                                        Layout.alignment: Qt.AlignTop
                                        Label {
                                            anchors.centerIn: parent
                                            text: "i"
                                            font.pixelSize: 10
                                            font.weight: Font.DemiBold
                                            color: win.palette.placeholderText
                                        }
                                    }
                                    Label {
                                        text: modelData
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                            Label {
                                visible: text.length > 0
                                text: win.entry ? win.entry.environmentNote : ""
                                wrapMode: Text.Wrap
                                font.pointSize: Application.font.pointSize * 0.85
                                color: win.palette.placeholderText
                                Layout.fillWidth: true
                                Layout.topMargin: 8
                            }
                        }
                    }
                }

                Loader {
                    id: collectorPageLoader
                    visible: win.isCollector
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    active: win.collectorPaneCreated
                    sourceComponent: Component {
                        CollectorPage {
                            anchors.fill: parent
                            collector: win.collectorData
                            endpointHosts: win.v ? (win.v.endpointHosts || []) : []
                            onTabChanged: if (tab !== "") win.rememberedCollectorTab = tab
                            onFlagsSeen: win.seenFlagCount = win.collectorData ? win.collectorData.flagCount : 0
                        }
                    }
                    onLoaded: {
                        if (win.isCollector)
                            win.openCollectorSelection(item, win.selection);
                    }
                }
            }
        }
    }

    Connections {
        target: win.collectorData
        function onFlagCountChanged() {
            if (win.collectorData && win.seenFlagCount > win.collectorData.flagCount)
                win.seenFlagCount = win.collectorData.flagCount;
        }
    }

    function legendMeaning(level) {
        if (!st)
            return "";
        for (const l of st.legend)
            if (l.level === level)
                return l.meaning;
        return "";
    }
}
