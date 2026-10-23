pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// The details window: apps/others/checked locations on the left, the selection on the right.
ApplicationWindow {
    id: win

    // Parsed AppController.viewJson / staticJson, set by Main.qml.
    property var view: null
    property var st: null

    // An entry id, ":changes", ":sources" or "" for the default.
    property string selection: ""
    readonly property var v: view
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property bool hasChanges: v !== null && v.changes !== null && v.changes.rows.length > 0
    readonly property string effective: {
        if (v === null)
            return "";
        if (selection === ":changes" && hasChanges)
            return selection;
        if (selection === ":sources")
            return selection;
        if (selection.length > 0 && v.entries[selection] !== undefined)
            return selection;
        return v.defaultSelection;
    }
    readonly property var entry: v !== null && v.entries[effective] !== undefined ? v.entries[effective] : null
    readonly property bool stale: v !== null && v.failure !== null && v.hasReport
    readonly property bool failedFirst: v !== null && v.failure !== null && !v.hasReport

    // Closing hides the window and leaves the tray running, unless the setting is off or
    // there's no tray to come back from.
    onClosing: {
        if (!(SettingsController.closeToTray && AppController.trayAvailable))
            AppController.quit();
    }

    function showSelection(sel) {
        selection = sel;
        show();
        raise();
        requestActivate();
    }

    // Sidebar rows built from the view: {kind: "changes"|"header"|"entry"|"sources", ...}.
    readonly property var sidebar: {
        const items = [];
        if (v === null)
            return items;
        if (hasChanges)
            items.push({ kind: "changes", id: ":changes" });
        items.push({ kind: "header", text: qsTr("AI apps") });
        for (const a of v.apps)
            items.push({ kind: "entry", id: a.id, row: a });
        if (v.others.length > 0) {
            items.push({ kind: "header", text: qsTr("Other monitoring") });
            for (const o of v.others)
                items.push({ kind: "entry", id: o.id, row: o });
        }
        items.push({ kind: "sources", id: ":sources" });
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
    width: 780
    height: 560
    minimumWidth: 640
    minimumHeight: 440

    SystemColors { id: sys }

    Shortcut { sequences: ["Ctrl+R"]; onActivated: AppController.refresh() }
    Shortcut { sequences: ["Ctrl+,"]; onActivated: AppController.showSettings() }
    Shortcut { sequences: ["Ctrl+W", "Esc"]; onActivated: win.close() }
    Shortcut { sequences: ["Ctrl+Q"]; onActivated: AppController.quit() }

    header: ToolBar {
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 4
            Item { Layout.fillWidth: true }
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
                }
            }
        }
    }

    SplitView {
        anchors.fill: parent

        Pane {
            SplitView.minimumWidth: 220
            SplitView.preferredWidth: 270
            padding: 0

            ListView {
                id: side
                anchors.fill: parent
                clip: true
                model: win.sidebar
                ScrollBar.vertical: ScrollBar {}

                delegate: ItemDelegate {
                    id: item
                    required property var modelData
                    readonly property bool isHeader: modelData.kind === "header"
                    width: ListView.view.width
                    enabled: !isHeader && (modelData.kind !== "entry" || modelData.row.installed)
                    highlighted: !isHeader && modelData.id === win.effective
                    topPadding: isHeader ? 12 : 6
                    bottomPadding: isHeader ? 2 : 6
                    onClicked: win.selection = modelData.id

                    background: Rectangle {
                            color: parent.highlighted ? parent.palette.highlight
                                   : parent.hovered ? Qt.alpha(parent.palette.highlight, 0.12) : "transparent"
                            radius: 4
                        }

                    contentItem: RowLayout {
                        spacing: 8
                        Item {
                            visible: !item.isHeader
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
                        }
                        Label {
                            text: item.isHeader ? item.modelData.text
                                  : item.modelData.kind === "changes" ? qsTr("Changes")
                                  : item.modelData.kind === "sources" ? qsTr("Checked locations")
                                  : item.modelData.row.name
                            font.weight: item.isHeader ? Font.DemiBold : Font.Normal
                            color: item.isHeader ? item.palette.placeholderText
                                   : item.highlighted ? item.palette.highlightedText : item.palette.text
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                        LevelIcon {
                            visible: item.modelData.kind === "entry"
                            level: item.modelData.row ? item.modelData.row.level : "unknown"
                            size: 16
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
                    visible: win.v === null || AppController.phase === "scanning" || win.failedFirst
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
                    visible: win.v !== null && win.v.hasReport
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
                            visible: win.entry !== null && win.effective !== ":changes" && win.effective !== ":sources"
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
            }
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
