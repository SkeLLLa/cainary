pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// Live › OTel collector › Feed: every batch and red flag, newest first, with an inspector
// for the selected row below the list (like a browser's Network panel).
ColumnLayout {
    id: feed

    required property CollectorData collector
    // Set from the Red flags tab's "Show in feed".
    property string pattern: ""
    signal turnOnRequested()
    signal setupRequested()

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color warn: Style.warningColor(dark)
    readonly property color flagColor: Style.levelColor("high", dark, palette.windowText)

    // Filters.
    property bool showLogs: true
    property bool showMetrics: true
    property bool showTraces: true
    property bool flagsOnly: false
    property bool uncatalogedOnly: false
    // Pause remembers the keys present when it was pressed, so new rows can be counted across updates.
    property bool paused: false
    property var pausedKeys: []

    readonly property var all: collector.view.rows
    readonly property var shown: all.filter(row => feed.isShown(row))
    readonly property int held: paused ? all.filter(row => pausedKeys.indexOf(row.key) < 0).length : 0
    readonly property bool filtering: search.text.trim().length > 0 || !showLogs || !showMetrics || !showTraces
        || flagsOnly || uncatalogedOnly || pattern.length > 0

    property string selectedKey: ""
    property bool modelReady: false
    readonly property var selected: {
        for (const r of shown)
            if (r.key === selectedKey)
                return r;
        return shown.length > 0 ? shown[0] : null;
    }

    // Keep this predicate behavior identical to tray_model::collector::matches. Rust prepares
    // the signal, flag count, catalog count and lowercase haystack; QML only reads those fields.
    function matches(row) {
        const signals = [];
        if (showLogs) signals.push("logs");
        if (showMetrics) signals.push("metrics");
        if (showTraces) signals.push("traces");
        if (signals.indexOf(row.signal) < 0)
            return false;
        if (flagsOnly && row.flags.length === 0)
            return false;
        if (pattern.length > 0 && !row.flags.some(flag => flag.pattern === pattern))
            return false;
        if (uncatalogedOnly && row.notInCatalog === 0)
            return false;
        const text = search.text.trim().toLowerCase();
        return text.length === 0 || row.haystack.indexOf(text) >= 0;
    }

    function isShown(row) {
        return (!paused || pausedKeys.indexOf(row.key) >= 0) && matches(row);
    }

    function batchFor(row) {
        if (!row || row.batchId === null)
            return null;
        for (const batch of collector.view.batches)
            if (batch.id === row.batchId)
                return batch;
        return null;
    }

    function modelIndex(key) {
        for (let i = 0; i < rowModel.count; ++i)
            if (rowModel.get(i).key === key)
                return i;
        return -1;
    }

    function syncRows() {
        if (!modelReady)
            return;

        const wasAtTop = list.atYBeginning;
        let anchorKey = "";
        let anchorOffset = 0;
        if (!wasAtTop) {
            for (let i = 0; i < rowModel.count; ++i) {
                const item = list.itemAtIndex(i);
                if (item && item.y + item.height > list.contentY) {
                    anchorKey = item.row.key;
                    anchorOffset = item.y - list.contentY;
                    break;
                }
            }
        }

        const wanted = shown;
        const wantedKeys = wanted.map(row => row.key);
        for (let i = rowModel.count - 1; i >= 0; --i)
            if (wantedKeys.indexOf(rowModel.get(i).key) < 0)
                rowModel.remove(i);

        for (let target = 0; target < wanted.length; ++target) {
            const row = wanted[target];
            let current = modelIndex(row.key);
            const signature = JSON.stringify(row);
            if (current < 0) {
                rowModel.insert(target, { key: row.key, row: row, signature: signature });
                continue;
            }
            if (current !== target) {
                rowModel.move(current, target, 1);
                current = target;
            }
            if (rowModel.get(current).signature !== signature)
                rowModel.set(current, { key: row.key, row: row, signature: signature });
        }

        if (!wasAtTop && anchorKey.length > 0) {
            Qt.callLater(function() {
                const index = modelIndex(anchorKey);
                if (index < 0)
                    return;
                list.positionViewAtIndex(index, ListView.Beginning);
                Qt.callLater(function() {
                    const item = list.itemAtIndex(index);
                    if (item)
                        list.contentY = Math.max(0, item.y - anchorOffset);
                });
            });
        }
    }

    onShownChanged: syncRows()
    Component.onCompleted: {
        modelReady = true;
        syncRows();
    }

    spacing: 0

    // Column widths shared by the header and the rows; Source takes the rest.
    QtObject {
        id: cols
        readonly property int time: 70
        readonly property int signal: 64
        readonly property int records: 62
        readonly property int size: 60
        readonly property int flags: 150
    }

    // Filter bar, once there is something to filter
    RowLayout {
        visible: feed.all.length > 0
        Layout.fillWidth: true
        Layout.margins: 8
        spacing: 4

        TextField {
            id: search
            placeholderText: qsTr("Search events, attributes, sources…")
            Layout.fillWidth: true
            Layout.minimumWidth: 90
        }
        component Toggle: Button {
            checkable: true
            flat: !checked
            leftPadding: 6
            rightPadding: 6
            font.pointSize: Application.font.pointSize * 0.9
        }
        Toggle { text: qsTr("logs"); checked: feed.showLogs; onToggled: feed.showLogs = checked }
        Toggle { text: qsTr("metrics"); checked: feed.showMetrics; onToggled: feed.showMetrics = checked }
        Toggle { text: qsTr("traces"); checked: feed.showTraces; onToggled: feed.showTraces = checked }
        ToolSeparator {}
        Toggle {
            text: "⚑ " + qsTr("Flagged")
            checked: feed.flagsOnly
            onToggled: feed.flagsOnly = checked
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Only batches with a red flag")
        }
        Toggle {
            text: "◇ " + qsTr("Uncataloged")
            checked: feed.uncatalogedOnly
            onToggled: feed.uncatalogedOnly = checked
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Only batches with something not in the catalog")
        }
        ToolSeparator {}
        ToolButton {
            text: feed.paused ? "▶" : "⏸"
            Accessible.name: feed.paused ? qsTr("Resume") : qsTr("Pause")
            ToolTip.visible: hovered
            ToolTip.text: feed.paused ? qsTr("Resume") : qsTr("Pause: hold new rows back")
            onClicked: {
                    if (!feed.paused)
                        feed.pausedKeys = feed.all.map(row => row.key);
                    else
                        feed.pausedKeys = [];
                    feed.paused = !feed.paused;
            }
        }
        ToolButton {
            text: qsTr("Clear")
            font.pointSize: Application.font.pointSize * 0.9
            enabled: feed.all.length > 0
            Accessible.name: qsTr("Clear")
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Clear the feed")
            onClicked: CollectorController.clear()
        }
    }

    // Active pattern filter, and rows held back by Pause.
    RowLayout {
        visible: feed.pattern.length > 0 || feed.held > 0
        Layout.fillWidth: true
        Layout.leftMargin: 8
        Layout.rightMargin: 8
        Layout.bottomMargin: 6
        spacing: 6
        Button {
            visible: feed.pattern.length > 0
            text: "⚑ " + feed.pattern + "  ✕"
            flat: true
            font.pointSize: Application.font.pointSize * 0.9
            Accessible.name: qsTr("Stop filtering by %1").arg(feed.pattern)
            onClicked: feed.pattern = ""
        }
        Item { Layout.fillWidth: true }
        Button {
            visible: feed.held > 0
            text: (feed.held === 1 ? qsTr("↑ 1 new — Resume") : qsTr("↑ %1 new — Resume").arg(feed.held))
            highlighted: true
            onClicked: {
                feed.paused = false;
                feed.pausedKeys = [];
            }
        }
    }

    // Empty states
    ColumnLayout {
        visible: feed.all.length === 0
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.margins: 24
        spacing: 10
        Item { Layout.fillHeight: true }
        Label {
            text: !feed.collector.enabled ? qsTr("The collector is off.")
                : feed.collector.state === "listening" ? qsTr("Waiting for the first batch…")
                : feed.collector.stateText
            font.pointSize: Application.font.pointSize * 1.2
            font.weight: Font.DemiBold
            Layout.alignment: Qt.AlignHCenter
        }
        Label {
            text: !feed.collector.enabled
                ? qsTr("Turn it on to receive OpenTelemetry on this device only and see what each AI tool's export contains.")
                : qsTr("Start Claude Code or Codex with these settings:")
            color: palette.placeholderText
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: 440
            Layout.alignment: Qt.AlignHCenter
        }
        Button {
            visible: !feed.collector.enabled
            text: qsTr("Turn on the collector")
            highlighted: true
            Layout.alignment: Qt.AlignHCenter
            onClicked: feed.turnOnRequested()
        }
        TextArea {
            visible: feed.collector.enabled && feed.collector.view.claudeCode.length > 0
            text: feed.collector.view.claudeCode.join("\n")
            readOnly: true
            selectByMouse: true
            font.family: "monospace"
            Layout.maximumWidth: 520
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignHCenter
        }
        RowLayout {
            visible: feed.collector.enabled
            Layout.alignment: Qt.AlignHCenter
            Button {
                visible: feed.collector.view.claudeCode.length > 0
                text: qsTr("Copy")
                onClicked: CollectorController.copyText(feed.collector.view.claudeCode.join("\n"))
            }
            Button {
                text: qsTr("More setup…")
                flat: true
                onClicked: feed.setupRequested()
            }
        }
        Item { Layout.fillHeight: true }
    }

    SplitView {
        visible: feed.all.length > 0
        orientation: Qt.Vertical
        Layout.fillWidth: true
        Layout.fillHeight: true

        // The list
        ColumnLayout {
            SplitView.fillHeight: true
            SplitView.minimumHeight: 110
            spacing: 0

            component Cell: Label {
                elide: Text.ElideRight
                font.pointSize: Application.font.pointSize * 0.92
            }
            Rectangle {
                id: header
                Layout.fillWidth: true
                implicitHeight: headerRow.implicitHeight + 6
                color: Qt.alpha(palette.windowText, 0.05)
                RowLayout {
                    id: headerRow
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12
                    spacing: 8
                    component Head: Cell {
                        font.weight: Font.DemiBold
                        font.pointSize: Application.font.pointSize * 0.8
                        font.capitalization: Font.AllUppercase
                        color: palette.placeholderText
                    }
                    Head { text: qsTr("Time"); Layout.preferredWidth: cols.time }
                    Head { text: qsTr("Signal"); Layout.preferredWidth: cols.signal }
                    Head { text: qsTr("Source"); Layout.fillWidth: true }
                    Head { text: qsTr("Records"); horizontalAlignment: Text.AlignRight; Layout.preferredWidth: cols.records }
                    Head { text: qsTr("Size"); horizontalAlignment: Text.AlignRight; Layout.preferredWidth: cols.size }
                    Head { text: qsTr("Flags"); Layout.preferredWidth: cols.flags }
                }
            }

            ListModel {
                id: rowModel
                dynamicRoles: true
            }

            ListView {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: rowModel
                ScrollBar.vertical: ScrollBar {}
                keyNavigationEnabled: true

                Label {
                    anchors.centerIn: parent
                    visible: rowModel.count === 0
                    text: feed.filtering ? qsTr("Nothing matches the filters.") : qsTr("Cleared. New rows show up here.")
                    color: palette.placeholderText
                }

                delegate: ItemDelegate {
                    id: rowItem
                    required property var row
                    required property int index
                    readonly property bool isAlert: row.isAlert
                    readonly property var b: feed.batchFor(row)
                    readonly property int uncataloged: row.notInCatalog
                    readonly property var flags: row.flags
                    width: ListView.view.width
                    highlighted: feed.selected !== null && feed.selected.key === row.key
                    topPadding: 4
                    bottomPadding: 4
                    leftPadding: 12
                    rightPadding: 12
                    onClicked: feed.selectedKey = row.key

                    background: Rectangle {
                        color: rowItem.highlighted ? rowItem.palette.highlight
                             : rowItem.hovered ? Qt.alpha(rowItem.palette.highlight, 0.12)
                             : rowItem.index % 2 ? Qt.alpha(rowItem.palette.windowText, 0.03) : "transparent"
                    }

                    readonly property color fg: highlighted ? palette.highlightedText : palette.text
                    readonly property color dim: highlighted ? palette.highlightedText : palette.placeholderText

                    contentItem: RowLayout {
                        spacing: 8
                        Cell {
                            text: rowItem.row.time
                            font.family: "monospace"
                            color: rowItem.dim
                            Layout.preferredWidth: cols.time
                        }
                        Cell {
                            text: rowItem.row.signal
                            color: rowItem.fg
                            Layout.preferredWidth: cols.signal
                        }
                        Cell {
                            text: rowItem.isAlert
                                ? qsTr("Red flag outside a listed batch: %1").arg(rowItem.row.source)
                                : rowItem.row.source
                            color: rowItem.fg
                            Layout.fillWidth: true
                            Layout.preferredWidth: 0   // the rest of the row, whatever its text
                        }
                        Cell {
                            text: rowItem.isAlert ? "" : rowItem.row.records
                            color: rowItem.fg
                            horizontalAlignment: Text.AlignRight
                            Layout.preferredWidth: cols.records
                        }
                        Cell {
                            text: rowItem.row.size
                            color: rowItem.dim
                            horizontalAlignment: Text.AlignRight
                            Layout.preferredWidth: cols.size
                        }
                        RowLayout {
                            spacing: 6
                            Layout.preferredWidth: cols.flags
                            Layout.maximumWidth: cols.flags
                            Cell {
                                visible: rowItem.flags.length > 0
                                text: rowItem.flags.length === 0 ? "" : "⚑ " + rowItem.flags[0].pattern
                                      + (rowItem.flags.length > 1 ? " +" + (rowItem.flags.length - 1) : "")
                                color: rowItem.highlighted ? rowItem.palette.highlightedText : feed.flagColor
                                font.weight: Font.DemiBold
                                Layout.fillWidth: true
                                Layout.maximumWidth: cols.flags - 40
                            }
                            Cell {
                                visible: rowItem.uncataloged > 0
                                text: "◇ " + rowItem.uncataloged
                                color: rowItem.highlighted ? rowItem.palette.highlightedText : feed.warn
                                ToolTip.visible: rowHover.hovered && visible
                                ToolTip.text: (rowItem.uncataloged === 1 ? qsTr("1 not in catalog") : qsTr("%1 not in catalog").arg(rowItem.uncataloged))
                                HoverHandler { id: rowHover }
                            }
                            Item { Layout.fillWidth: true }
                        }
                    }
                }
            }
        }

        // The inspector
        ScrollView {
            id: inspector
            SplitView.preferredHeight: 230
            SplitView.minimumHeight: 90
            contentWidth: availableWidth
            clip: true
            background: Rectangle { color: palette.base }

            ColumnLayout {
                width: inspector.availableWidth
                spacing: 6
                readonly property var row: feed.selected
                readonly property var b: feed.batchFor(row)

                Item { Layout.preferredHeight: 4 }

                Label {
                    visible: parent.row === null
                    text: qsTr("Select a row to see what it carried.")
                    color: palette.placeholderText
                    Layout.margins: 12
                }

                // Title line
                Label {
                    visible: parent.b !== null
                    text: parent.b
                        ? [parent.row.signal, parent.row.source, (parent.b.records === 1 ? qsTr("1 record") : qsTr("%1 records").arg(parent.b.records)), parent.b.endpointPath, parent.row.time].filter(x => x).join(" · ")
                        : ""
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                }

                // Red flags on this row
                Repeater {
                    model: parent.row ? parent.row.flagDetails : []
                    delegate: Rectangle {
                        id: flagBox
                        required property var modelData
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        Layout.rightMargin: 12
                        implicitHeight: flagText.implicitHeight + 10
                        radius: 4
                        color: Qt.alpha(feed.flagColor, 0.10)
                        border.color: Qt.alpha(feed.flagColor, 0.35)
                        Label {
                            id: flagText
                            anchors.fill: parent
                            anchors.margins: 5
                            anchors.leftMargin: 8
                            text: "⚑ <b>" + flagBox.modelData.pattern + "</b>" + (flagBox.modelData.count > 1 ? " ×" + flagBox.modelData.count : "")
                                  + " · " + [flagBox.modelData.event, flagBox.modelData.attribute].filter(x => x).join(" · ")
                                  + (flagBox.modelData.matched ? " (" + flagBox.modelData.matched + ")" : "")
                            textFormat: Text.StyledText
                            wrapMode: Text.Wrap
                        }
                    }
                }

                Label {
                    visible: parent.b !== null && parent.b.identity.length > 0
                    text: parent.b ? qsTr("Identity (on every record): ") + parent.b.identity.join(" · ") : ""
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                }
                Label {
                    visible: parent.b !== null && parent.b.resource.length > 0
                    text: parent.b ? qsTr("Resource: ") + parent.b.resource.join(" · ") : ""
                    color: palette.placeholderText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                }

                Repeater {
                    model: parent.b ? parent.b.summary : []
                    delegate: ColumnLayout {
                        id: rec
                        required property var modelData
                        spacing: 2
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        Layout.rightMargin: 12
                        Layout.topMargin: 4
                        RowLayout {
                            Layout.fillWidth: true
                            Label {
                                text: rec.modelData.name + " ×" + rec.modelData.count
                                font.family: "monospace"
                                font.weight: Font.DemiBold
                            }
                            Label {
                                visible: rec.modelData.what.length > 0
                                text: rec.modelData.what
                                color: palette.placeholderText
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            Item { visible: rec.modelData.what.length === 0; Layout.fillWidth: true }
                            Label {
                                visible: !rec.modelData.known
                                text: "◇ " + qsTr("not in catalog")
                                color: feed.warn
                            }
                        }
                        Flow {
                            Layout.fillWidth: true
                            Layout.leftMargin: 12
                            spacing: 6
                            Repeater {
                                model: rec.modelData.attrs
                                delegate: Rectangle {
                                    id: chip
                                    required property var modelData
                                    readonly property bool content: modelData.group === "content"
                                    readonly property color tint: content || !modelData.known ? feed.warn : palette.windowText
                                    implicitWidth: chipText.implicitWidth + 12
                                    implicitHeight: chipText.implicitHeight + 4
                                    radius: 3
                                    color: Qt.alpha(tint, content || !modelData.known ? 0.12 : 0.06)
                                    Label {
                                        id: chipText
                                        anchors.centerIn: parent
                                        text: "<span style='opacity:0.6'>" + (chip.modelData.group || qsTr("unknown")) + "</span> "
                                              + chip.modelData.key
                                              + (chip.modelData.flag ? " <i>(" + chip.modelData.flag + ")</i>" : "")
                                              + (chip.modelData.known ? "" : " ◇")
                                        textFormat: Text.StyledText
                                        font.family: "monospace"
                                        font.pointSize: Application.font.pointSize * 0.85
                                        color: chip.content || !chip.modelData.known ? feed.warn : palette.text
                                    }
                                }
                            }
                        }
                    }
                }

                RowLayout {
                    visible: parent.b !== null
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    Layout.topMargin: 4
                    Button {
                        visible: parent.parent.b !== null && !parent.parent.b.resourcesOmitted
                        text: raw.visible ? qsTr("Hide raw records") : qsTr("Raw records")
                        flat: true
                        onClicked: raw.visible = !raw.visible
                    }
                    Label {
                        visible: parent.parent.b !== null && parent.parent.b.resourcesOmitted
                        text: qsTr("Raw records left out: the batch was too large.")
                        color: palette.placeholderText
                    }
                }
                TextArea {
                    id: raw
                    visible: false
                    text: visible && parent.b ? parent.b.rawRecords : ""
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                }
                Item { Layout.preferredHeight: 8 }
            }
        }
    }
}
