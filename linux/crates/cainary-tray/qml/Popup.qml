pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// The tray popup: 360 px wide, as tall as its content up to 640 px (and the screen). Closes on
// Esc, and on focus loss unless it is `decorated` (an ordinary window, for compositors that
// can't place or keep a frameless one: GNOME on Wayland).
Window {
    id: win

    // Parsed AppController.viewJson / staticJson, set by Main.qml.
    property var view: null
    property var st: null

    readonly property var v: view
    readonly property bool failedOnly: v !== null && AppController.phase === "failed"
    readonly property bool decorated: AppController.placement === "decorated"
    readonly property bool dark: frame.palette.window.hslLightness < 0.5

    // When a focus-loss hide last happened. Clicking the tray icon of an open popup first takes
    // its focus, so the click that follows must not reopen it.
    property double hiddenAt: 0

    // Moves the popup under the tray icon at (x, y), clamped to the screen's available area
    // (X11: there is no compositor to place it). (0, 0) means the primary screen.
    function placeNear(x, y) {
        const area = AppController.availableArea(x, y);
        const minX = area.x + 8;
        const minY = area.y + 8;
        const maxX = Math.max(minX, area.x + area.width - 1 - win.width - 7);
        const maxY = Math.max(minY, area.y + area.height - 1 - win.height - 7);
        if (x === 0 && y === 0) {
            // Some tray hosts report no position: top right, where trays usually are.
            win.x = maxX;
            win.y = minY;
            return;
        }
        win.x = Math.min(Math.max(x - Math.floor(win.width / 2), minX), maxX);
        win.y = Math.min(Math.max(y, minY), maxY);
    }

    // For the snapshot harness and the "N not installed" chevron.
    function setNotInstalledExpanded(expanded) {
        AppController.setNotInstalledExpanded(expanded);
    }
    function openSelection(sel) {
        win.hide();
        AppController.openDetails(sel);
    }

    objectName: "popup"
    title: "cAInary"
    width: 360
    height: Math.min(640, Math.max(120, (screen ? screen.desktopAvailableHeight : 720) - 48), frame.implicitHeight)
    minimumWidth: width
    maximumWidth: width
    flags: decorated ? Qt.Window : (Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
    color: decorated ? sys.window : "transparent"

    // Focus loss only closes a popup that has been active, so a compositor that hands focus
    // over late (layer-shell on-demand) doesn't dismiss it on arrival.
    property bool wasActive: false
    onActiveChanged: {
        if (active)
            wasActive = true;
        else if (wasActive && visible && !decorated && !moreMenu.visible) {
            hiddenAt = Date.now();
            hide();
        }
    }
    onVisibleChanged: if (!visible) wasActive = false

    Shortcut {
        sequence: "Esc"
        onActivated: win.hide()
    }

    SystemColors { id: sys }

    Pane {
        id: frame
        anchors.fill: parent
        padding: win.decorated ? 0 : 1
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
        background: Rectangle {
            color: frame.palette.window
            border.color: win.decorated ? "transparent" : frame.palette.mid
            radius: win.decorated ? 0 : 6
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            // Header
            RowLayout {
                visible: win.v !== null && !win.failedOnly && AppController.phase !== "scanning"
                Layout.fillWidth: true
                Layout.margins: 12
                spacing: 10

                LevelIcon {
                    level: win.v ? win.v.header.level : "unknown"
                    size: 32
                    Layout.alignment: Qt.AlignTop
                }
                ColumnLayout {
                    spacing: 1
                    Layout.fillWidth: true
                    Label {
                        text: win.v ? win.v.header.label : ""
                        font.weight: Font.DemiBold
                        font.pointSize: Application.font.pointSize * 1.1
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                    Label {
                        text: win.v ? win.v.header.summary : ""
                        wrapMode: Text.Wrap
                        maximumLineCount: 2
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                    Flow {
                        Layout.fillWidth: true
                        spacing: 8
                        Repeater {
                            model: win.v ? win.v.header.scanLine : []
                            delegate: Label {
                                required property var modelData
                                text: modelData.text
                                font.pointSize: Application.font.pointSize * 0.85
                                color: modelData.tone === "warning" ? Style.warningColor(win.dark)
                                                                    : frame.palette.placeholderText
                            }
                        }
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
                    Layout.alignment: Qt.AlignTop
                }
                BusyIndicator {
                    visible: AppController.busy
                    running: visible
                    implicitWidth: 32
                    implicitHeight: 32
                    Layout.alignment: Qt.AlignTop
                }
            }

            // First scan
            RowLayout {
                visible: win.v === null || AppController.phase === "scanning"
                Layout.fillWidth: true
                Layout.margins: 16
                spacing: 12
                BusyIndicator { running: parent.visible }
                Label {
                    text: qsTr("Scanning…")
                    Layout.fillWidth: true
                }
            }

            FailureBanner {
                visible: win.failedOnly
                failure: win.v ? win.v.failure : null
                Layout.fillWidth: true
                Layout.margins: 12
            }

            MenuSeparator {
                visible: win.v !== null && !win.failedOnly && AppController.phase !== "scanning"
                Layout.fillWidth: true
                padding: 0
            }

            ScrollView {
                id: scroll
                visible: win.v !== null && AppController.phase !== "scanning" && win.v.hasReport
                contentWidth: availableWidth
                clip: true
                opacity: win.failedOnly ? 0.5 : 1
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredHeight: body.implicitHeight

                ColumnLayout {
                    id: body
                    width: scroll.availableWidth
                    spacing: 0

                    // Changes
                    ColumnLayout {
                        visible: win.v !== null && !win.failedOnly && win.v.changes !== null
                                 && win.v.changes.rows.length > 0
                        spacing: 6
                        Layout.fillWidth: true
                        Layout.margins: 12
                        Label {
                            text: win.v && win.v.changes ? win.v.changes.title : ""
                            font.weight: Font.DemiBold
                        }
                        Repeater {
                            model: win.v && win.v.changes ? win.v.changes.rows.slice(0, 5) : []
                            delegate: ChangeRow {
                                required property var modelData
                                change: modelData
                                Layout.fillWidth: true
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Button {
                                visible: win.v && win.v.changes && win.v.changes.rows.length > 5
                                flat: true
                                text: qsTr("+%1 more").arg(win.v && win.v.changes ? win.v.changes.rows.length - 5 : 0)
                                onClicked: win.openSelection(":changes")
                            }
                            Item { Layout.fillWidth: true }
                            Button {
                                text: qsTr("Mark as seen")
                                onClicked: AppController.markAsSeen()
                            }
                        }
                    }
                    MenuSeparator {
                        visible: win.v !== null && !win.failedOnly && win.v.changes !== null
                                 && win.v.changes.rows.length > 0
                        Layout.fillWidth: true
                        padding: 0
                    }

                    // AI apps
                    SectionHeader { text: qsTr("AI apps"); visible: win.v !== null && win.v.apps.length > 0 }
                    Repeater {
                        model: win.v ? win.v.apps.filter(a => a.installed) : []
                        delegate: AppRow {
                            required property var modelData
                            row: modelData
                            Layout.fillWidth: true
                            onClicked: win.openSelection(modelData.id)
                        }
                    }
                    AbstractButton {
                        id: notInstalled
                        visible: win.v !== null && win.v.notInstalledCount > 0
                        Layout.fillWidth: true
                        implicitHeight: 32
                        onClicked: win.setNotInstalledExpanded(!win.v.notInstalledExpanded)
                        contentItem: RowLayout {
                            spacing: 6
                            Item { Layout.preferredWidth: 4 }
                            Label {
                                text: win.v && win.v.notInstalledExpanded ? "▾" : "▸"
                                color: frame.palette.placeholderText
                            }
                            Label {
                                text: qsTr("%1 not installed").arg(win.v ? win.v.notInstalledCount : 0)
                                color: frame.palette.placeholderText
                                Layout.fillWidth: true
                            }
                        }
                    }
                    Repeater {
                        model: win.v && win.v.notInstalledExpanded ? win.v.apps.filter(a => !a.installed) : []
                        delegate: AppRow {
                            required property var modelData
                            row: modelData
                            Layout.fillWidth: true
                        }
                    }

                    // Other monitoring
                    SectionHeader { text: qsTr("Other monitoring on this device") }
                    Label {
                        visible: win.v !== null && win.v.others.length === 0
                        text: qsTr("No other monitoring found")
                        color: frame.palette.placeholderText
                        Layout.leftMargin: 12
                        Layout.bottomMargin: 8
                    }
                    Repeater {
                        model: win.v ? win.v.others : []
                        delegate: AppRow {
                            required property var modelData
                            row: modelData
                            Layout.fillWidth: true
                            onClicked: win.openSelection(modelData.id)
                        }
                    }

                    MenuSeparator { Layout.fillWidth: true; padding: 0 }
                    Legend {
                        legend: win.st ? win.st.legend : []
                        Layout.fillWidth: true
                        Layout.margins: 12
                    }
                }
            }

            MenuSeparator { Layout.fillWidth: true; padding: 0 }

            // Footer
            RowLayout {
                Layout.fillWidth: true
                Layout.margins: 8
                spacing: 6

                Button {
                    text: qsTr("Open details")
                    onClicked: win.openSelection("")
                }
                Item { Layout.fillWidth: true }
                ToolButton {
                    text: "⋯"
                    font.pixelSize: 18
                    Accessible.name: qsTr("More")
                    ToolTip.visible: hovered && !moreMenu.visible
                    ToolTip.text: qsTr("More")
                    onClicked: moreMenu.popup(0, -moreMenu.implicitHeight)

                    AppMenu {
                        id: moreMenu
                        canCopy: win.v !== null && win.v.canCopy
                        support: win.st ? win.st.support : null
                        onActivated: win.hide()
                    }
                }
            }
        }
    }

    component SectionHeader: Label {
        Layout.leftMargin: 12
        Layout.topMargin: 10
        Layout.bottomMargin: 4
        font.weight: Font.DemiBold
        color: frame.palette.placeholderText
    }
}
