pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "components"
import "components/style.js" as Style

// Live › OTel collector › Red flags: what the collector flagged, grouped by pattern.
ColumnLayout {
    id: flags

    required property CollectorData collector
    required property CollectorSettingsModel model
    // Set by the page to scroll a group into view, e.g. from a notification.
    property string pattern: ""
    signal showInFeed(string pattern)

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color flagColor: Style.levelColor("high", dark, palette.windowText)
    // Built in tray-model, newest group first.
    readonly property var groups: collector.view.flagGroups

    spacing: 0

    CheckBox {
        text: qsTr("Notify about red flags")
        checked: flags.model.value.notify
        onToggled: flags.model.change(next => { next.notify = checked; })
        Layout.leftMargin: 8
        Layout.topMargin: 4
    }

    // Compact empty state
    ColumnLayout {
        visible: flags.groups.length === 0
        Layout.fillWidth: true
        Layout.fillHeight: true
        spacing: 6
        Item { Layout.fillHeight: true }
        Label {
            text: qsTr("No red flags")
            font.weight: Font.DemiBold
            Layout.alignment: Qt.AlignHCenter
        }
        Label {
            text: flags.collector.enabled
                ? qsTr("Nothing matched the rules yet. Edit them in Setup.")
                : qsTr("The collector is off.")
            color: palette.placeholderText
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
        }
        Item { Layout.fillHeight: true }
    }

    ScrollView {
        id: scroll
        visible: flags.groups.length > 0
        Layout.fillWidth: true
        Layout.fillHeight: true
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: scroll.availableWidth
            spacing: 8

            Repeater {
                id: repeater
                model: flags.groups
                delegate: Rectangle {
                    id: card
                    required property var modelData
                    readonly property bool target: flags.pattern === modelData.pattern
                    Layout.fillWidth: true
                    Layout.leftMargin: 8
                    Layout.rightMargin: 8
                    implicitHeight: content.implicitHeight + 20
                    radius: 6
                    color: Qt.alpha(flags.flagColor, target ? 0.12 : 0.05)
                    border.color: Qt.alpha(flags.flagColor, target ? 0.6 : 0.25)

                    // The whole card opens the feed filtered to this pattern, not only its button.
                    TapHandler {
                        cursorShape: Qt.PointingHandCursor
                        onTapped: flags.showInFeed(card.modelData.pattern)
                    }

                    ColumnLayout {
                        id: content
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 4

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Label {
                                text: "⚑ " + card.modelData.pattern
                                font.weight: Font.DemiBold
                                color: flags.flagColor
                            }
                            Label {
                                text: card.modelData.preset ? qsTr("preset") : qsTr("custom")
                                color: palette.placeholderText
                                font.pointSize: Application.font.pointSize * 0.85
                            }
                            Item { Layout.fillWidth: true }
                            Label {
                                text: (card.modelData.hits === 1 ? qsTr("1 hit") : qsTr("%1 hits").arg(card.modelData.hits))
                                    + (card.modelData.total !== card.modelData.hits ? " · ×" + card.modelData.total : "")
                                color: palette.placeholderText
                            }
                        }
                        Label {
                            text: qsTr("Last seen %1").arg(card.modelData.lastTime)
                            color: palette.placeholderText
                            font.pointSize: Application.font.pointSize * 0.9
                        }
                        Label {
                            visible: card.modelData.events.length > 0
                            text: qsTr("Events: %1").arg(card.modelData.events.join(", "))
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                        Label {
                            visible: card.modelData.attributes.length > 0
                            text: qsTr("Attributes: %1").arg(card.modelData.attributes.join(", "))
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            font.family: "monospace"
                            Layout.fillWidth: true
                        }
                        Label {
                            text: qsTr("Signals: %1").arg(card.modelData.signals.join(", "))
                            color: palette.placeholderText
                        }
                        RowLayout {
                            spacing: 6
                            Button {
                                text: qsTr("Show in feed")
                                onClicked: flags.showInFeed(card.modelData.pattern)
                            }
                            // Hook only: the known-signature list is designed elsewhere. A disabled
                            // button gets no hover, so the tooltip hangs on a wrapper.
                            Item {
                                implicitWidth: known.implicitWidth
                                implicitHeight: known.implicitHeight
                                ToolTip.visible: knownHover.hovered
                                ToolTip.text: qsTr("Known signatures are coming")
                                HoverHandler { id: knownHover }
                                Button {
                                    id: known
                                    text: qsTr("Mark as known…")
                                    enabled: false
                                }
                            }
                        }
                    }

                    // Scroll the targeted group into view.
                    onTargetChanged: if (target) scrollTo()
                    Component.onCompleted: if (target) scrollTo()
                    function scrollTo() {
                        const flick = scroll.contentItem as Flickable;
                        flick.contentY = Math.max(0, Math.min(card.mapToItem(flick.contentItem, 0, 0).y - 8,
                                                               flick.contentHeight - flick.height));
                    }
                }
            }
            Item { Layout.preferredHeight: 4 }
        }
    }
}
