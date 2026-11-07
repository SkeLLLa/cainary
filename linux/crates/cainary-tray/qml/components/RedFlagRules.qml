import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "style.js" as Style

// What the collector flags: the presets and the user's own patterns.
ColumnLayout {
    id: root

    required property CollectorSettingsModel model
    // Off where the notify checkbox already sits elsewhere (the Red flags tab header).
    property bool showNotify: true
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color warning: Style.warningColor(dark)

    Label { text: qsTr("Presets"); font.weight: Font.DemiBold }
    GridLayout {
        columns: 2
        columnSpacing: 16
        rowSpacing: 0
        Layout.fillWidth: true
        Repeater {
            model: root.model.presets
            delegate: CheckBox {
                required property var modelData
                text: modelData.label
                checked: root.model.value.presets.indexOf(modelData.key) >= 0
                onToggled: root.model.change(next => {
                    const i = next.presets.indexOf(modelData.key);
                    if (checked && i < 0)
                        next.presets.push(modelData.key);
                    else if (!checked && i >= 0)
                        next.presets.splice(i, 1);
                })
            }
        }
    }

    Label { text: qsTr("Custom patterns"); font.weight: Font.DemiBold; Layout.topMargin: 6 }
    Label {
        visible: root.model.value.patterns.length === 0
        text: qsTr("None. Add a customer name, a project code or anything else that must not leave this device.")
        color: palette.placeholderText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Repeater {
        model: root.model.value.patterns
        delegate: ColumnLayout {
            required property int index
            required property var modelData
            Layout.fillWidth: true
            RowLayout {
                Layout.fillWidth: true
                TextField {
                    text: modelData.name
                    placeholderText: qsTr("Name")
                    onEditingFinished: root.model.updatePattern(index, "name", text)
                    Layout.preferredWidth: 110
                }
                TextField {
                    text: modelData.pattern
                    placeholderText: qsTr("Pattern")
                    onEditingFinished: root.model.updatePattern(index, "pattern", text)
                    Layout.fillWidth: true
                }
                CheckBox {
                    text: qsTr("Regex")
                    checked: modelData.kind === "regex"
                    onToggled: root.model.updatePattern(index, "kind", checked ? "regex" : "text")
                }
                CheckBox {
                    text: qsTr("Match case")
                    checked: modelData.case_sensitive
                    onToggled: root.model.updatePattern(index, "case_sensitive", checked)
                }
                ToolButton {
                    text: "−"
                    Accessible.name: qsTr("Remove pattern")
                    onClicked: root.model.change(next => { next.patterns.splice(index, 1); })
                }
            }
            Label {
                visible: index < root.model.value.patternErrors.length
                    && root.model.value.patternErrors[index] !== ""
                text: index < root.model.value.patternErrors.length
                    ? root.model.value.patternErrors[index] + qsTr(" This pattern is not used.") : ""
                color: root.warning
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }
    Label {
        visible: root.model.value.overLimit
        text: qsTr("The enabled presets and valid patterns exceed the collector limit of 64. Turn off a preset or remove a pattern.")
        color: root.warning
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Button {
        text: qsTr("Add pattern")
        enabled: root.model.value.patterns.length < 64
        onClicked: root.model.change(next => {
            next.patterns.push({ name: "", kind: "text", pattern: "", case_sensitive: false });
        })
    }
    CheckBox {
        visible: root.showNotify
        text: qsTr("Notify about red flags")
        checked: root.model.value.notify
        onToggled: root.model.change(next => { next.notify = checked; })
    }
}
