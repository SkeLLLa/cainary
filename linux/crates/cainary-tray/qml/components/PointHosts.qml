pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "style.js" as Style

// The body of Setup › HTTPS takeover › "Point the host names at this computer": what each host
// name resolves to, the one-click "Add to /etc/hosts…", what to do when it can't be used or didn't
// work, and always the lines to add by hand until the names point here. The copy is the design's
// (docs/local/design/hosts-quick-edit.md §5); the states come from the app's `hostsFile` and
// `hostCheck` (tray-model hostsview, hostcheck).
ColumnLayout {
    id: root

    // The collector view (`hostsFile`, `hostCheck`, `tlsHosts`).
    required property var view
    // The "hosts" step of the takeover guide, or null.
    property var hostsGuide: null
    // The host lookups are for the names the collector serves now.
    property bool checkCurrent: false
    // The lookups that didn't end at this computer.
    property var problems: []

    readonly property var file: view.hostsFile
    readonly property var check: view.hostCheck
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property bool done: !check.running && checkCurrent && problems.length === 0
    readonly property bool listening: view.state === "listening"
    readonly property bool busy: file.busy
    readonly property var unsupported: file.unsupported
    readonly property bool sandboxed: file.helper === "sandboxed"
    readonly property bool stillElsewhere: !check.running && !busy && checkCurrent
        && problems.length > 0 && file.block === "current"
    readonly property var result: file.result
    readonly property bool resultShown: result !== null && result.op === "set" && result.message.length > 0
    // Whether the one-click button exists (it can still be disabled). Before the first check only
    // Check and the manual lines show.
    readonly property bool buttonShown: !done && !sandboxed && unsupported === null
        && (checkCurrent || check.running || busy)
    readonly property string firstElsewhere: {
        const hit = problems.find(r => r.state === "elsewhere") || problems[0];
        return hit ? hit.host : "";
    }

    spacing: Style.space.s
    Layout.fillWidth: true

    component Note: Label {
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }

    // Per host: a spinner while looking, then where the name goes.
    Repeater {
        model: root.check.running ? root.view.tlsHosts.map(h => ({ host: h, state: "pending", address: "", message: "" }))
            : root.checkCurrent ? root.check.results : []
        RowLayout {
            id: row
            required property var modelData
            spacing: Style.space.s
            Layout.fillWidth: true
            Item {
                implicitWidth: 16
                implicitHeight: 16
                Layout.alignment: Qt.AlignTop
                BusyIndicator {
                    anchors.fill: parent
                    visible: row.modelData.state === "pending"
                    running: visible
                }
                GlyphIcon {
                    visible: row.modelData.state !== "pending"
                    glyph: row.modelData.state === "here" ? "check" : row.modelData.state === "elsewhere" ? "warning" : "error"
                    color: row.modelData.state === "here" ? Style.okColor(root.dark)
                        : row.modelData.state === "elsewhere" ? Style.warningColor(root.dark) : Style.errorColor(root.dark)
                }
            }
            Note {
                text: row.modelData.state === "here" ? qsTr("%1 → this computer").arg(row.modelData.host)
                    : row.modelData.state === "elsewhere" ? qsTr("%1 → %2").arg(row.modelData.host).arg(row.modelData.address)
                    : row.modelData.state === "error" ? qsTr("Couldn't look up %1: %2").arg(row.modelData.host).arg(row.modelData.message)
                    : row.modelData.host
            }
        }
    }

    Note {
        visible: root.done
        text: qsTr("All names reach this computer.") + (root.file.block === "current" ? " " + qsTr("Added by cAInary to /etc/hosts.") : "")
    }

    // Added, but a name still goes elsewhere: the usual causes.
    Callout {
        visible: root.stillElsewhere
        tone: "warning"
        title: qsTr("The lines are in /etc/hosts, but %1 still resolves to %2.").arg(root.firstElsewhere)
            .arg((root.problems.find(r => r.host === root.firstElsewhere) || { address: "" }).address || qsTr("the wrong place"))
        Layout.fillWidth: true
        Repeater {
            model: root.stillElsewhere ? root.file.conflicts : []
            Note {
                required property var modelData
                text: qsTr("Line %1 sends %2 to %3. Remove or comment it out yourself; cAInary only edits its own lines.")
                    .arg(modelData.line).arg(modelData.host).arg(modelData.address)
            }
        }
        Note {
            text: qsTr("Your resolver may not read /etc/hosts first (hosts: in /etc/nsswitch.conf).")
        }
        Note {
            text: qsTr("If nscd is running, clear its cache:")
        }
        CommandBlock {
            lines: ["sudo nscd -i hosts"]
            shell: true
            copyName: qsTr("the nscd command")
            Layout.fillWidth: true
        }
    }

    Note {
        visible: root.file.block === "stale" && root.unsupported === null && !root.done
        text: qsTr("/etc/hosts has cAInary lines for other host names.")
    }
    Note {
        // A refusal for a damaged block says the same, so it isn't repeated.
        visible: root.file.block === "damaged" && !(root.resultShown && root.result.token === "damaged-block")
        text: qsTr("/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts.")
        color: Style.errorColor(root.dark)
    }

    // The last edit's outcome. Neutral ones are plain text; the rest sit in a box.
    Note {
        visible: root.resultShown && root.result.tone === "neutral"
        text: root.result ? root.result.message : ""
    }
    Callout {
        visible: root.resultShown && root.result.tone !== "neutral"
        tone: root.result && root.result.tone === "error" ? "error" : "warning"
        body: root.result ? root.result.message : ""
        Layout.fillWidth: true
    }

    // Why the button can't be used, when that isn't obvious.
    Note {
        visible: root.unsupported !== null
        text: {
            const why = root.unsupported;
            if (why === null)
                return "";
            if (why.kind === "symlink")
                return qsTr("/etc/hosts is managed by your system (it links to %1). Add the names in your system configuration, for example networking.hosts on NixOS.").arg(why.target);
            if (why.kind === "mount-point")
                return qsTr("/etc/hosts is mounted from elsewhere (a container?). Edit it on the host.");
            if (why.kind === "unprotected")
                return qsTr("/etc/hosts can be changed by users other than root; cAInary won't edit it.");
            return qsTr("/etc/hosts isn't a regular file; cAInary won't edit it.");
        }
    }
    Note {
        visible: root.unsupported === null && root.file.error.length > 0
        text: qsTr("Couldn't read /etc/hosts (%1). cAInary won't edit it.").arg(root.file.error)
    }
    Note {
        visible: root.buttonShown && root.file.tooMany
        text: qsTr("One-click editing handles up to 8 names.")
    }
    Note {
        visible: root.buttonShown && !root.file.tooMany && root.file.reserved.length > 0
        text: qsTr("cAInary won't redirect %1, this computer's own name.").arg(root.file.reserved.join(", "))
    }
    Note {
        visible: root.buttonShown && root.file.helper === "no-helper"
        text: qsTr("One-click editing needs the cAInary hosts helper. Update the cAInary package, or for a source build run mise run linux:helper.")
    }
    Note {
        visible: root.buttonShown && root.file.helper === "mismatch" && root.file.helperNote.length > 0
        text: root.file.helperNote
        color: palette.placeholderText
    }
    Note {
        visible: root.sandboxed
        text: qsTr("cAInary is sandboxed and can't edit /etc/hosts.")
    }
    Note {
        visible: root.busy
        text: qsTr("Enter your password in the system dialog.")
    }

    RowLayout {
        visible: root.listening
        spacing: Style.space.m
        Layout.fillWidth: true
        Button {
            visible: root.buttonShown
            highlighted: true
            text: root.file.block === "stale" ? qsTr("Update /etc/hosts…") : qsTr("Add to /etc/hosts…")
            enabled: root.file.canEdit && !root.check.running
            onClicked: CollectorController.editHosts()
        }
        Button {
            text: root.check.running ? qsTr("Checking…") : root.checkCurrent ? qsTr("Check again") : qsTr("Check")
            enabled: !root.check.running && !root.busy
            onClicked: CollectorController.checkHosts()
        }
    }
    Note {
        visible: root.listening && root.buttonShown && root.file.canEdit
        text: qsTr("This changes name lookups for every program on this computer until you remove it.")
        color: palette.placeholderText
    }

    // The manual way stays until the names point here.
    Note {
        visible: root.hostsGuide !== null && !root.done
        text: root.buttonShown && root.file.canEdit ? qsTr("Or add these lines yourself, for example with sudoedit /etc/hosts:")
            : qsTr("Add these lines to /etc/hosts as root, for example with sudoedit /etc/hosts:")
    }
    CommandBlock {
        visible: root.hostsGuide !== null && !root.done
        lines: root.hostsGuide ? root.hostsGuide.lines : []
        copyName: qsTr("the hosts file lines")
        Layout.fillWidth: true
    }
}
