pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// Setup › HTTPS takeover: the warning, the numbered steps (host names, port, hosts file, redirect,
// trust, restart) with what the app can tell about each, and the undo. The commands come from
// `view.takeoverGuide`; the titles, the order and the statuses are the app's own. This also owns
// the dialog that confirms the Claude Code trust change.
ColumnLayout {
    id: root

    required property CollectorData collector
    required property CollectorSettingsModel model
    property var endpointHosts: []
    // Step key → whether the user opened (true) or closed (false) it. The page keeps it, so a
    // choice outlives a tab switch.
    property var openSteps: ({})

    // The user toggled a step.
    signal stepToggled(string key, bool open)
    // A host field was focused (so the page can scroll to it).
    signal hostFocused(Item field)
    signal turnOnRequested

    readonly property var view: collector.view
    readonly property var guide: view.takeoverGuide
    readonly property var trust: view.trust
    readonly property var trustStatus: view.trust.status
    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color okColor: Style.okColor(dark)
    readonly property color warningColor: Style.warningColor(dark)

    readonly property int tlsPort: Math.max(1, model.value.tls_port || 443)
    readonly property bool listening: view.state === "listening"
    // No steps from the collector: it has not said hello (or its text didn't parse).
    readonly property bool unparsed: guide.steps.length === 0
    readonly property bool locked: unparsed && view.takeover.length === 0
    readonly property var hostsGuide: guideStep("hosts")
    readonly property var redirectGuide: guideStep("redirect")
    readonly property var trustGuide: guideStep("trust")
    readonly property var otherGuides: guide.steps.filter(s => s.kind === "other")
    readonly property bool hasRedirect: redirectGuide !== null || (locked && tlsPort !== 443)

    // Numbers shift by one when the redirect step is missing.
    readonly property int pointNumber: 3
    readonly property int redirectNumber: 4
    readonly property int trustNumber: hasRedirect ? 5 : 4
    readonly property int restartNumber: hasRedirect ? 6 : 5
    readonly property int total: hasRedirect ? 6 : 5

    // Step statuses: { state: "done" | "todo" | "waiting" | "unknown" | "off", text }.
    readonly property bool hostsValid: {
        const hosts = model.value.tls_hosts;
        return hosts.length > 0 && hosts.every(h => h.trim() !== "")
            && model.value.tlsHostErrors.every(e => e === "");
    }
    readonly property var hostsStatus: {
        const count = model.value.tls_hosts.length;
        if (hostsValid)
            return { state: "done", text: count === 1 ? qsTr("1 host") : qsTr("%1 hosts").arg(count) };
        return { state: "todo", text: qsTr("Add a host name") };
    }
    readonly property var portStatus: {
        const privilege = view.privilege;
        const failure = collector.portFailure;
        if (failure && failure.code === "port-in-use")
            return { state: "todo", text: qsTr("Port in use") };
        if (listening)
            return { state: "done", text: privilege.state === "held" ? qsTr("Port %1 open").arg(tlsPort) : qsTr("Listening on %1").arg(tlsPort) };
        switch (privilege.state) {
        case "held":
            return { state: "done", text: qsTr("Port %1 open").arg(tlsPort) };
        case "held-stopped":
            return { state: "waiting", text: qsTr("Port %1 reserved").arg(tlsPort) };
        case "ready":
        case "mismatch":
            return { state: "todo", text: qsTr("Needs permission") };
        case "no-helper":
            return { state: "todo", text: qsTr("Port helper missing") };
        case "checking":
        case "opening":
            return { state: "waiting", text: qsTr("Waiting for permission") };
        }
        // Any other listen failure: open the step so its failure box shows.
        if (failure)
            return { state: "todo", text: qsTr("Can't listen") };
        if (view.state === "off")
            return { state: "off", text: qsTr("Collector is off") };
        if (view.state === "starting")
            return { state: "waiting", text: qsTr("Starting…") };
        return { state: "off", text: qsTr("Not running") };
    }
    // The host lookups (tray-model hostcheck), for the names the collector is serving now.
    readonly property var hostCheck: view.hostCheck
    readonly property bool hostCheckCurrent: hostCheck.results.length > 0
        && hostCheck.results.length === view.tlsHosts.length
        && hostCheck.results.every((r, i) => r.host === view.tlsHosts[i])
    readonly property var hostProblems: hostCheckCurrent ? hostCheck.results.filter(r => r.state !== "here") : []
    readonly property var hostsFile: view.hostsFile
    // cAInary's own lines are in /etc/hosts (a block it can remove).
    readonly property bool ownBlock: hostsFile.block === "current" || hostsFile.block === "stale"
    // The last removal's outcome, for the undo.
    readonly property var undoResult: hostsFile.result !== null && hostsFile.result.op === "clear"
        && hostsFile.result.message.length > 0 ? hostsFile.result : null
    readonly property var pointStatus: {
        if (hostsFile.edit === "adding")
            return { state: "waiting", text: qsTr("Waiting for permission") };
        if (hostCheck.running)
            return { state: "waiting", text: qsTr("Checking…") };
        if (!hostCheckCurrent)
            return { state: "unknown", text: qsTr("Not checked") };
        if (hostProblems.length === 0)
            return { state: "done", text: qsTr("Points here") };
        if (hostsFile.block === "current")
            return { state: "todo", text: qsTr("Still points elsewhere") };
        if (hostsFile.block === "stale")
            return { state: "todo", text: qsTr("Out of date") };
        if (hostProblems.every(r => r.state === "error"))
            return { state: "todo", text: qsTr("Doesn't resolve") };
        return { state: "todo", text: qsTr("Points elsewhere") };
    }
    // cAInary holds the privileged port's socket (the port step's change).
    readonly property bool portHeld: view.privilege.state === "held" || view.privilege.state === "held-stopped"
    // The redirect can't be seen without root.
    readonly property var redirectStatus: ({ state: "unknown", text: qsTr("Can't check") })
    readonly property bool claudeTrusted: !!trustStatus && trustStatus.claudeCode.state === "applied"
    readonly property bool claudeOther: !!trustStatus && trustStatus.claudeCode.state === "other-value"
    readonly property bool codexReady: !!trustStatus && trustStatus.codex.state === "ready"
    readonly property var trustState: {
        if (!trustStatus || !trustStatus.caExists)
            return { state: "off", text: qsTr("Starts after the collector runs once") };
        if (claudeTrusted && codexReady)
            return { state: "done", text: qsTr("Both ready") };
        if (claudeTrusted)
            return { state: "done", text: qsTr("Claude Code trusted") };
        if (codexReady)
            return { state: "done", text: qsTr("Codex ready") };
        if (claudeOther)
            return { state: "todo", text: qsTr("Claude Code uses another certificate") };
        return { state: "todo", text: qsTr("Not done") };
    }
    // The collector clears its batches on every restart, so these arrived since the last start.
    readonly property var restartStatus: {
        const count = view.batches.length;
        if (!listening)
            return { state: "off", text: view.state === "off" ? qsTr("Collector is off") : qsTr("Not running") };
        if (count > 0)
            return { state: "done", text: count === 1 ? qsTr("Receiving · 1 batch") : qsTr("Receiving · %1 batches").arg(count) };
        return { state: "waiting", text: qsTr("Waiting for the first batch") };
    }
    readonly property bool allDone: hostsStatus.state === "done" && portStatus.state === "done"
        && trustState.state === "done" && restartStatus.state === "done" && !locked

    // The trust step's lines from the collector, picked by their prefix.
    readonly property var trustLines: trustGuide ? trustGuide.lines : []
    readonly property string claudeLine: lineWith("Claude Code: ")
    readonly property string codexLine: lineWith("Codex: ")
    readonly property string sha256: lineWith("Certificate SHA-256: ") || view.caSha256
    readonly property var claudeNoWrite: trust.noWriteAvailable ? [trust.noWriteCommand]
        : claudeLine.length > 0 ? [claudeLine] : []
    readonly property var codexNoWrite: {
        const vars = ["SSL_CERT_FILE", "CODEX_CA_CERTIFICATE"]
            .map(name => { const m = new RegExp(name + "=(\\S+)").exec(codexLine); return m ? name + "=" + m[1] : ""; })
            .filter(line => line.length > 0);
        return vars.length > 0 ? vars : codexLine.length > 0 ? [codexLine] : [];
    }

    // The undo has a redirect step only when the collector printed redirect commands.
    readonly property bool undoRedirect: guide.undo.lines.length > 0

    function guideStep(kind) {
        return guide.steps.find(s => s.kind === kind) || null;
    }

    // The part of a "Label: value" line after its prefix, or "".
    function lineWith(prefix) {
        const line = trustLines.find(l => l.startsWith(prefix));
        return line ? line.slice(prefix.length) : "";
    }

    // Done steps and steps the app can't know about stay shut; everything left to do is open. The
    // user's choice, once made, wins.
    function isOpen(key, status, lockedBody) {
        if (root.openSteps[key] !== undefined)
            return root.openSteps[key];
        return status.state !== "done" && status.state !== "off" && !(lockedBody && root.locked);
    }

    // Focuses the first empty host name, opening its step first.
    function addHostAndFocus() {
        if (!isOpen("hosts", hostsStatus, false))
            root.stepToggled("hosts", true);
        Qt.callLater(() => hosts.addHostAndFocus());
    }

    // The status line under the trust rows: the last result, else the collector's message.
    function trustResultText() {
        const result = trust.result;
        if (result && result.message.length > 0)
            return result.message;
        return trust.message;
    }

    component UndoText: Label {
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    // Removing cAInary's /etc/hosts lines, and how the last removal went.
    component RemoveHostsRow: ColumnLayout {
        id: removeRow
        property var hostsFile: root.hostsFile
        property var result: root.undoResult
        property bool dark: root.dark
        spacing: Style.space.s
        Layout.fillWidth: true
        RowLayout {
            visible: removeRow.hostsFile.block === "current" || removeRow.hostsFile.block === "stale"
            spacing: Style.space.m
            Layout.fillWidth: true
            Button {
                text: qsTr("Remove from /etc/hosts…")
                enabled: removeRow.hostsFile.canRemove
                onClicked: CollectorController.removeHostsLines()
            }
            UndoText {
                visible: removeRow.hostsFile.busy
                text: qsTr("Enter your password in the system dialog.")
            }
        }
        UndoText {
            visible: removeRow.result !== null
            text: removeRow.result ? removeRow.result.message : ""
            color: removeRow.result && removeRow.result.tone === "error" ? Style.errorColor(removeRow.dark)
                : removeRow.result && removeRow.result.tone === "warning" ? Style.warningColor(removeRow.dark)
                : palette.windowText
        }
    }

    spacing: Style.space.l

    Callout {
        tone: "warning"
        title: qsTr("While the takeover is on, your organization's collector gets nothing from this computer.")
        body: root.allDone ? "" : qsTr("Nothing is forwarded. Other programs that use these host names will fail their TLS handshake here; that's expected.")
        Layout.fillWidth: true
        Disclosure {
            title: qsTr("More about what this changes")
            Label {
                visible: root.guide.warnings.length <= 3 && root.guide.footer.length === 0
                text: qsTr("The host names are what you entered here, not a verified sender. The collector issues certificates only for these names, keeps the key in memory only, and never adds it to the system trust store. Any local program can send to the collector, so the feed shows what arrived, not who sent it.")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Repeater {
                model: root.guide.warnings.slice(3).concat(root.guide.footer)
                delegate: Label {
                    required property string modelData
                    text: modelData
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }
    }

    // 1 Host names
    SetupStep {
        number: 1
        total: root.total
        title: qsTr("Host names")
        summary: root.model.value.tls_hosts.filter(h => h !== "").join(", ")
        stepState: root.hostsStatus.state
        statusText: root.hostsStatus.text
        expanded: root.isOpen("hosts", root.hostsStatus, false)
        onToggled: root.stepToggled("hosts", !expanded)

        CollectorFailure {
            visible: root.collector.hostFailure !== null
            failure: root.collector.hostFailure
            privilege: null
            onAddHostRequested: root.addHostAndFocus()
            Layout.fillWidth: true
        }
        TakeoverHosts {
            id: hosts
            model: root.model
            endpointHosts: root.endpointHosts
            Layout.fillWidth: true
            onHostFocused: field => root.hostFocused(field)
        }
    }

    // 2 Port
    SetupStep {
        number: 2
        total: root.total
        title: qsTr("Port")
        summary: root.tlsPort === 443 ? qsTr("443, no redirect needed")
            : qsTr("%1, with a redirect from 443 (step %2)").arg(root.tlsPort).arg(root.redirectNumber)
        stepState: root.portStatus.state
        statusText: root.portStatus.text
        expanded: root.isOpen("port", root.portStatus, false)
        onToggled: root.stepToggled("port", !expanded)

        CollectorFailure {
            visible: root.collector.portFailure !== null
            failure: root.collector.portFailure
            privilege: root.view.privilege
            effectivePort: root.tlsPort
            onTryPortRequested: port => root.model.change(next => { next.tls_port = port; })
            Layout.fillWidth: true
        }
        TakeoverPort {
            model: root.model
            privilege: root.collector.privilegedFailure ? ({ state: "none" }) : root.view.privilege
            Layout.fillWidth: true
        }
        StepUndo {
            visible: root.portHeld
            text: qsTr("cAInary keeps port %1 open until the collector is turned off or cAInary quits.").arg(root.tlsPort)
            Button {
                text: qsTr("Close port %1").arg(root.tlsPort)
                Accessible.description: qsTr("Turns the collector off")
                onClicked: root.model.change(next => { next.enabled = false; })
            }
        }
    }

    // 3 Point the host names at this computer
    SetupStep {
        number: root.pointNumber
        total: root.total
        title: qsTr("Point the host names at this computer")
        stepState: root.pointStatus.state
        statusText: root.pointStatus.text
        expanded: root.isOpen("point", root.pointStatus, true)
        onToggled: root.stepToggled("point", !expanded)

        LockedNote {
            visible: root.locked
            collectorOn: root.view.state !== "off"
            onTurnOnRequested: root.turnOnRequested()
        }
        PointHosts {
            visible: !root.locked
            view: root.view
            hostsGuide: root.hostsGuide
            checkCurrent: root.hostCheckCurrent
            problems: root.hostProblems
        }
        StepUndo {
            visible: !root.locked && (root.ownBlock || root.undoResult !== null)
            RemoveHostsRow {}
        }
    }

    // 4 Redirect, only when the port isn't 443
    SetupStep {
        visible: root.hasRedirect
        number: root.redirectNumber
        total: root.total
        title: qsTr("Redirect port 443 to %1").arg(root.tlsPort)
        stepState: root.redirectStatus.state
        statusText: root.redirectStatus.text
        expanded: root.isOpen("redirect", root.redirectStatus, true)
        onToggled: root.stepToggled("redirect", !expanded)

        LockedNote {
            visible: root.locked
            collectorOn: root.view.state !== "off"
            onTurnOnRequested: root.turnOnRequested()
        }
        Label {
            visible: !root.locked && root.redirectGuide !== null
            text: qsTr("Run these in a terminal. They last until you reboot or undo them.")
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        CommandBlock {
            visible: !root.locked && root.redirectGuide !== null
            lines: root.redirectGuide ? root.redirectGuide.lines : []
            shell: true
            copyName: qsTr("the redirect commands")
            Layout.fillWidth: true
        }
        Label {
            visible: !root.locked
            text: qsTr("Or skip this step: listen on port 443 directly (step 2).")
            textFormat: Text.PlainText
            color: palette.placeholderText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        StepUndo {
            visible: !root.locked && root.undoRedirect
            text: qsTr("Run these in a terminal:")
            CommandBlock {
                lines: root.guide.undo.lines
                shell: true
                copyName: qsTr("the undo commands")
                Layout.fillWidth: true
            }
        }
    }

    // 5 Trust
    SetupStep {
        number: root.trustNumber
        total: root.total
        title: qsTr("Let the agents trust the certificate")
        stepState: root.trustState.state
        statusText: root.trustState.text
        expanded: root.isOpen("trust", root.trustState, false)
        onToggled: root.stepToggled("trust", !expanded)

        GridLayout {
            columns: 3
            columnSpacing: 10
            rowSpacing: Style.space.s
            Layout.fillWidth: true

            Label {
                text: qsTr("Claude Code")
                font.weight: Font.DemiBold
                Layout.alignment: Qt.AlignTop
            }
            Label {
                text: root.claudeTrusted ? qsTr("Trusted in %1").arg(root.trustStatus.claudeCode.settingsPath)
                    : root.claudeOther
                        ? qsTr("Uses another certificate (%1)").arg(root.trustStatus.claudeCode.value || "")
                        : qsTr("Not set up")
                textFormat: Text.PlainText
                color: root.claudeTrusted ? root.okColor : palette.placeholderText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
            }
            RowLayout {
                spacing: Style.space.m
                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                Button {
                    id: trustButton
                    visible: !root.claudeTrusted
                    text: qsTr("Let Claude Code trust…")
                    enabled: !root.trust.busy
                    onClicked: CollectorController.previewClaudeTrust()
                }
                Button {
                    visible: root.claudeTrusted
                    text: qsTr("Undo")
                    enabled: !root.trust.busy
                    Accessible.name: qsTr("Undo Claude Code trust")
                    onClicked: CollectorController.undoClaudeTrust()
                }
            }

            Label {
                text: qsTr("Codex")
                font.weight: Font.DemiBold
                Layout.alignment: Qt.AlignTop
            }
            Label {
                text: root.codexReady ? qsTr("Bundle ready") : qsTr("Not set up")
                color: root.codexReady ? root.okColor : palette.placeholderText
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
            }
            RowLayout {
                spacing: Style.space.m
                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                Button {
                    visible: !root.codexReady
                    text: qsTr("Prepare Codex bundle")
                    enabled: !root.trust.busy
                    onClicked: CollectorController.prepareCodexBundle()
                }
                Button {
                    visible: root.codexReady
                    text: qsTr("Remove")
                    enabled: !root.trust.busy
                    Accessible.name: qsTr("Remove Codex bundle")
                    onClicked: CollectorController.undoCodexBundle()
                }
            }
        }

        Label {
            visible: root.codexReady && !!root.trustStatus.codex.command
            text: qsTr("Start Codex with:")
            textFormat: Text.PlainText
            Layout.fillWidth: true
        }
        CommandBlock {
            visible: root.codexReady && !!root.trustStatus.codex.command
            lines: visible ? [root.trustStatus.codex.command] : []
            copyName: qsTr("the Codex command")
            Layout.fillWidth: true
        }

        Label {
            visible: text.length > 0
            text: root.trust.busy ? qsTr("Working…") : root.trustResultText()
            textFormat: Text.PlainText
            color: root.trust.busy ? palette.placeholderText
                : root.trust.result && (root.trust.result.action === "refused" || root.trust.result.action === "failed")
                    ? Style.errorColor(root.dark) : palette.placeholderText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Label {
            visible: !!root.trustStatus && !!root.trustStatus.note
            text: root.trustStatus && root.trustStatus.note ? root.trustStatus.note : ""
            textFormat: Text.PlainText
            color: palette.placeholderText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        Disclosure {
            title: qsTr("Without changing any settings")
            Label {
                visible: root.claudeNoWrite.length === 0 && root.codexNoWrite.length === 0
                text: qsTr("Start the HTTPS takeover once to create the certificate.")
                textFormat: Text.PlainText
                color: palette.placeholderText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: root.claudeNoWrite.length > 0
                text: qsTr("Claude Code: start it with")
                textFormat: Text.PlainText
                Layout.fillWidth: true
            }
            CommandBlock {
                visible: root.claudeNoWrite.length > 0
                lines: root.claudeNoWrite
                copyName: qsTr("the Claude Code command")
                Layout.fillWidth: true
            }
            Label {
                visible: root.codexNoWrite.length > 0
                text: qsTr("Codex: set one of these for the codex process")
                textFormat: Text.PlainText
                Layout.fillWidth: true
            }
            CommandBlock {
                visible: root.codexNoWrite.length > 0
                lines: root.codexNoWrite
                copyName: qsTr("the Codex variables")
                Layout.fillWidth: true
            }
        }

        RowLayout {
            visible: root.sha256.length > 0
            spacing: 10
            Layout.fillWidth: true
            Label {
                text: qsTr("Certificate SHA-256")
                textFormat: Text.PlainText
                color: palette.placeholderText
                Layout.alignment: Qt.AlignTop
            }
            TextEdit {
                text: root.sha256
                readOnly: true
                selectByMouse: true
                textFormat: TextEdit.PlainText
                font.family: "monospace"
                font.pointSize: Application.font.pointSize
                color: palette.text
                selectionColor: palette.highlight
                selectedTextColor: palette.highlightedText
                wrapMode: TextEdit.WrapAnywhere
                Layout.fillWidth: true
            }
        }
    }

    // 6 Restart the agents
    SetupStep {
        number: root.restartNumber
        total: root.total
        title: qsTr("Restart the agents")
        stepState: root.restartStatus.state
        statusText: root.restartStatus.text
        expanded: root.isOpen("restart", root.restartStatus, true)
        onToggled: root.stepToggled("restart", !expanded)

        Label {
            text: qsTr("Restart Claude Code and Codex now, and again whenever the collector restarts: every run makes a new certificate.")
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }

    // Steps the app has no kind for, with the collector's own wording.
    Repeater {
        model: root.otherGuides
        delegate: ColumnLayout {
            id: other
            required property var modelData
            spacing: Style.space.s
            Layout.fillWidth: true
            Label {
                text: other.modelData.title
                textFormat: Text.PlainText
                font.weight: Font.DemiBold
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            CommandBlock {
                visible: other.modelData.lines.length > 0
                lines: other.modelData.lines
                copyName: qsTr("the commands")
                Layout.fillWidth: true
            }
        }
    }

    // The collector's text didn't split into steps: show it whole, never cut off.
    ColumnLayout {
        visible: root.unparsed && !root.locked
        spacing: Style.space.s
        Layout.fillWidth: true
        Label {
            text: qsTr("Instructions from the collector")
            font.weight: Font.DemiBold
            Layout.fillWidth: true
        }
        CommandBlock {
            lines: root.view.takeover
            copyName: qsTr("the takeover instructions")
            Layout.fillWidth: true
        }
    }

    // The undo, in the order to do it. Undoing the takeover doesn't touch the trust settings.
    Rectangle {
        height: 1
        color: Qt.alpha(palette.windowText, 0.18)
        Layout.fillWidth: true
    }
    Disclosure {
        title: qsTr("Undo the takeover")
        bold: true
        expanded: root.openSteps.undo === true

        UndoText { text: qsTr("1. Switch back to Point agents here, or turn the collector off.") }
        Button {
            text: qsTr("Switch back")
            onClicked: root.model.change(next => { next.tls = false; })
        }
        UndoText {
            text: root.ownBlock ? qsTr("2. Remove the cAInary lines from /etc/hosts:")
                : root.hostsGuide ? qsTr("2. Remove these lines from /etc/hosts:")
                : qsTr("2. Remove the lines you added for the host names from /etc/hosts.")
        }
        RemoveHostsRow {}
        UndoText {
            visible: root.ownBlock && root.hostsGuide !== null
            text: qsTr("or remove these lines yourself:")
        }
        UndoText {
            visible: root.hostsFile.block === "damaged"
            text: qsTr("/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts.")
            color: Style.errorColor(root.dark)
        }
        CommandBlock {
            visible: root.hostsGuide !== null
            lines: root.hostsGuide ? root.hostsGuide.lines : []
            copyName: qsTr("the hosts file lines")
            Layout.fillWidth: true
        }
        UndoText {
            visible: root.undoRedirect
            text: qsTr("3. Remove the redirect:")
        }
        CommandBlock {
            visible: root.undoRedirect
            lines: root.guide.undo.lines
            shell: true
            copyName: qsTr("the undo commands")
            Layout.fillWidth: true
        }
        UndoText {
            text: (root.undoRedirect ? qsTr("4.") : qsTr("3.")) + " " + qsTr("Remove the trust:")
        }
        RowLayout {
            spacing: Style.space.m
            Layout.fillWidth: true
            Button {
                text: qsTr("Undo Claude Code trust")
                enabled: !root.trust.busy && root.claudeTrusted
                onClicked: CollectorController.undoClaudeTrust()
            }
            Button {
                text: qsTr("Remove Codex bundle")
                enabled: !root.trust.busy && root.codexReady
                onClicked: CollectorController.undoCodexBundle()
            }
        }
        UndoText {
            text: (root.undoRedirect ? qsTr("5.") : qsTr("4.")) + " "
                + qsTr("Restart the agents. A process that already loaded the certificate keeps trusting it until it restarts.")
        }
    }

    Dialog {
        id: trustDialog
        modal: true
        parent: Overlay.overlay
        anchors.centerIn: Overlay.overlay
        width: Math.min(480, parent.width - 48)
        title: qsTr("Let Claude Code trust the local collector?")
        property bool dismissed: false
        visible: root.collector.view.trust.preview !== null && !dismissed
        onAccepted: {
            dismissed = true;
            CollectorController.applyClaudeTrust();
        }
        onRejected: {
            dismissed = true;
            CollectorController.cancelClaudeTrustPreview();
        }
        onClosed: trustButton.forceActiveFocus()
        footer: DialogButtonBox {
            Button {
                text: qsTr("Cancel")
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
            }
            Button {
                text: qsTr("Confirm")
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            }
        }
        contentItem: ColumnLayout {
            spacing: 10
            Label {
                text: root.collector.view.trust.preview
                    ? root.collector.view.trust.preview.message : ""
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.key)
                text: root.collector.view.trust.preview
                    ? qsTr("Change: %1\nFrom: %2\nTo: %3")
                        .arg(root.collector.view.trust.preview.key || "")
                        .arg(root.collector.view.trust.preview.from || qsTr("not set"))
                        .arg(root.collector.view.trust.preview.to || "") : ""
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.settingsPath)
                text: qsTr("Settings: ") + (root.collector.view.trust.preview ? root.collector.view.trust.preview.settingsPath : "")
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                visible: !!(root.collector.view.trust.preview && root.collector.view.trust.preview.backupPath)
                text: qsTr("Backup: ") + (root.collector.view.trust.preview ? root.collector.view.trust.preview.backupPath : "")
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Label {
                text: qsTr("Your org's collector receives nothing while the takeover is active.")
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }

    Connections {
        target: CollectorController
        function onViewJsonChanged() {
            if (root.collector.view.trust.preview === null)
                trustDialog.dismissed = false;
        }
    }
}
