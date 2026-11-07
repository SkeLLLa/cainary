import QtQuick
import ua.SkeLLLa.cAInary

// The parsed CollectorController.viewJson with every key defaulted, shared by the Details
// window, its toolbar pill and the popup's live row.
QtObject {
    readonly property var view: {
        const trustDefaults = { busy: false, message: "", status: null, preview: null, result: null, noWriteAvailable: false, noWriteCommand: "" };
        const privilegeDefaults = { state: "none", port: 0, heading: "", detail: "", warning: "", error: "", instructions: [], canOpen: false, busy: false };
        const hostsFileDefaults = { helper: "checking", helperNote: "", block: "unknown", conflicts: [], reserved: [], unsupported: null, error: "", tooMany: false, canEdit: false, canRemove: false, busy: false, edit: "idle", result: null };
        const hostCheckDefaults = { running: false, results: [] };
        const guideDefaults = { warnings: [], steps: [], undo: { title: "", lines: [] }, footer: [] };
        let value = {};
        try {
            value = JSON.parse(CollectorController.viewJson) || {};
        } catch (error) {
            value = {};
        }
        return {
            state: value.state || "off",
            message: value.message || "",
            endpoint: value.endpoint || "",
            claudeCode: value.claudeCode || [],
            codex: value.codex || [],
            notes: value.notes || [],
            takeover: value.takeover || [],
            // The takeover text split into warnings, steps, undo and footer (tray-model).
            takeoverGuide: value.takeoverGuide ? {
                warnings: value.takeoverGuide.warnings || [],
                steps: value.takeoverGuide.steps || [],
                undo: value.takeoverGuide.undo || guideDefaults.undo,
                footer: value.takeoverGuide.footer || []
            } : guideDefaults,
            mode: value.mode || "receiver",
            tlsHosts: value.tlsHosts || [],
            caPath: value.caPath || "",
            caSha256: value.caSha256 || "",
            stderrTail: value.stderrTail || "",
            alerts: value.alerts || [],
            batches: value.batches || [],
            rows: value.rows || [],
            flagGroups: value.flagGroups || [],
            errors: value.errors || [],
            trust: value.trust || trustDefaults,
            // Why the collector stopped on its own: { code, message, port }, else null.
            failure: value.failure || null,
            // What opening a port below 1024 needs; state "none" when it needs nothing.
            privilege: value.privilege || privilegeDefaults,
            // Whether the takeover host names resolve to this computer: { running, results: [{ host, state, address, message }] }.
            hostCheck: value.hostCheck ? { running: !!value.hostCheck.running, results: value.hostCheck.results || [] } : hostCheckDefaults,
            // The /etc/hosts state and the one-click edit (tray-model hostsview).
            hostsFile: value.hostsFile ? Object.assign({}, hostsFileDefaults, value.hostsFile) : hostsFileDefaults
        };
    }

    readonly property string state: view.state
    readonly property bool enabled: state !== "off"
    // ":4318" from "http://127.0.0.1:4318".
    readonly property string port: {
        const m = /:(\d+)\/?$/.exec(view.endpoint);
        return m ? ":" + m[1] : "";
    }
    readonly property string stateText: {
        switch (state) {
        case "listening": return qsTr("Listening");
        case "starting": return qsTr("Starting…");
        case "stopped": return qsTr("Stopped");
        case "failed": return qsTr("Failed");
        default: return qsTr("Off");
        }
    }
    // The failure box carries the "Open port N" action, so the port fields' own note stays out.
    readonly property bool privilegedFailure: view.failure !== null
        && (view.failure.code === "port-privileged" || view.failure.code === "listen-fd")
        && view.privilege.state !== "none"
    // The failure when its fix is a step of the takeover checklist (host names or port), else null.
    readonly property var hostFailure: view.failure !== null
        && (view.failure.code === "tls-no-host" || view.failure.code === "tls-bad-host") ? view.failure : null
    readonly property var portFailure: view.failure !== null
        && ["port-privileged", "listen-fd", "port-in-use"].includes(view.failure.code) ? view.failure : null
    // One line for the page header: why the collector isn't running, or that it holds a port.
    readonly property string statusLine: {
        const p = view.privilege;
        const reserved = p.state === "held-stopped" ? p.heading : "";
        if (view.failure)
            return reserved ? view.failure.message + " · " + reserved : view.failure.message;
        return p.state === "held" ? p.heading : reserved;
    }
    // Red-flag hits: one per alert line, each with its own ×count.
    readonly property int flagCount: view.alerts.length
}
