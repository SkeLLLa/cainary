import QtQuick
import ua.SkeLLLa.cAInary

// The parsed CollectorController.viewJson with every key defaulted, shared by the Details
// window, its toolbar pill and the popup's live row.
QtObject {
    readonly property var view: {
        const trustDefaults = { busy: false, message: "", status: null, preview: null, result: null, noWriteAvailable: false, noWriteCommand: "" };
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
            trust: value.trust || trustDefaults
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
    // Red-flag hits: one per alert line, each with its own ×count.
    readonly property int flagCount: view.alerts.length
}
