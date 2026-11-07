pragma Singleton
import QtQuick
import "SampleView.js" as S
import ua.SkeLLLa.cAInary

QtObject {
    property string viewJson: previewVariant("popup")
    property string placement: "x11"
    property string scenario: "popup"
    readonly property var status: JSON.parse(S.status(scenario))
    readonly property bool busy: status.busy
    readonly property string phase: status.phase
    readonly property string lastChecked: status.lastChecked
    property string staticJson: S.staticJson()
    property string cliVersion: "0.1.0"
    property bool trayAvailable: true
    signal detailsRequested(string selection)
    signal aboutRequested()
    signal popupRequested(int x, int y, string token)
    signal quitRequested()
    signal openExternalRequested(string url)
    function refresh() {}
    function uiReady() {}
    function markAsSeen() {}
    function copyReport() {}
    function openDetails(s) { detailsRequested(s); }
    function copyFindingJson(a, b) {}
    function showSettings() { detailsRequested(":settings"); }
    function showAbout() {}
    function setNotInstalledExpanded(b) { show(b ? "popup-expanded" : "popup"); }
    // The preview process has no Rust image provider, so use EntryIcon's monogram fallback.
    function previewVariant(name) {
        const data = JSON.parse(S.variant(name));
        function clearIconKeys(value) {
            if (Array.isArray(value)) {
                value.forEach(clearIconKeys);
            } else if (value && typeof value === "object") {
                if (typeof value.iconKey === "string")
                    value.iconKey = "";
                Object.keys(value).forEach(key => clearIconKeys(value[key]));
            }
        }
        clearIconKeys(data);
        return JSON.stringify(data);
    }
    function show(name) {
        scenario = name;
        viewJson = previewVariant(name);
        SettingsController.show(name);
        CollectorController.show(name);
    }
    function revealPath(p) {}
    function availableArea(x, y) { return Qt.rect(0, 0, 1920, 1080); }
    function setActivationToken(t) {}
    function copyDiagnostics() {}
    function quit() {}
}
