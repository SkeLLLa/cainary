pragma Singleton
import QtQuick
import "SampleView.js" as S

QtObject {
    property string viewJson: S.variant("")
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
    signal settingsRequested()
    signal aboutRequested()
    signal popupRequested(int x, int y, string token)
    signal quitRequested()
    signal openExternalRequested(string url)
    function refresh() {}
    function uiReady() {}
    function markAsSeen() {}
    function copyReport() {}
    function openDetails(s) {}
    function copyFindingJson(a, b) {}
    function showSettings() {}
    function showAbout() {}
    function setNotInstalledExpanded(b) { show(b ? "popup-expanded" : "popup"); }
    function show(name) { scenario = name; viewJson = S.variant(name); }
    function revealPath(p) {}
    function availableArea(x, y) { return Qt.rect(0, 0, 1920, 1080); }
    function setActivationToken(t) {}
    function copyDiagnostics() {}
    function quit() {}
}
