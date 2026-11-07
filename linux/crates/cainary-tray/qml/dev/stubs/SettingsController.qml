pragma Singleton
import QtQuick
import ua.SkeLLLa.cAInary
import "SampleView.js" as S

QtObject {
    property bool notifications: true
    property string refresh: "1h"
    property bool launchAtLogin: false
    property bool startMinimized: true
    property bool closeToTray: true
    property string iconStyle: "monochrome"
    property string launchAtLoginError: "Couldn't write the autostart file"
    property bool notificationsAvailable: false
    property bool fileChooserAvailable: false
    property string loadError: ""
    property string collectorJson: "{}"
    function show(name) { collectorJson = S.collectorSettings(name); }
    function setCollector(json) { collectorJson = json; }
    function chooseCollectorLogFile() {}
    function setSidebarCollapsed(section, collapsed) {
        const view = JSON.parse(AppController.viewJson);
        if (section === "scan")
            view.scanCollapsed = collapsed;
        else if (section === "live")
            view.liveCollapsed = collapsed;
        AppController.viewJson = JSON.stringify(view);
    }
}
