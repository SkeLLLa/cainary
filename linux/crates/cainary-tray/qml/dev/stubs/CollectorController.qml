pragma Singleton
import QtQuick
import "SampleView.js" as S

// Dev only: the collector bridge, fed from the scenario's sample in SampleView.js.
QtObject {
    property string viewJson: ""
    function show(name) { viewJson = S.collector(name); }
    function copyText(text) { console.info("copyText:", text); }
    function retry() {}
    function openPrivilegedPort() { console.info("openPrivilegedPort"); }
    function clear() {}
    function previewClaudeTrust() {}
    function checkHosts() {}
    function editHosts() {}
    function removeHostsLines() {}
    function applyClaudeTrust() {}
    function cancelClaudeTrustPreview() {}
    function undoClaudeTrust() {}
    function prepareCodexBundle() {}
    function undoCodexBundle() {}
}
