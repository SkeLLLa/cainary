import QtQuick
import ua.SkeLLLa.cAInary
import "style.js" as Style

// The parsed view model. `view` follows AppController.viewJson, `st` follows staticJson;
// both are null until the controller has published them.
QtObject {
    readonly property var view: Style.parse(AppController.viewJson)
    readonly property var st: Style.parse(AppController.staticJson)
}
