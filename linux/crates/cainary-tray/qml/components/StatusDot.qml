import QtQuick
import "style.js" as Style

// A live source's state: grey off or stopped, amber starting, green listening, red failed.
Rectangle {
    id: root

    property string sourceState: "off"
    property int size: 8
    readonly property bool dark: palette.window.hslLightness < 0.5

    implicitWidth: size
    implicitHeight: size
    radius: size / 2
    color: sourceState === "listening" ? Style.levelColor("ok", dark, palette.windowText)
         : sourceState === "starting" ? Style.levelColor("low", dark, palette.windowText)
         : sourceState === "failed" ? Style.levelColor("high", dark, palette.windowText)
         : Qt.alpha(palette.windowText, 0.35)
}
