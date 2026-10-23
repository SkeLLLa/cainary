import QtQuick
import QtQuick.Controls
import QtQuick.Window

// The app icon from the cainary-icon provider, else a monogram tile. Monitoring entries
// (device, device-management, network-proxy, shield) are drawn here, as macOS draws SF symbols.
Item {
    id: root

    property string iconKey
    property string name
    property bool installed: true
    property int size: 24

    readonly property bool drawn: ["device", "device-management", "network-proxy", "shield"].indexOf(iconKey) >= 0
    // The provider answers with a transparent 1x1 image when no theme icon matches.
    readonly property bool hasImage: !drawn && image.status === Image.Ready
                                     && image.implicitWidth > 1 && image.implicitHeight > 1

    implicitWidth: size
    implicitHeight: size
    opacity: installed ? 1 : 0.4

    Image {
        id: image
        anchors.fill: parent
        source: root.iconKey.length > 0 && !root.drawn ? "image://cainary-icon/" + root.iconKey : ""
        sourceSize: Qt.size(root.size * 2, root.size * 2)
        fillMode: Image.PreserveAspectFit
        visible: root.hasImage
    }
    Canvas {
        id: glyph
        anchors.fill: parent
        visible: root.drawn
        readonly property color ink: root.palette.windowText
        onInkChanged: requestPaint()
        onWidthChanged: requestPaint()
        onPaint: {
            const ctx = getContext("2d");
            ctx.reset();
            const s = width;
            ctx.strokeStyle = ink;
            ctx.fillStyle = ink;
            ctx.lineWidth = s * 0.08;
            ctx.lineJoin = "round";
            ctx.lineCap = "round";
            function rect(x, y, w, h) {
                ctx.beginPath();
                ctx.rect(x * s, y * s, w * s, h * s);
                ctx.stroke();
            }
            switch (root.iconKey) {
            case "device": // laptop
                rect(0.18, 0.2, 0.64, 0.46);
                ctx.beginPath();
                ctx.moveTo(0.06 * s, 0.78 * s);
                ctx.lineTo(0.94 * s, 0.78 * s);
                ctx.stroke();
                break;
            case "device-management": // building
                rect(0.22, 0.12, 0.56, 0.76);
                for (let r = 0; r < 3; ++r)
                    for (let c = 0; c < 2; ++c)
                        ctx.fillRect((0.34 + c * 0.2) * s, (0.24 + r * 0.17) * s, 0.08 * s, 0.08 * s);
                break;
            case "network-proxy": // three linked nodes
                ctx.beginPath();
                ctx.moveTo(0.5 * s, 0.22 * s);
                ctx.lineTo(0.22 * s, 0.76 * s);
                ctx.lineTo(0.78 * s, 0.76 * s);
                ctx.closePath();
                ctx.stroke();
                for (const p of [[0.5, 0.22], [0.22, 0.76], [0.78, 0.76]]) {
                    ctx.beginPath();
                    ctx.arc(p[0] * s, p[1] * s, 0.09 * s, 0, Math.PI * 2);
                    ctx.fill();
                }
                break;
            default: // shield, left half filled
                ctx.beginPath();
                ctx.moveTo(0.5 * s, 0.1 * s);
                ctx.lineTo(0.84 * s, 0.22 * s);
                ctx.lineTo(0.84 * s, 0.5 * s);
                ctx.quadraticCurveTo(0.84 * s, 0.76 * s, 0.5 * s, 0.9 * s);
                ctx.quadraticCurveTo(0.16 * s, 0.76 * s, 0.16 * s, 0.5 * s);
                ctx.lineTo(0.16 * s, 0.22 * s);
                ctx.closePath();
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(0.5 * s, 0.1 * s);
                ctx.lineTo(0.16 * s, 0.22 * s);
                ctx.lineTo(0.16 * s, 0.5 * s);
                ctx.quadraticCurveTo(0.16 * s, 0.76 * s, 0.5 * s, 0.9 * s);
                ctx.closePath();
                ctx.fill();
                break;
            }
        }
    }
    Rectangle {
        anchors.fill: parent
        visible: !root.hasImage && !root.drawn
        radius: root.size * 0.22
        color: root.iconKey === "claude" ? "#D97757" : root.palette.mid
        Label {
            anchors.centerIn: parent
            text: root.name.length > 0 ? root.name.charAt(0).toUpperCase() : "?"
            font.pixelSize: Math.round(root.size * 0.55)
            font.weight: Font.DemiBold
            color: root.iconKey === "claude" ? root.palette.window : root.palette.windowText
        }
    }
}
