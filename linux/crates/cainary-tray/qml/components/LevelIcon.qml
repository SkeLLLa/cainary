import QtQuick
import "style.js" as Style

// The level symbol, drawn so it needs no icon theme: high is an octagon, medium a triangle,
// low a circle with "!", opted-out a circle with a bar, ok a check, not-installed a dashed
// circle, unknown a circled "?". Shape differs per level so colour is never the only signal.
Item {
    id: root

    property string level: "unknown"
    property int size: 20

    readonly property bool dark: palette.window.hslLightness < 0.5
    readonly property color fill: {
        if (level === "not-installed")
            return Qt.alpha(palette.windowText, 0.45);
        if (level === "unknown")
            return Qt.alpha(palette.windowText, 0.7);
        return Style.levelColor(level, dark, palette.windowText);
    }

    implicitWidth: size
    implicitHeight: size
    Accessible.role: Accessible.Graphic
    Accessible.name: level

    onLevelChanged: canvas.requestPaint()
    onFillChanged: canvas.requestPaint()
    onSizeChanged: canvas.requestPaint()

    Canvas {
        id: canvas
        anchors.fill: parent
        onPaint: {
            const ctx = getContext("2d");
            ctx.reset();
            const s = width;
            const c = s / 2;
            const knock = root.palette.window;
            ctx.fillStyle = root.fill;
            ctx.strokeStyle = root.fill;
            ctx.lineCap = "round";
            ctx.lineJoin = "round";

            function polygon(points) {
                ctx.beginPath();
                for (let i = 0; i < points.length; ++i) {
                    if (i === 0)
                        ctx.moveTo(points[i][0], points[i][1]);
                    else
                        ctx.lineTo(points[i][0], points[i][1]);
                }
                ctx.closePath();
            }
            function disc() {
                ctx.beginPath();
                ctx.arc(c, c, s * 0.46, 0, Math.PI * 2);
                ctx.fill();
            }
            function mark(x, top, bottom) {
                ctx.strokeStyle = knock;
                ctx.fillStyle = knock;
                ctx.lineWidth = s * 0.11;
                ctx.beginPath();
                ctx.moveTo(x, top);
                ctx.lineTo(x, bottom);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(x, bottom + s * 0.15, s * 0.065, 0, Math.PI * 2);
                ctx.fill();
            }

            switch (root.level) {
            case "high": {
                const r = s * 0.48;
                const pts = [];
                for (let i = 0; i < 8; ++i) {
                    const a = Math.PI / 8 + i * Math.PI / 4;
                    pts.push([c + r * Math.cos(a) / Math.cos(Math.PI / 8), c + r * Math.sin(a) / Math.cos(Math.PI / 8)]);
                }
                polygon(pts);
                ctx.fill();
                mark(c, s * 0.24, s * 0.55);
                break;
            }
            case "medium":
                polygon([[c, s * 0.06], [s * 0.96, s * 0.9], [s * 0.04, s * 0.9]]);
                ctx.lineWidth = s * 0.1;
                ctx.fill();
                ctx.stroke();
                mark(c, s * 0.38, s * 0.62);
                break;
            case "low":
                disc();
                mark(c, s * 0.25, s * 0.54);
                break;
            case "opted-out":
                disc();
                ctx.strokeStyle = knock;
                ctx.lineWidth = s * 0.12;
                ctx.beginPath();
                ctx.moveTo(s * 0.28, c);
                ctx.lineTo(s * 0.72, c);
                ctx.stroke();
                break;
            case "ok":
                disc();
                ctx.strokeStyle = knock;
                ctx.lineWidth = s * 0.11;
                ctx.beginPath();
                ctx.moveTo(s * 0.28, s * 0.52);
                ctx.lineTo(s * 0.44, s * 0.68);
                ctx.lineTo(s * 0.73, s * 0.34);
                ctx.stroke();
                break;
            case "not-installed":
                ctx.lineWidth = s * 0.09;
                ctx.setLineDash([s * 0.12, s * 0.1]);
                ctx.beginPath();
                ctx.arc(c, c, s * 0.42, 0, Math.PI * 2);
                ctx.stroke();
                break;
            default:
                ctx.lineWidth = s * 0.08;
                ctx.beginPath();
                ctx.arc(c, c, s * 0.42, 0, Math.PI * 2);
                ctx.stroke();
                ctx.font = "bold " + Math.round(s * 0.6) + "px sans-serif";
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillText("?", c, c + s * 0.04);
                break;
            }
        }
    }
}
