import QtQuick
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "SampleView.js" as S

// Dev only: renders the fixtures::scenarios() from SampleView.js without the Rust app.
// Arguments after `--`: scenario name filters (substring match; none = all). `--live` shows the
// first match and stays open (for qmlpreview hot reload) instead of grabbing PNGs and quitting.
Item {
    id: root
    Main { id: app }

    readonly property var args: {
        const a = Qt.application.arguments;
        const i = a.indexOf("--");
        return i < 0 ? [] : a.slice(i + 1);
    }
    readonly property bool live: args.indexOf("--live") >= 0
    readonly property var filters: args.filter(x => !x.startsWith("--"))
    readonly property var shots: S.scenarios.filter(s =>
        filters.length === 0 || filters.some(f => s.name.indexOf(f) >= 0))
    property int i: 0

    function open(s) {
        AppController.show(s.name);
        const w = app[s.window];
        if (s.window === "details")
            w.showSelection(s.selection);
        else if (s.window === "about")
            w.present();
        w.show();
        w.requestActivate();
        return w;
    }

    // An ApplicationWindow's root item has no QML engine to grab with, so the header, content
    // and footer are grabbed one by one and stacked in `sheet`. A grab is opaque black where the
    // item is transparent, so each part gets the window color under it while it is grabbed.
    property var pending: []
    function grab(w, name, done) {
        // The largest child of the (engine-less) content item stands for the content.
        const body = Array.from(w.contentItem.children).filter(c => c.visible)
            .reduce((a, c) => !a || c.width * c.height > a.width * a.height ? c : a, null);
        const parts = [w.header, body, w.footer].filter(p => p && p.visible && p.height > 0);
        const color = w.palette ? w.palette.window : w.color;
        const results = [];
        const next = () => {
            if (results.length === parts.length) {
                sheet.width = w.width;
                parts_.model = results.map(r => r.url);
                root.pending = results;     // keeps the grab URLs alive until the sheet is drawn
                sheetTimer.name = name;
                sheetTimer.size = w.width + "x" + w.height;
                sheetTimer.done = done;
                sheetWindow.visible = true;
                sheetTimer.start();
                return;
            }
            const part = parts[results.length];
            const under = underlay.createObject(part, { color: color });
            if (!part.grabToImage(r => { under.destroy(); results.push(r); next(); })) {
                console.warn("couldn't grab", name);
                under.destroy();
                done();
            }
        };
        next();
    }
    Component {
        id: underlay
        Rectangle { anchors.fill: parent; z: -1000 }
    }

    Window {
        id: sheetWindow
        width: 1600; height: 1200
        visible: false
        flags: Qt.Tool
        Column {
            id: sheet
            Repeater {
                id: parts_
                Image { required property string modelData; source: modelData; cache: false }
            }
        }
    }
    Timer {
        id: sheetTimer
        property string name
        property string size
        property var done
        interval: 150
        onTriggered: sheet.grabToImage(r => {
            r.saveToFile(name + ".png");
            console.log("shot", name + ".png", size);
            sheetWindow.visible = false;
            done();
        })
    }

    Component.onCompleted: {
        if (shots.length === 0) {
            console.warn("no scenario matches", filters, "; known:", S.scenarios.map(s => s.name).join(" "));
            Qt.exit(2);
        } else if (live) {
            open(shots[0]);
        } else {
            Qt.callLater(shoot);
        }
    }

    // One scenario at a time: open, let it settle, grab, then the next.
    function shoot() {
        if (root.i >= root.shots.length) {
            quitTimer.start();
            return;
        }
        const s = root.shots[root.i++];
        const w = root.open(s);
        settle.after = () => root.grab(w, s.name, () => { w.hide(); root.shoot(); });
        settle.start();
    }
    Timer {
        id: settle
        property var after
        interval: 300
        onTriggered: after()
    }
    Timer { id: quitTimer; interval: 600; onTriggered: Qt.quit() }
}
