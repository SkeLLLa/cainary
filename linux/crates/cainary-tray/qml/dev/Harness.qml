import QtQuick
import QtQuick.Window
import ua.SkeLLLa.cAInary

// Dev only: shows each window, grabs PNGs, quits.
Item {
    id: root
    Main { id: app }

    function scenario(win, name, sel) {
        return { win: win, name: name, pre: () => {
            AppController.show(name);
            if (win === "details") app.details.showSelection(sel);
            else if (win === "settings") app.settings.present();
            else if (win === "about") app.about.present();
        } };
    }
    property var shots: [
        scenario("popup", "popup"),
        scenario("popup", "popup-expanded"),
        scenario("popup", "popup-failed"),
        scenario("popup", "popup-scanning"),
        scenario("popup", "popup-empty"),
        scenario("details", "details", ""),
        scenario("details", "details-changes", ":changes"),
        scenario("details", "details-sources", ":sources"),
        scenario("settings", "settings"),
        scenario("about", "about")
    ]
    property int i: 0
    Timer {
        interval: 600; running: true; repeat: true
        onTriggered: {
            const s = root.shots[root.i];
            const w = app[s.win];
            s.pre();
            w.show();
            w.requestActivate();
            // grab after the pre() takes effect
            Qt.callLater(() => {
                const item = s.win === "popup" ? w.contentItem : w.contentItem.children[0];
                item.grabToImage(r => { r.saveToFile("shot-" + s.name + ".png"); });
                if (w.header)
                    w.header.grabToImage(r => { r.saveToFile("shot-" + s.name + "-header.png"); });
            });
            root.i++;
            if (root.i >= root.shots.length) { running = false; quitTimer.start(); }
        }
    }
    Timer { id: quitTimer; interval: 1500; onTriggered: Qt.quit() }
}
