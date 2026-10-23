pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"

// Root of the QML app. Load it with QQmlApplicationEngine (module URI ua.SkeLLLa.cAInary,
// resource path qml/Main.qml); it has no visible item of its own.
//
// Four top-level windows are created eagerly as children of this root, all hidden. Find them
// by objectName (QWindow::objectName among QGuiApplication::allWindows()):
//  - "popup"    360 px wide, hidden until a tray click. Frameless Qt.Tool window that hides
//               itself on Esc and focus loss; with placement "decorated" an ordinary window.
//               setNotInstalledExpanded(bool).
//  - "details"  ordinary ApplicationWindow, 780x560 (min 640x440). showSelection(sel) where
//               sel is an entry id, ":changes", ":sources" or "" for the default.
//  - "settings" cAInary Settings, 480 wide. present().
//  - "about"    About cAInary, 420 wide. present().
//
// Rust drives everything through AppController signals: popupRequested toggles the popup
// (positioning it itself on X11, after Rust attached/placed the layer surface on Wayland).
QtObject {
    id: root

    readonly property Window popup: popupWindow
    readonly property Window details: detailsWindow
    readonly property Window settings: settingsWindow
    readonly property Window about: aboutWindow

    property ViewData data: ViewData {}

    property Popup popupWindow: Popup {
        view: root.data.view
        st: root.data.st
    }
    property Details detailsWindow: Details {
        view: root.data.view
        st: root.data.st
    }
    property SettingsWindow settingsWindow: SettingsWindow {
        st: root.data.st
    }
    property AboutWindow aboutWindow: AboutWindow {
        st: root.data.st
    }

    property Connections controllerConnections: Connections {
        target: AppController
        function onDetailsRequested(selection) {
            root.detailsWindow.showSelection(selection);
        }
        function onSettingsRequested() {
            root.settingsWindow.present();
        }
        function onAboutRequested() {
            root.aboutWindow.present();
        }
        function onPopupRequested(x, y, token) {
            root.togglePopup(x, y, token);
        }
        function onQuitRequested() {
            Qt.quit();
        }
        function onOpenExternalRequested(url) {
            Qt.openUrlExternally(url);
        }
    }

    // The token is consumed when the popup maps; it must not outlive that (children inherit it).
    property Timer tokenClear: Timer {
        interval: 1500
        onTriggered: AppController.setActivationToken("")
    }

    function togglePopup(x, y, token) {
        const p = popupWindow;
        if (p.visible) {
            p.hide();
            return;
        }
        // The click that closed the popup by taking its focus must not reopen it.
        if (Date.now() - p.hiddenAt < 300)
            return;
        if (AppController.placement === "x11")
            p.placeNear(x, y);
        AppController.setActivationToken(token);
        tokenClear.restart();
        p.show();
        // A layer surface is activated by the xdg-activation token at map time; a second
        // activation request could consume the token first.
        if (AppController.placement !== "layer-shell") {
            p.raise();
            p.requestActivate();
        }
    }

    // Rust waits for this (and for both controllers to exist) before it sends anything.
    Component.onCompleted: {
        void SettingsController.notificationsAvailable;
        AppController.uiReady();
    }
}
