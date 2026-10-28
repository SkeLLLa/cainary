import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import ua.SkeLLLa.cAInary
import "components"
import "components/style.js" as Style

// About cAInary.
ApplicationWindow {
    id: win

    // Parsed AppController.staticJson, set by Main.qml.
    property var st: null

    function present() {
        show();
        raise();
        requestActivate();
    }

    objectName: "about"
    palette.window: sys.window
    palette.windowText: sys.windowText
    palette.base: sys.base
    palette.alternateBase: sys.alternateBase
    palette.text: sys.text
    palette.button: sys.button
    palette.buttonText: sys.buttonText
    palette.highlight: sys.highlight
    palette.highlightedText: sys.highlightedText
    palette.mid: sys.mid
    palette.midlight: sys.midlight
    palette.dark: sys.dark
    palette.light: sys.light
    palette.shadow: sys.shadow
    palette.link: sys.link
    palette.toolTipBase: sys.toolTipBase
    palette.toolTipText: sys.toolTipText
    palette.placeholderText: Qt.alpha(sys.windowText, 0.6)
    title: qsTr("About cAInary")
    width: 420
    height: Math.min(content.implicitHeight + 48, 760)
    minimumWidth: 420
    maximumWidth: 420

    SystemColors { id: sys }

    Shortcut { sequences: ["Ctrl+W", "Esc"]; onActivated: win.close() }

    ScrollView {
        id: scroll
        anchors.fill: parent
        contentWidth: availableWidth

        ColumnLayout {
            id: content
            x: 24
            width: scroll.availableWidth - 48
            spacing: 10

            Image {
                source: "image://cainary-icon/app"
                sourceSize: Qt.size(128, 128)
                Layout.preferredWidth: 64
                Layout.preferredHeight: 64
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 24
                fillMode: Image.PreserveAspectFit
            }
            Label {
                text: "cAInary"
                font.pointSize: Application.font.pointSize * 1.6
                font.weight: Font.DemiBold
                Layout.alignment: Qt.AlignHCenter
            }
            Label {
                text: win.st ? win.st.about.description : ""
                wrapMode: Text.Wrap
                horizontalAlignment: Text.AlignHCenter
                Layout.fillWidth: true
            }

            GridLayout {
                columns: 2
                columnSpacing: 12
                rowSpacing: 2
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 6
                Label { text: qsTr("Version"); color: win.palette.placeholderText }
                Label { text: win.st ? win.st.build.version : "" }
                Label { text: qsTr("Commit"); color: win.palette.placeholderText }
                Label { text: win.st ? win.st.build.commit : "" }
                Label { text: qsTr("Built"); color: win.palette.placeholderText }
                Label { text: win.st ? win.st.build.built : "" }
                Label { text: qsTr("Source"); color: win.palette.placeholderText }
                Label {
                    text: "<a href=\"" + (win.st ? win.st.about.repo : "") + "\">" + (win.st ? win.st.about.repo : "") + "</a>"
                    textFormat: Text.StyledText
                    linkColor: win.palette.link
                    onLinkActivated: url => Style.openExternal(url)
                }
            }

            Label {
                text: win.st ? win.st.about.license : ""
                wrapMode: Text.Wrap
                font.pointSize: Application.font.pointSize * 0.85
                color: win.palette.placeholderText
                Layout.fillWidth: true
                Layout.topMargin: 8
            }
            Label {
                text: "<a href=\"" + (win.st ? win.st.about.licenseUrl : "") + "\">" + qsTr("Full license text") + "</a>"
                textFormat: Text.StyledText
                linkColor: win.palette.link
                font.pointSize: Application.font.pointSize * 0.85
                onLinkActivated: url => Style.openExternal(url)
            }

            MenuSeparator { Layout.fillWidth: true; padding: 0 }
            Label {
                text: qsTr("Support Ukraine")
                font.weight: Font.DemiBold
            }
            SupportLinks {
                support: win.st ? win.st.support : null
                Layout.fillWidth: true
            }
            Label {
                text: qsTr("Privacy tools")
                font.weight: Font.DemiBold
                Layout.topMargin: 6
            }
            SupportLinks {
                support: win.st ? win.st.privacy : null
                Layout.fillWidth: true
            }

            Button {
                text: qsTr("Copy diagnostics")
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 6
                onClicked: AppController.copyDiagnostics()
            }

            Label {
                text: win.st ? win.st.about.copyright : ""
                wrapMode: Text.Wrap
                font.pointSize: Application.font.pointSize * 0.85
                color: win.palette.placeholderText
                Layout.fillWidth: true
                Layout.topMargin: 6
                Layout.bottomMargin: 16
            }
        }
    }
}
