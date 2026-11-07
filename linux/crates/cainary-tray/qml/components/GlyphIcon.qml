import QtQuick
import QtQuick.Controls.impl

// A bundled monochrome icon from qml/icons, tinted like text so it follows the palette and the
// row's highlight. Sized in pixels so it matches the 20 px app icons beside it.
IconImage {
    id: root

    // The file name under qml/icons, without ".svg".
    property string glyph
    property int size: 16

    source: glyph.length > 0 ? Qt.resolvedUrl("../icons/" + glyph + ".svg") : ""
    sourceSize: Qt.size(size, size)
    width: size
    height: size
}
