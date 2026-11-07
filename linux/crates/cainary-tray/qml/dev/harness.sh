#!/bin/sh
# Render the QML windows offscreen against dev/SampleView.js without the Rust app.
# Usage: qml/dev/harness.sh [-o outdir] [--live] [--width=N] [--height=N] [--dark] [scenario-filter...]
#   QT_QUICK_CONTROLS_STYLE=org.kde.desktop renders with Breeze instead of the default style.
#   Filters are substrings of fixtures::scenarios() names (none = all); PNGs land in outdir
#   (default /tmp/cainary-qml-harness). --live opens the first match in a real window under
#   qmlpreview (hot reload on save) when it is installed, else under plain qml.
# The module is symlinked to the sources, so edits show up without re-running this script.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/.." && pwd)
out=/tmp/cainary-qml-harness
live=
if [ "${1:-}" = "-o" ]; then out=$2; shift 2; fi
for a in "$@"; do [ "$a" = "--live" ] && live=1; done
mkdir -p "$out"
out=$(cd "$out" && pwd)
mod=$out/imports/ua/SkeLLLa/cAInary
rm -rf "$out/imports" "$out"/*.png
mkdir -p "$mod"
for f in "$src"/*.qml "$src/components" "$src/icons" "$here/SampleView.js" "$here/stubs/"*.qml; do
    ln -s "$f" "$mod/"
done
cp "$here/stubs/qmldir" "$mod/qmldir"
for f in "$src"/*.qml; do
    n=$(basename "$f" .qml)
    echo "$n 1.0 $n.qml" >> "$mod/qmldir"
done
ln -sf "$here/Harness.qml" "$out/Harness.qml"
ln -sf "$here/SampleView.js" "$out/SampleView.js"
bin=${QT_BIN:-/usr/lib64/qt6/bin}
# Qt logs to the journal when stderr is not a terminal; keep warnings in the output.
export QT_FORCE_STDERR_LOGGING=1 QT_LOGGING_RULES="${QT_LOGGING_RULES:-qml.debug=true}"
cd "$out"
if [ -n "$live" ]; then
    if [ -x "$bin/qmlpreview" ]; then
        exec "$bin/qmlpreview" "$bin/qml" -I "$out/imports" Harness.qml -- "$@"
    fi
    exec "$bin/qml" -I "$out/imports" Harness.qml -- "$@"
fi
QT_QPA_PLATFORM=offscreen exec "$bin/qml" -I "$out/imports" Harness.qml -- "$@"
