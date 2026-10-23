#!/bin/sh
# Render the QML windows offscreen against dev/SampleView.js without the Rust app.
# Usage: qml/dev/harness.sh [outdir]   (needs Qt's `qml` tool; PNGs land in outdir)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/cainary-qml-harness}
mod=$out/imports/ua/SkeLLLa/cAInary
rm -rf "$out"; mkdir -p "$mod"
cp -r "$here/.."/*.qml "$here/../components" "$mod/"
cp "$here/SampleView.js" "$mod/"
cp "$here/stubs/"*.qml "$here/stubs/qmldir" "$mod/"
(cd "$mod" && ls *.qml | grep -v '^\(AppController\|SettingsController\)' | sed 's/\(.*\)\.qml/\1 1.0 \1.qml/' >> qmldir)
cp "$here/Harness.qml" "$here/SampleView.js" "$out/"
cd "$out"
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software "${QML:-/usr/lib64/qt6/bin/qml}" -I "$out/imports" Harness.qml
