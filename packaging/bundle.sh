#!/bin/sh
# Assemble dist/cAInary.app and a distributable zip from the built app and the Rust helper.
# Run it through `make bundle`, which builds both inputs first.
#
# Environment:
#   APP_BIN  SwiftUI app binary (default: target/macos/cAInary)
#   CORE     cainary helper binary (default: target/debug/cainary)
#   OUT      output directory (default: dist)
#   CODESIGN_IDENTITY  Developer ID identity for releases (default: empty, ad-hoc signature)
set -eu

cd "$(dirname "$0")/.."

APP_BIN="${APP_BIN:-target/macos/cAInary}"
CORE="${CORE:-target/debug/cainary}"
OUT="${OUT:-dist}"

# --- 1. Version: Cargo.toml is the single source; a stale helper must not slip through ----
# shellcheck source=/dev/null
. packaging/ci/deps-lib.sh
VERSION="$(toml_get Cargo.toml workspace package version)" || VERSION=""
[ -n "$VERSION" ] || { echo "error: no [workspace.package] version in Cargo.toml" >&2; exit 1; }
for f in "$APP_BIN" "$CORE"; do
    [ -x "$f" ] || { echo "error: $f is missing or not executable" >&2; exit 1; }
done
CORE_VERSION="$("$CORE" --version)"
if [ "$CORE_VERSION" != "cainary $VERSION" ]; then
    echo "error: $CORE reports '$CORE_VERSION', expected 'cainary $VERSION' (stale helper?)" >&2
    exit 1
fi

# --- 2. Lay out the bundle ---------------------------------------------------
APP="$OUT/cAInary.app"
ZIP="$OUT/cAInary-$VERSION-macos.zip"
rm -rf "$APP"
rm -f "$ZIP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources"
cp "$APP_BIN" "$APP/Contents/MacOS/cAInary"
cp "$CORE" "$APP/Contents/Helpers/cainary"
# GPL text ships with the app; the About panel points at it.
cp COPYING "$APP/Contents/Resources/COPYING"

# --- 3. Stamp and lint the plist ---------------------------------------------
COMMIT="$(git rev-parse --verify -q HEAD 2> /dev/null || echo unknown)"
if [ -n "$(git status --porcelain 2> /dev/null)" ]; then COMMIT="$COMMIT-dirty"; fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sed -e "s/__VERSION__/$VERSION/g" -e "s/__COMMIT__/$COMMIT/g" -e "s/__BUILD_DATE__/$BUILD_DATE/g" \
    macos/Info.plist > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist"

# --- 4. Sign inside out (ad hoc unless CODESIGN_IDENTITY is set), then verify -
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
    # Notarization needs a secure timestamp.
    set -- --sign "$CODESIGN_IDENTITY" --timestamp
else
    set -- --sign -
fi
codesign --force --options runtime "$@" "$APP/Contents/Helpers/cainary"
codesign --force --options runtime "$@" "$APP"
codesign --verify --strict "$APP"

# --- 5. Zip (--norsrc/--noextattr keep AppleDouble ._ files out) -------------
ditto -c -k --norsrc --noextattr --keepParent "$APP" "$ZIP"

echo "App: $APP"
echo "Zip: $ZIP"
