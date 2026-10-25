#!/bin/sh
# Assemble dist/cAInary.app and a distributable zip from the built app and the Rust helper.
# Run it through `make bundle`, which builds both inputs first.
#
# Environment:
#   APP_BIN  SwiftUI app binary (default: target/macos/cAInary)
#   CORE     cainary helper binary (default: target/debug/cainary)
#   OUT      output directory (default: dist)
#   CODESIGN_IDENTITY  SHA-1 of a self-signed code-signing certificate in the keychain search
#                      list (default: empty, ad-hoc signature). See docs/distribution.md#signing.
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

# Icon: PNG -> iconset -> icns. The PNG is rendered from resources/icons/cainary-macos.svg.
SRC_ICON="resources/icons/cainary-1024.png"
ICONSET="$(mktemp -d "${TMPDIR:-/tmp}/cainary-icon.XXXXXX")/AppIcon.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$SRC_ICON" --out "$ICONSET/icon_${size}x${size}.png" > /dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$SRC_ICON" --out "$ICONSET/icon_${size}x${size}@2x.png" > /dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$(dirname "$ICONSET")"

# --- 3. Stamp and lint the plist ---------------------------------------------
COMMIT="$(git rev-parse --verify -q HEAD 2> /dev/null || echo unknown)"
if [ -n "$(git status --porcelain 2> /dev/null)" ]; then COMMIT="$COMMIT-dirty"; fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sed -e "s/__VERSION__/$VERSION/g" -e "s/__COMMIT__/$COMMIT/g" -e "s/__BUILD_DATE__/$BUILD_DATE/g" \
    macos/Info.plist > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist"

# --- 4. Sign inside out (ad hoc unless CODESIGN_IDENTITY is set), then verify -
# A certificate signature makes the designated requirement `identifier … and certificate leaf =
# H"<sha1>"`, which stays the same across builds, so TCC and login-item grants survive updates.
# An ad-hoc one pins the cdhash and changes with every build.
BUNDLE_ID="ua.SkeLLLa.cAInary"
HELPER_ID="$BUNDLE_ID.helper"
SIGN_ID="${CODESIGN_IDENTITY:-}"
if [ -n "$SIGN_ID" ]; then
    case "$SIGN_ID" in
        *[!0-9A-Fa-f]*) SIGN_ID="" ;;
    esac
    if [ "${#SIGN_ID}" -ne 40 ]; then
        echo "error: CODESIGN_IDENTITY must be the certificate's 40-digit SHA-1" >&2
        exit 1
    fi
    SIGN_ID="$(printf %s "$SIGN_ID" | tr '[:lower:]' '[:upper:]')"
else
    SIGN_ID="-"
fi
sign() { # <identifier> <path>
    if [ "$SIGN_ID" = "-" ]; then
        codesign --force --options runtime --timestamp=none --sign - -i "$1" "$2"
    else
        # The requirement is spelled out rather than left to codesign's default, so it can't drift.
        codesign --force --options runtime --timestamp=none --sign "$SIGN_ID" -i "$1" \
            -r="designated => identifier \"$1\" and certificate leaf = H\"$SIGN_ID\"" "$2"
    fi
}
sign "$HELPER_ID" "$APP/Contents/Helpers/cainary"
sign "$BUNDLE_ID" "$APP"
codesign --verify --strict "$APP"
# Fail unless both the signature and the designated requirement pin this identifier and leaf
# (catches a wrong key, or a requirement that fell back to the cdhash).
check_pinned() { # <identifier> <path>
    codesign --verify --strict -R="=identifier \"$1\" and certificate leaf = H\"$SIGN_ID\"" "$2"
    codesign -d -r- "$2" 2>&1 | grep -qi "identifier \"$1\" and certificate leaf = H\"$SIGN_ID\"" || {
        echo "error: the designated requirement of $2 does not pin leaf $SIGN_ID" >&2
        exit 1
    }
}
if [ "$SIGN_ID" != "-" ]; then
    check_pinned "$BUNDLE_ID" "$APP"
    check_pinned "$HELPER_ID" "$APP/Contents/Helpers/cainary"
fi

# --- 5. Zip (--norsrc/--noextattr keep AppleDouble ._ files out) -------------
ditto -c -k --norsrc --noextattr --keepParent "$APP" "$ZIP"

echo "App: $APP"
echo "Zip: $ZIP"
