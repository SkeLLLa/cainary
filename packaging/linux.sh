#!/bin/sh
# Build the Linux release artifacts from an already-built CLI and tray app. Run it through
# `make linux`, which builds both first.
#
# Usage:
#   packaging/linux.sh --version V --arch x86_64|aarch64 --cli PATH --tray PATH \
#       [--formats tar,deb,rpm] [--out dist/]
#
#   --cli    the static musl `cainary` (target/<arch>-unknown-linux-musl/release/cainary)
#   --tray   `cainary-tray` (linux/target/release/cainary-tray)
#
# Artifacts (docs/distribution.md):
#   tar  cainary-V-linux-ARCH.tar.gz   bin/, share/, install-user.sh, linux-assets.txt, README.md, LICENSE
#   deb  cainary_V_amd64|arm64.deb     cargo-deb --no-build
#   rpm  cainary-V-1.ARCH.rpm          cargo-generate-rpm
#
# What is installed is listed in packaging/linux-assets.txt. The deb and rpm metadata live in linux/crates/cainary-tray/Cargo.toml. Their assets are all
# under target/<triple>/release/, which this script points at its staging tree: the packagers get
# CARGO_TARGET_DIR / --target-dir = $CAINARY_STAGE/target, so all three formats ship the same files.
#
# Environment:
#   CAINARY_STAGE  staging directory (default: a fresh temporary directory, removed on exit)
#   CAINARY_LINUX  the linux workspace directory (default: linux)
#   SOURCE_DATE_EPOCH  file times in the tarball and rpm (default: the HEAD commit time)
set -eu

cd "$(dirname "$0")/.."

usage() {
    echo "usage: $0 --version V --arch x86_64|aarch64 --cli PATH --tray PATH [--formats tar,deb,rpm] [--out DIR]" >&2
    exit 2
}

VERSION=""
ARCH=""
CLI=""
TRAY=""
FORMATS="tar,deb,rpm"
OUT="dist"
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || usage
    case "$1" in
        --version) VERSION="$2" ;;
        --arch) ARCH="$2" ;;
        --cli) CLI="$2" ;;
        --tray) TRAY="$2" ;;
        --formats) FORMATS="$2" ;;
        --out) OUT="$2" ;;
        *) usage ;;
    esac
    shift 2
done

case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "error: --version must be MAJOR.MINOR.PATCH, got '$VERSION'" >&2; usage ;;
esac
case "$ARCH" in
    x86_64) DEB_ARCH=amd64 ;;
    aarch64) DEB_ARCH=arm64 ;;
    *) echo "error: --arch must be x86_64 or aarch64, got '$ARCH'" >&2; usage ;;
esac
if [ -z "$CLI" ] || [ -z "$TRAY" ]; then usage; fi

DO_TAR=0
DO_DEB=0
DO_RPM=0
for f in $(echo "$FORMATS" | tr ',' ' '); do
    case "$f" in
        tar) DO_TAR=1 ;;
        deb) DO_DEB=1 ;;
        rpm) DO_RPM=1 ;;
        *) echo "error: unknown format '$f' (tar, deb, rpm)" >&2; exit 2 ;;
    esac
done
[ $((DO_TAR + DO_DEB + DO_RPM)) -gt 0 ] || { echo "error: --formats is empty" >&2; exit 2; }

LINUX="$(cd "${CAINARY_LINUX:-linux}" && pwd)"
DATA="$LINUX/data"

# --- 1. Versions: both binaries must report V; a stale build must not slip through ----------
for f in "$CLI" "$TRAY"; do
    if [ ! -f "$f" ] || [ ! -x "$f" ]; then
        echo "error: $f is missing or not executable" >&2
        exit 1
    fi
done
check_version() {
    got="$("$1" --version)" || { echo "error: '$1 --version' failed" >&2; exit 1; }
    if [ "$got" != "$2 $VERSION" ]; then
        echo "error: $1 reports '$got', expected '$2 $VERSION' (stale build?)" >&2
        exit 1
    fi
}
check_version "$CLI" cainary
check_version "$TRAY" cainary-tray

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2> /dev/null || date +%s)"
fi
export SOURCE_DATE_EPOCH
if [ -z "${CAINARY_GIT_SHA:-}" ]; then
    CAINARY_GIT_SHA="$(git rev-parse --short HEAD 2> /dev/null || echo unknown)"
fi
if [ -z "${CAINARY_BUILD_DATE:-}" ]; then
    CAINARY_BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2> /dev/null || echo unknown)"
fi
export CAINARY_GIT_SHA CAINARY_BUILD_DATE

# --- 2. Stage the install tree ---------------------------------------------------------------
if [ -n "${CAINARY_STAGE:-}" ]; then
    STAGE="$CAINARY_STAGE"
    mkdir -p "$STAGE"
else
    STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cainary-stage.XXXXXX")"
    trap 'rm -rf "$STAGE"' EXIT
fi
STAGE="$(cd "$STAGE" && pwd)"
CAINARY_STAGE="$STAGE"
export CAINARY_STAGE
NAME="cainary-$VERSION-linux-$ARCH"
TREE="$STAGE/$NAME"
rm -rf "$TREE" "$STAGE/target"

# Every file comes from packaging/linux-assets.txt: `<mode> <staged path> <destination>`.
install -d "$TREE"
while read -r mode path _dest; do
    case "$mode" in "" | "#"*) continue ;; esac
    case "$path" in
        bin/cainary) from="$CLI" ;;
        bin/cainary-tray) from="$TRAY" ;;
        share/icons/*) from="$DATA/icons/${path#share/icons/}" ;;
        share/*/*) from="$DATA/${path##*/}" ;;
        LICENSE) from=COPYING ;;
        README.md) from=README.md ;;
        *) echo "error: linux-assets.txt: no source for '$path'" >&2; exit 1 ;;
    esac
    [ -f "$from" ] || { echo "error: $from (for $path) is missing" >&2; exit 1; }
    install -D -m "$mode" "$from" "$TREE/$path"
done < packaging/linux-assets.txt
install -m 644 packaging/linux-assets.txt "$TREE/linux-assets.txt"
install -m 755 packaging/dist/install-user.sh "$TREE/install-user.sh"
# cargo-deb and cargo-generate-rpm retain staged file times; normalize them to the release commit.
find "$TREE" -exec touch -d "@$SOURCE_DATE_EPOCH" {} +

# The packagers read target/<triple>/release/...; point that at the tree.
TRIPLE="$ARCH-unknown-linux-gnu"
mkdir -p "$STAGE/target/$TRIPLE"
ln -s "../../$NAME" "$STAGE/target/$TRIPLE/release"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ARTIFACTS=""

# --- 3. Formats ------------------------------------------------------------------------------
if [ "$DO_TAR" -eq 1 ]; then
    TGZ="$OUT/$NAME.tar.gz"
    # GNU tar (every target distro): stable order, owner and times, so rebuilds are identical.
    (cd "$STAGE" && tar --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime="@$SOURCE_DATE_EPOCH" -cf - "$NAME") | gzip -9n > "$TGZ"
    ARTIFACTS="$ARTIFACTS $TGZ"
fi

if [ "$DO_DEB" -eq 1 ]; then
    DEB="$OUT/cainary_${VERSION}_$DEB_ARCH.deb"
    # --deb-version: exactly V, no -1 revision. --no-strip: the release profiles strip already,
    # and the deb ships the very bytes that the tarball and rpm ship.
    (cd "$LINUX" && CARGO_TARGET_DIR="$CAINARY_STAGE/target" cargo deb --manifest-path Cargo.toml \
        -p cainary-tray --no-build --no-strip --target "$TRIPLE" \
        --deb-version "$VERSION" --output "$DEB" >&2)
    ARTIFACTS="$ARTIFACTS $DEB"
fi

if [ "$DO_RPM" -eq 1 ]; then
    RPM="$OUT/cainary-$VERSION-1.$ARCH.rpm"
    # cargo-generate-rpm has no --manifest-path: -p is the crate directory, relative to the workspace.
    (cd "$LINUX" && CARGO_TARGET_DIR="$CAINARY_STAGE/target" cargo generate-rpm \
        -p crates/cainary-tray --target "$TRIPLE" --target-dir "$CAINARY_STAGE/target" --arch "$ARCH" \
        --output "$RPM" >&2)
    ARTIFACTS="$ARTIFACTS $RPM"
fi

for a in $ARTIFACTS; do
    echo "$a"
done
