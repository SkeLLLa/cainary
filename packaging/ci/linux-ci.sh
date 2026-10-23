#!/bin/sh
# The Linux CI steps that run inside a distro container (.github/workflows/ci.yml, release.yml).
# Runs as root in debian:trixie, ubuntu:26.04, fedora:4x or archlinux. Not meant for a
# workstation: it installs packages without asking. docs/linux.md lists the same dependencies.
#
# Usage:
#   packaging/ci/linux-ci.sh deps rust|build|package
#       rust     curl, git, the distro musl linker, and the Rust toolchain from mise.toml
#       build    rust + the tray's build dependencies + the linux-check tools
#       package  build + cargo-deb and cargo-generate-rpm at the versions in mise.toml
#   packaging/ci/linux-ci.sh version
#       the release version, from Cargo.toml
#   packaging/ci/linux-ci.sh inspect DIR VERSION ARCH
#       check what packaging/linux.sh wrote to DIR: file lists, versions, dependencies
#   packaging/ci/linux-ci.sh smoke deb|rpm|tar DIR
#       install the artifact from DIR as a user would, then run both binaries
#
# Environment: CARGO_HOME and RUSTUP_HOME (the workflows set /usr/local/{cargo,rustup}); VERSION,
# the version smoke expects (default: Cargo.toml's).
# GITHUB_PATH and GITHUB_ENV, when set, receive cargo's bin directory and QMAKE.
set -eu

cd "$(dirname "$0")/../.."

die() {
    echo "error: $*" >&2
    exit 1
}

# In a subshell: os-release also sets VERSION, which smoke reads.
# shellcheck disable=SC1091
OS_ID="$(. /etc/os-release && echo "${ID:-}")"
# shellcheck disable=SC1091
OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-$OS_ID}")"
case "$OS_ID" in
    debian | ubuntu) PM=apt ;;
    fedora) PM=dnf ;;
    arch) PM=pacman ;;
    *) die "unsupported distribution '$OS_ID'" ;;
esac

# The package lists, shared with packaging/ci/host-deps.sh.
# shellcheck source=/dev/null
. "$(dirname "$0")/deps-lib.sh"

ARCH="$(uname -m)"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

pkg_install() {
    case "$PM" in
        apt)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
            ;;
        dnf) dnf install -y -q --setopt=install_weak_deps=False "$@" ;;
        pacman) pacman -Syu --noconfirm --needed "$@" ;;
    esac
}

gh_path() { if [ -n "${GITHUB_PATH:-}" ]; then echo "$1" >> "$GITHUB_PATH"; fi; }
gh_env() { if [ -n "${GITHUB_ENV:-}" ]; then echo "$1" >> "$GITHUB_ENV"; fi; }

# The release version: [workspace.package] in Cargo.toml.
cargo_version() { toml_get Cargo.toml workspace package version; }

deps_rust() {
    # Unquoted: one word per package.
    # shellcheck disable=SC2046
    pkg_install $(deps_pkgs "$PM" rust)
    v="$(toml_get mise.toml tools rust)" || die "no rust version in mise.toml"
    if ! command -v rustup > /dev/null 2>&1; then
        # A pinned rustup-init, checked against a digest recorded here, not one fetched with it.
        rustup_version=1.29.0
        case "$ARCH" in
            x86_64) rustup_sha256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10 ;;
            aarch64) rustup_sha256=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792 ;;
            *) die "no pinned rustup-init for '$ARCH'" ;;
        esac
        rustup_dir="$(mktemp -d)"
        curl --proto '=https' --tlsv1.2 -sSfL -o "$rustup_dir/rustup-init" \
            "https://static.rust-lang.org/rustup/archive/$rustup_version/$ARCH-unknown-linux-gnu/rustup-init"
        echo "$rustup_sha256  $rustup_dir/rustup-init" | sha256sum -c -
        chmod +x "$rustup_dir/rustup-init"
        "$rustup_dir/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
        rm -rf "$rustup_dir"
    fi
    rustup toolchain install "$v" --profile minimal --component rustfmt,clippy \
        --target "$ARCH-unknown-linux-musl"
    rustup default "$v"
    gh_path "$CARGO_HOME/bin"
    cargo --version
}

deps_build() {
    deps_rust
    # shellcheck disable=SC2046
    pkg_install $(deps_pkgs "$PM" build) $(deps_pkgs "$PM" tools)
    QMAKE="$(deps_qmake "$PM")"
    [ -x "$QMAKE" ] || die "$QMAKE not found"
    gh_env "QMAKE=$QMAKE"
    "$QMAKE" -query QT_VERSION
}

deps_package() {
    deps_build
    extra="$(deps_pkgs "$PM" package)"
    # shellcheck disable=SC2086
    if [ -n "$extra" ]; then pkg_install $extra; fi
    for tool in cargo-deb cargo-generate-rpm; do
        v="$(toml_get mise.toml tools "cargo:$tool")" || die "no $tool version in mise.toml"
        cargo install --locked "$tool@$v"
    done
}

# --- inspect --------------------------------------------------------------------------------
# Paths every format must ship, relative to the install prefix (/usr, or the tarball root).
SHIPPED="bin/cainary
bin/cainary-tray
share/applications/ua.SkeLLLa.cAInary.desktop
share/metainfo/ua.SkeLLLa.cAInary.metainfo.xml
share/icons/hicolor/scalable/apps/ua.SkeLLLa.cAInary.svg
share/icons/hicolor/48x48/apps/ua.SkeLLLa.cAInary.png
share/icons/hicolor/256x256/apps/ua.SkeLLLa.cAInary.png"

# expect_files LIST PREFIX: every SHIPPED path, under PREFIX, is a line of LIST.
expect_files() {
    echo "$SHIPPED" | while IFS= read -r p; do
        grep -qx "$2$p" "$1" || die "$2$p is missing from the package"
    done
}

# The packaged files must be the same bytes; only the version is checked here, the rest by
# the smoke test.
inspect() {
    dir="$1"
    version="$2"
    arch="$3"
    case "$arch" in
        x86_64) deb_arch=amd64 ;;
        aarch64) deb_arch=arm64 ;;
        *) die "unknown arch '$arch'" ;;
    esac
    list="$(mktemp)"
    found=0

    tgz="$dir/cainary-$version-linux-$arch.tar.gz"
    if [ -f "$tgz" ]; then
        found=1
        echo "== $tgz"
        tar -tzf "$tgz" | sort > "$list"
        cat "$list"
        top="cainary-$version-linux-$arch/"
        expect_files "$list" "$top"
        for p in install-user.sh README.md LICENSE; do
            grep -qx "$top$p" "$list" || die "$top$p is missing from the tarball"
        done
        # Nothing outside the one top-level directory.
        if grep -v "^$top" "$list" | grep -vx "${top%/}" | grep -q .; then
            die "the tarball has entries outside $top"
        fi
        x="$(mktemp -d)"
        tar -xzf "$tgz" -C "$x"
        [ "$("$x/$top/bin/cainary" --version)" = "cainary $version" ] || die "tarball cainary version"
        file "$x/$top/bin/cainary" | grep -q 'static' || die "tarball cainary is not static"
        rm -rf "$x"
    fi

    deb="$dir/cainary_${version}_$deb_arch.deb"
    if [ -f "$deb" ]; then
        found=1
        echo "== $deb"
        dpkg-deb -f "$deb"
        [ "$(dpkg-deb -f "$deb" Package)" = cainary ] || die "deb Package"
        [ "$(dpkg-deb -f "$deb" Version)" = "$version" ] || die "deb Version is not $version"
        [ "$(dpkg-deb -f "$deb" Architecture)" = "$deb_arch" ] || die "deb Architecture"
        dpkg-deb -f "$deb" Depends | grep -q 'libqt6core6' || die "deb Depends has no libqt6core6 (\$auto)"
        dpkg-deb -f "$deb" Depends | grep -q 'qml6-module-qtquick-controls' || die "deb Depends has no QML modules"
        dpkg-deb -c "$deb" | awk '{ print $NF }' | sed 's|^\./||' | sort > "$list"
        expect_files "$list" "usr/"
        if grep -q 'etc/xdg/autostart' "$list"; then die "the deb installs system-wide autostart"; fi
    fi

    rpm="$dir/cainary-$version-1.$arch.rpm"
    if [ -f "$rpm" ]; then
        found=1
        echo "== $rpm"
        rpm -qip "$rpm"
        [ "$(rpm -qp --qf '%{NAME} %{VERSION} %{ARCH}' "$rpm")" = "cainary $version $arch" ] ||
            die "rpm name, version or arch"
        rpm -qp --requires "$rpm" | tee "$list.req"
        grep -q 'libQt6Core' "$list.req" || die "rpm Requires has no libQt6Core (auto-req)"
        grep -q 'qt6-qtdeclarative' "$list.req" || die "rpm Requires has no qt6-qtdeclarative"
        rpm -qlp "$rpm" | sort > "$list"
        expect_files "$list" "/usr/"
        if grep -q 'etc/xdg/autostart' "$list"; then die "the rpm installs system-wide autostart"; fi
    fi

    rm -f "$list" "$list.req"
    [ "$found" -eq 1 ] || die "no artifacts for $version $arch in $dir"
    echo "inspect: ok"
}

# --- smoke ----------------------------------------------------------------------------------
smoke() {
    kind="$1"
    dir="$2"
    case "$ARCH" in
        x86_64) deb_arch=amd64 ;;
        aarch64) deb_arch=arm64 ;;
        *) die "unknown arch '$ARCH'" ;;
    esac
    # The smoke containers have no python3 for toml_get, so read the version off the artifact.
    case "$kind" in
        deb) glob="cainary_*_$deb_arch.deb" ;;
        rpm) glob="cainary-*-1.$ARCH.rpm" ;;
        tar) glob="cainary-*-linux-$ARCH.tar.gz" ;;
        *) die "unknown kind '$kind' (deb, rpm, tar)" ;;
    esac
    # shellcheck disable=SC2086 # the glob is meant to expand
    set -- "$dir"/$glob
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then die "expected exactly one $glob in $dir"; fi
    version="$(basename "$1" | sed -E 's/^cainary[_-]([0-9]+\.[0-9]+\.[0-9]+)[_-].*/\1/')"
    [ -n "$version" ] || die "no version in $1"

    case "$kind" in
        deb)
            # No Recommends: Depends alone must be enough for the self-test.
            pkg_install jq "$(cd "$dir" && pwd)/cainary_${version}_$deb_arch.deb"
            ;;
        rpm)
            pkg_install jq "$(cd "$dir" && pwd)/cainary-$version-1.$ARCH.rpm"
            ;;
        tar)
            [ "$PM" = pacman ] || die "the tarball smoke test runs on Arch (PKGBUILD depends)"
            # The AUR package's depends, read from the PKGBUILD itself.
            # shellcheck disable=SC2046
            pkg_install jq $(bash -c '. packaging/aur/PKGBUILD && printf "%s\n" "${depends[@]}"')
            x="$(mktemp -d)"
            tar -xzf "$dir/cainary-$version-linux-$ARCH.tar.gz" -C "$x"
            HOME="$x/home" "$x/cainary-$version-linux-$ARCH/install-user.sh"
            export PATH="$x/home/.local/bin:$PATH"
            ;;
        *) die "unknown kind '$kind' (deb, rpm, tar)" ;;
    esac

    set -x
    [ "$(cainary --version)" = "cainary $version" ]
    cainary scan --json --env-kind launchd | jq -e .schema
    [ "$(cainary-tray --version)" = "cainary-tray $version" ]
    CAINARY_UI_SNAPSHOTS="$(mktemp -d)" QT_QPA_PLATFORM=offscreen cainary-tray --self-test
    set +x
    if [ "$kind" = tar ]; then
        HOME="$x/home" "$x/cainary-$version-linux-$ARCH/install-user.sh" --uninstall
        [ ! -e "$x/home/.local/bin/cainary-tray" ] || die "uninstall left cainary-tray behind"
    fi
    echo "smoke ($OS_NAME, $kind): ok"
}

case "${1:-}" in
    deps)
        case "${2:-}" in
            rust) deps_rust ;;
            build) deps_build ;;
            package) deps_package ;;
            *) die "usage: $0 deps rust|build|package" ;;
        esac
        ;;
    version) cargo_version ;;
    inspect)
        [ "$#" -eq 4 ] || die "usage: $0 inspect DIR VERSION ARCH"
        inspect "$2" "$3" "$4"
        ;;
    smoke)
        [ "$#" -eq 3 ] || die "usage: $0 smoke deb|rpm|tar DIR"
        smoke "$2" "$3"
        ;;
    *) die "usage: $0 deps|version|inspect|smoke ..." ;;
esac
