#!/bin/sh
# The distro packages the Linux build needs, one list per package manager: the single source for
# packaging/ci/linux-ci.sh (containers and CI) and packaging/ci/host-deps.sh (`mise run linux:deps`).
# Sourced, not run.
#
#   deps_pkgs PM KIND   print the packages, one per line.  PM: apt, dnf or pacman.
#       rust      curl, git, certificates, python3 and the musl linker (the static CLI)
#       build     the tray's compiler, Qt 6 development packages, D-Bus and validators
#       tools     shellcheck and jq, which a workstation gets from mise instead
#       package   what packaging/linux.sh needs on top of build (dpkg-shlibdeps; rpm tools)
#   deps_qmake PM       the Qt 6 qmake path
#   toml_get FILE KEY... print the value at the key path: a string, or the `version` of a table
#                       (`toml_get mise.toml tools rust`). Needs python3 (the rust group installs it).

deps_pkgs() {
    case "$1:$2" in
        apt:rust) echo "ca-certificates curl git musl-tools python3-minimal" ;;
        dnf:rust) echo "ca-certificates curl git-core musl-gcc python3" ;;
        pacman:rust) echo "ca-certificates curl git musl python" ;;
        apt:build)
            echo "build-essential pkg-config musl-tools
qt6-base-dev qt6-base-dev-tools qt6-declarative-dev qt6-wayland-dev qt6-svg-dev
liblayershellqtinterface-dev libwayland-dev
qml6-module-qtquick qml6-module-qtquick-controls qml6-module-qtquick-layouts
qml6-module-qtquick-window qml6-module-qtquick-templates
qml6-module-qtqml-workerscript qt6-wayland qt6-svg-plugins
dbus dbus-daemon appstream desktop-file-utils file"
            ;;
        dnf:build)
            echo "gcc-c++ make pkgconf-pkg-config
qt6-qtbase-devel qt6-qtdeclarative-devel qt6-qtwayland-devel qt6-qtsvg-devel
layer-shell-qt-devel wayland-devel
dbus-daemon appstream desktop-file-utils file"
            ;;
        pacman:build)
            echo "base-devel qt6-base qt6-declarative qt6-wayland qt6-svg layer-shell-qt
wayland dbus file"
            ;;
        apt:tools) echo "shellcheck jq" ;;
        dnf:tools) echo "ShellCheck jq" ;;
        pacman:tools) echo "shellcheck jq" ;;
        # cargo-deb expands $auto with dpkg-shlibdeps from dpkg-dev.
        apt:package) echo "dpkg-dev" ;;
        # cargo-generate-rpm is pure Rust (from mise); the rpm CLI that inspect uses is in the base image.
        dnf:package) ;;
        pacman:package) ;;
        *) echo "deps_pkgs: unknown '$1' '$2'" >&2; return 1 ;;
    esac
}

deps_qmake() {
    case "$1" in
        apt) echo /usr/lib/qt6/bin/qmake ;;
        dnf | pacman) echo /usr/bin/qmake6 ;;
        *) echo "deps_qmake: unknown '$1'" >&2; return 1 ;;
    esac
}

toml_get() {
    python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    value = tomllib.load(f)
for key in sys.argv[2:]:
    value = value[key]
if isinstance(value, dict):
    value = value["version"]
print(value)
' "$@"
}
