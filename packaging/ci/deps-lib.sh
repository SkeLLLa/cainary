#!/bin/sh
# The distro packages the Linux build needs, one list per package manager: the single source for
# packaging/ci/linux-ci.sh (containers and CI) and packaging/ci/host-deps.sh (`mise run linux:deps`).
# Sourced, not run.
#
#   deps_pkgs PM KIND   print the packages, one per line.  PM: apt, dnf or pacman.
#       rust      curl, git, certificates, the host C compiler that build scripts link
#                 with, and musl (the static CLI)
#       build     the tray's compiler, Qt 6 development packages, D-Bus and validators
#       tools     shellcheck and jq, which a workstation gets from mise instead
#       package   what packaging/linux.sh needs on top of build (dpkg-shlibdeps; find-requires)
#   deps_qmake PM       the Qt 6 qmake path
#   toml_get FILE KEY... print the value at the key path: a string, or the `version` of a table
#                       (`toml_get mise.toml tools rust`).

deps_pkgs() {
    case "$1:$2" in
        apt:rust) echo "ca-certificates curl gcc libc6-dev git musl-tools" ;;
        dnf:rust) echo "ca-certificates curl git-core musl-gcc" ;;
        pacman:rust) echo "ca-certificates curl gcc git musl" ;;
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
        # cargo-generate-rpm (from mise) takes Requires from rpm-build's find-requires; without it
        # it falls back to ldd, which lists transitive libraries and glibc [WEAK] versions that no
        # package provides. The rpm CLI that inspect uses is in the base image.
        dnf:package) echo "rpm-build" ;;
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

# Just enough TOML for the callers: one-line `key = "string"` or `key = { version = "..." }`.
toml_get() {
    awk '
        BEGIN {
            for (i = 2; i < ARGC - 1; i++) table = table (i > 2 ? "." : "") ARGV[i]
            key = ARGV[ARGC - 1]
            ARGC = 2
        }
        /^[ \t]*\[/ {
            name = $0
            sub(/^[ \t]*\[[ \t]*/, "", name)
            sub(/[ \t]*\].*$/, "", name)
            in_table = (name == table)
            next
        }
        in_table {
            line = $0
            sub(/^[ \t]*/, "", line)
            k = line
            sub(/[ \t]*=.*$/, "", k)
            gsub(/"/, "", k)
            if (k != key || index(line, "=") == 0) next
            value = substr(line, index(line, "=") + 1)
            # An inline table: its version.
            if (value ~ /^[ \t]*\{/) {
                if (!match(value, /version[ \t]*=[ \t]*"[^"]*"/)) exit 1
                value = substr(value, RSTART, RLENGTH)
                sub(/^version[ \t]*=[ \t]*/, "", value)
            }
            sub(/^[ \t]*/, "", value)
            sub(/[ \t]*(#.*)?$/, "", value)
            gsub(/"/, "", value)
            print value
            found = 1
            exit
        }
        END { exit !found }
    ' "$@"
}
