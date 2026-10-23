#!/bin/sh
# The distro packages the Linux tray needs on a workstation (`mise run linux:deps`): the same
# lists as the CI containers (packaging/ci/deps-lib.sh), minus shellcheck and jq, which mise
# installs. Prints the install command; with --install it asks first, then runs it with sudo
# unless you are root. It never runs sudo without that prompt.
#
# Usage: packaging/ci/host-deps.sh [--install] [--distro apt|dnf|pacman] [--list]
#   --list   print only the package names
set -eu

cd "$(dirname "$0")/../.."
# shellcheck source=/dev/null
. packaging/ci/deps-lib.sh

install=0
list=0
PM=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install) install=1 ;;
        --list) list=1 ;;
        --distro)
            [ "$#" -ge 2 ] || { echo "--distro needs apt, dnf or pacman" >&2; exit 2; }
            PM="$2"
            shift
            ;;
        *) echo "usage: $0 [--install] [--distro apt|dnf|pacman] [--list]" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$PM" ]; then
    if [ -r /etc/os-release ]; then
        # In a subshell: os-release sets many variables.
        # shellcheck disable=SC1091
        ids="$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")"
    else
        ids=""
    fi
    for id in $ids; do
        case "$id" in
            debian | ubuntu) PM=apt ;;
            fedora | rhel | centos) PM=dnf ;;
            arch) PM=pacman ;;
        esac
        [ -z "$PM" ] || break
    done
    [ -n "$PM" ] || { echo "unsupported distribution; pass --distro apt|dnf|pacman" >&2; exit 1; }
fi

pkgs="$(
    for kind in rust build package; do deps_pkgs "$PM" "$kind"; done | tr ' ' '\n' | grep . | sort -u
)"

if [ "$list" -eq 1 ]; then
    echo "$pkgs"
    exit 0
fi

# One word per package.
words="$(echo "$pkgs" | tr '\n' ' ')"
case "$PM" in
    apt) cmd="apt-get install -y --no-install-recommends $words" ;;
    dnf) cmd="dnf install -y --setopt=install_weak_deps=False $words" ;;
    pacman) cmd="pacman -S --needed $words" ;;
esac
as_root=""
[ "$(id -u)" -eq 0 ] || as_root="sudo "

echo "Packages for the Linux tray on this system ($PM):"
echo "  ${as_root}${cmd}"
echo "Tools mise installs (rust, shellcheck, jq, cargo-deb, ...): mise install"
echo "Also needed: podman or docker, for the linux:container:* tasks."

if [ "$install" -eq 1 ]; then
    printf 'Run this now? [y/N] '
    read -r answer
    case "$answer" in
        y | Y | yes) ;;
        *) echo "not installing"; exit 0 ;;
    esac
    # shellcheck disable=SC2086
    ${as_root}${cmd}
else
    echo "Run it yourself, or: mise run linux:deps -- --install"
fi
