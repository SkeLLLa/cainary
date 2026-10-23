#!/bin/sh
# Build, package and smoke-test the Linux tray in a distro container, the way CI does
# (`mise run linux:container:deb|rpm|arch`). The source is copied in, never bind-mounted, so
# the host's target/ directories and the container's never mix. Artifacts land in
# dist/container/<kind>/.
#
# Usage: packaging/ci/container.sh deb|rpm|arch
#   deb   debian:trixie: deps, tray + CLI, tarball + .deb, inspect, install smoke test
#   rpm   fedora:44: the same with the .rpm
#   arch  archlinux: dependencies and a debug build of the tray
#
# Uses podman, or docker when there is no podman. The images are the digest-pinned ones from
# packaging/ci/images.env, which the workflows use too. Set CONTAINER_ENGINE to choose.
set -eu

cd "$(dirname "$0")/../.."

die() {
    echo "error: $*" >&2
    exit 1
}

# shellcheck source=/dev/null
. packaging/ci/images.env
# shellcheck source=/dev/null
. packaging/ci/deps-lib.sh

kind="${1:-}"
case "$kind" in
    deb) image="$DEBIAN_IMAGE" ;;
    rpm) image="$FEDORA_IMAGE" ;;
    arch) image="$ARCH_IMAGE" ;;
    *) die "usage: $0 deb|rpm|arch" ;;
esac

engine="${CONTAINER_ENGINE:-}"
if [ -z "$engine" ]; then
    for e in podman docker; do
        if command -v "$e" > /dev/null 2>&1; then engine="$e"; break; fi
    done
fi
[ -n "$engine" ] || die "neither podman nor docker is installed"

# The steps run in the container's shell, which expands $VERSION and $(uname -m).
# shellcheck disable=SC2016
case "$kind" in
    deb) steps='packaging/ci/linux-ci.sh deps package
make linux LINUX_FORMATS=tar,deb CARGO_BIN=cargo
packaging/ci/linux-ci.sh inspect dist "$VERSION" "$(uname -m)"
packaging/ci/linux-ci.sh smoke deb dist' ;;
    rpm) steps='packaging/ci/linux-ci.sh deps package
make linux LINUX_FORMATS=rpm CARGO_BIN=cargo
packaging/ci/linux-ci.sh inspect dist "$VERSION" "$(uname -m)"
packaging/ci/linux-ci.sh smoke rpm dist' ;;
    arch) steps='packaging/ci/linux-ci.sh deps build
make linux-build CARGO_BIN=cargo' ;;
esac

out="dist/container/$kind"
cname="cainary-$kind-$$"
# shellcheck disable=SC2329
cleanup() { "$engine" rm -f "$cname" > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "== $engine: $image"
"$engine" run -d --name "$cname" "$image" sleep infinity > /dev/null
"$engine" exec "$cname" mkdir /src

# Everything but build output, caches and the VCS directory.
tar --exclude=./target --exclude=./linux/target --exclude=./dist --exclude=./.serena \
    --exclude=./.git -cf - . | "$engine" exec -i "$cname" tar -xf - -C /src

version="$(toml_get Cargo.toml workspace package version)" || die "no version in Cargo.toml"

status=0
"$engine" exec -w /src -e "VERSION=$version" \
    -e CARGO_HOME=/usr/local/cargo -e RUSTUP_HOME=/usr/local/rustup \
    "$cname" sh -euc "export PATH=/usr/local/cargo/bin:\$PATH
$steps" || status=$?

if [ "$status" -eq 0 ] && [ "$kind" != arch ]; then
    rm -rf "$out"
    mkdir -p "$out"
    "$engine" cp "$cname:/src/dist/." "$out/"
    echo "== artifacts in $out"
    ls -l "$out"
fi
[ "$status" -eq 0 ] || echo "container build failed (status $status)" >&2
exit "$status"
