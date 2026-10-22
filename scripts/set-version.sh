#!/bin/sh
# Set the release version: [workspace.package] version in Cargo.toml (the single source), the
# exact cainary-core requirement in [workspace.dependencies], and the workspace crates' entries
# in Cargo.lock. Used by .github/workflows/release.yml.
#
# Usage: scripts/set-version.sh 1.2.3
set -eu

cd "$(dirname "$0")/.."

VERSION="${1:-}"
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "usage: $0 MAJOR.MINOR.PATCH" >&2; exit 2 ;;
esac

tmp="$(mktemp "${TMPDIR:-/tmp}/set-version.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# The version line inside [workspace.package], and the exact `version = "=..."` on the
# cainary-core line in [workspace.dependencies]; other dependency versions stay untouched.
awk -v v="$VERSION" '
    /^\[/ { section = $0 }
    section == "[workspace.package]" && /^version *= *"/ { $0 = "version = \"" v "\"" }
    section == "[workspace.dependencies]" && /^cainary-core = / { sub(/version = "=[^"]*"/, "version = \"=" v "\"") }
    { print }
' Cargo.toml > "$tmp"
cat "$tmp" > Cargo.toml

# The version line right after `name = "cainary"` and `name = "cainary-core"` in their [[package]] blocks.
awk -v v="$VERSION" '
    /^name = "cainary(-core)?"$/ { own = 1; print; next }
    own && /^version = "/ { $0 = "version = \"" v "\""; own = 0 }
    { print }
' Cargo.lock > "$tmp"
cat "$tmp" > Cargo.lock

# Fail if either file didn't take the new version.
grep -qx "version = \"$VERSION\"" Cargo.toml
grep -q "^cainary-core = .*version = \"=$VERSION\"" Cargo.toml
[ "$(grep -A1 -E '^name = "cainary(-core)?"$' Cargo.lock | grep -cx "version = \"$VERSION\"")" -eq 2 ]
echo "version $VERSION"
