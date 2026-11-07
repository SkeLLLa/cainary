#!/bin/sh
# Set the release version: [workspace.package] version in Cargo.toml (the single source), the
# exact cainary-core requirement in [workspace.dependencies], and the workspace crates' entries
# in Cargo.lock (every member, named in its own manifest). The Linux tray workspace follows: linux/Cargo.toml's [workspace.package]
# version, its crates in linux/Cargo.lock, and a <release> entry in the AppStream metainfo.
# Used by .github/workflows/release.yml (through scripts/release-tree.sh).
#
# Usage: scripts/set-version.sh 1.2.3
#
# SET_VERSION_DATE (YYYY-MM-DD) overrides today's UTC date in the AppStream <release>, so
# separate runs of the release workflow produce byte-identical files.
set -eu

cd "$(dirname "$0")/.."

VERSION="${1:-}"
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "usage: $0 MAJOR.MINOR.PATCH" >&2; exit 2 ;;
esac

tmp="$(mktemp "${TMPDIR:-/tmp}/set-version.XXXXXX")"
trap 'rm -f "$tmp" "$tmp.count"' EXIT

# The version line inside [workspace.package], and the exact `version = "=..."` on the
# cainary-core line in [workspace.dependencies]; other dependency versions stay untouched.
awk -v v="$VERSION" '
    /^\[/ { section = $0 }
    section == "[workspace.package]" && /^version *= *"/ { $0 = "version = \"" v "\"" }
    section == "[workspace.dependencies]" && /^cainary-core = / { sub(/version = "=[^"]*"/, "version = \"=" v "\"") }
    { print }
' Cargo.toml > "$tmp"
cat "$tmp" > Cargo.toml

# Bump every workspace member's [[package]] entry in a lockfile: the version line right after its
# `name = "..."`. The names come from the members' own manifests, so a new crate needs no edit
# here; third-party packages are never matched. Fails if the bumped count differs from the
# member count.
bump_lock() { # MANIFEST LOCKFILE
    base="$(dirname "$1")"
    members="$(sed -n 's/^members *= *\[\(.*\)\].*/\1/p' "$1" | tr -d ' "' | tr ',' ' ')"
    names=""
    for m in $members; do
        n="$(sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$base/$m/Cargo.toml" | head -n 1)"
        [ -n "$n" ] || { echo "no package name in $base/$m/Cargo.toml" >&2; exit 1; }
        names="$names $n"
    done
    expected="$(echo "$names" | wc -w | tr -d ' ')"
    awk -v v="$VERSION" -v names="$names" '
        BEGIN { n = split(names, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
        /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name); own = (name in want); print; next }
        own && /^version = "/ { $0 = "version = \"" v "\""; own = 0; bumped++ }
        { print }
        END { print bumped + 0 > "/dev/stderr" }
    ' "$2" > "$tmp" 2> "$tmp.count"
    got="$(cat "$tmp.count")"
    rm -f "$tmp.count"
    if [ "$got" != "$expected" ]; then
        echo "$2: bumped $got entries, expected $expected ($names )" >&2
        exit 1
    fi
    cat "$tmp" > "$2"
}

bump_lock Cargo.toml Cargo.lock

# Fail if either file didn't take the new version.
grep -qx "version = \"$VERSION\"" Cargo.toml
grep -q "^cainary-core = .*version = \"=$VERSION\"" Cargo.toml

# --- The Linux tray workspace (its own Cargo.toml and Cargo.lock) ------------------------------
if [ -f linux/Cargo.toml ]; then
    awk -v v="$VERSION" '
        /^\[/ { section = $0 }
        section == "[workspace.package]" && /^version *= *"/ { $0 = "version = \"" v "\"" }
        { print }
    ' linux/Cargo.toml > "$tmp"
    cat "$tmp" > linux/Cargo.toml
    grep -qx "version = \"$VERSION\"" linux/Cargo.toml

    if [ -f linux/Cargo.lock ]; then
        bump_lock linux/Cargo.toml linux/Cargo.lock
    fi
fi

# A new <release> at the top of the list; an existing entry for this version is kept as is.
METAINFO=linux/data/ua.SkeLLLa.cAInary.metainfo.xml
if [ -f "$METAINFO" ] && ! grep -q "<release version=\"$VERSION\"" "$METAINFO"; then
    RELEASE_DATE="${SET_VERSION_DATE:-$(date -u +%Y-%m-%d)}"
    case "$RELEASE_DATE" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
        *) echo "SET_VERSION_DATE must be YYYY-MM-DD" >&2; exit 2 ;;
    esac
    awk -v v="$VERSION" -v d="$RELEASE_DATE" '
        { print }
        /^ *<releases>$/ { print "    <release version=\"" v "\" date=\"" d "\"/>" }
    ' "$METAINFO" > "$tmp"
    cat "$tmp" > "$METAINFO"
    grep -q "<release version=\"$VERSION\"" "$METAINFO"
fi

echo "version $VERSION"
