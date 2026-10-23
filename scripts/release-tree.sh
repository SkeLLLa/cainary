#!/bin/sh
# Apply the release version to the working tree (scripts/set-version.sh) and print a hash of
# the files it writes, as the last line of output. With EXPECTED_HASH set, fail unless the hash
# matches: the workflow's prepare job computes it once, and every build and the publish job
# must end up with the same tree. SET_VERSION_DATE should be set so the date is the same too.
# Used by .github/workflows/release.yml.
#
# Usage: [EXPECTED_HASH=...] scripts/release-tree.sh 1.2.3
set -eu

cd "$(dirname "$0")/.."

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 MAJOR.MINOR.PATCH" >&2; exit 2; }

scripts/set-version.sh "$VERSION" >&2

if command -v sha256sum > /dev/null 2>&1; then
    sum() { sha256sum; }
else
    sum() { shasum -a 256; }
fi

# Per-file hashes in a fixed order, hashed again.
hash="$(
    for f in Cargo.toml Cargo.lock linux/Cargo.toml linux/Cargo.lock \
        linux/data/ua.SkeLLLa.cAInary.metainfo.xml; do
        printf '%s ' "$f"
        sum < "$f"
    done | sum | awk '{ print $1 }'
)"

if [ -n "${EXPECTED_HASH:-}" ] && [ "$hash" != "$EXPECTED_HASH" ]; then
    echo "version files differ from the prepared release tree: $hash, expected $EXPECTED_HASH" >&2
    exit 1
fi
echo "$hash"
