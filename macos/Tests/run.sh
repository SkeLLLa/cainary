#!/bin/sh
# Builds and runs the macOS app's tests with Command Line Tools swiftc only (no SwiftPM, no
# XCTest). Run from the repo root (make ui-test does). The unit build compiles every Sources/*.swift
# except main.swift, plus Tests/Support and Tests/Unit, into target/macos-tests/tests.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
macos=$(dirname "$here")
root=$(dirname "$macos")
out="$root/target/macos-tests"
mkdir -p "$out"

tmp=${TMPDIR:-/tmp}
sdk=${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}
arch=$(uname -m)
swiftc=${SWIFTC:-swiftc}

# Sources minus main.swift; the tests bring their own @main.
sources=$(find "$macos/Sources" -name '*.swift' ! -name main.swift | sort)

# shellcheck disable=SC2086 # the lists are paths without spaces
$swiftc -parse-as-library -swift-version 6 \
  -sdk "$sdk" -module-cache-path "$tmp/swift-mc" -target "$arch-apple-macos14" \
  -Onone -g -D DEBUG \
  $sources "$here"/Support/*.swift "$here"/Unit/*.swift \
  -o "$out/tests"

CAINARY_ROOT="$root" "$out/tests"

# Snapshots: the real helper on fixtures, rendered to target/ui-snapshots/ (§5c). Needs
# target/debug/cainary, which make ui-test builds first.
# shellcheck disable=SC2086
$swiftc -parse-as-library -swift-version 6 \
  -sdk "$sdk" -module-cache-path "$tmp/swift-mc" -target "$arch-apple-macos14" \
  -Onone -g -D DEBUG \
  $sources "$here"/Support/*.swift "$here"/Snapshots/*.swift \
  -o "$out/snapshots"

CAINARY_ROOT="$root" "$out/snapshots"
