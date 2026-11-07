#!/usr/bin/env bash
# Regenerate the OTLP protobuf/gzip test fixtures from their JSON sources.
# Needs mise (fetches buf), jq and gzip. Tests never run this; outputs are committed.
set -euo pipefail

BUF_VERSION=1.75.0

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
proto="$root/crates/cainary-net/tests/fixtures/otlp-proto"
out="$root/crates/cainary-net/tests/fixtures/otlp"
payloads="$root/crates/cainary-core/tests/otel-payloads"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

buf() { mise exec "aqua:bufbuild/buf@$BUF_VERSION" -- buf "$@"; }

# OTLP/JSON carries trace/span ids as hex; proto3 JSON (buf) expects base64 bytes.
# jq has no hex decoder, so base64 is spelled out (3 bytes -> 4 characters).
# shellcheck disable=SC2016
JQ_HEX_IDS='
def hexbytes: ascii_downcase | explode | map(if . >= 97 then . - 87 else . - 48 end)
  | [range(0; length; 2) as $i | .[$i] * 16 + .[$i + 1]];
def b64chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
def b64: hexbytes as $b
  | [range(0; $b | length; 3) as $i | $b[$i:$i + 3]
      | . as $g
      | (($g[0] * 65536) + (($g[1] // 0) * 256) + ($g[2] // 0)) as $v
      | [($v / 262144 | floor) % 64, ($v / 4096 | floor) % 64, ($v / 64 | floor) % 64, $v % 64]
      | map(b64chars[.:.+1]) | join("")
      | if ($g | length) == 1 then .[0:2] + "=="
        elif ($g | length) == 2 then .[0:3] + "="
        else . end]
  | join("");
walk(if type == "object" then
       with_entries(if (.key | IN("traceId", "spanId", "parentSpanId")) and (.value | type == "string")
                    then .value |= b64 else . end)
     else . end)'

# convert <payload> <signal> <json> <message type>
convert() {
  local name=$1 signal=$2 src=$3 type=$4
  local base="$out/$name-$signal" json="$work/$name-$signal.json"
  jq "$JQ_HEX_IDS" "$src" >"$json"
  buf convert "$proto" --type "$type" --from "$json#format=json" --to "$base.binpb"
  gzip -n -9 -c "$base.binpb" >"$base.binpb.gz"
  # The .json.gz body is the original OTLP/JSON (hex ids), as an exporter would send it.
  gzip -n -9 -c "$src" >"$base.json.gz"
}

mkdir -p "$out"
for dir in "$payloads"/*/; do
  name=$(basename "$dir")
  [[ -f $dir/logs.json ]] && convert "$name" logs "$dir/logs.json" opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest
  [[ -f $dir/metrics.json ]] && convert "$name" metrics "$dir/metrics.json" opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest
done
convert synthetic traces "$out/traces.json" opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest

# Two-member gzip: the JSON bytes split in half, one member each. A decoder that reads
# every member reproduces the original document.
multi_src="$payloads/codex-0.166.0/logs.json"
size=$(wc -c <"$multi_src")
half=$((size / 2))
head -c "$half" "$multi_src" | gzip -n -9 -c >"$work/m1.gz"
tail -c +"$((half + 1))" "$multi_src" | gzip -n -9 -c >"$work/m2.gz"
cat "$work/m1.gz" "$work/m2.gz" >"$out/codex-0.166.0-logs.multi.json.gz"
