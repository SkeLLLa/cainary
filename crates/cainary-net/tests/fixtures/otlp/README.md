# OTLP body fixtures (protobuf and gzip)

Committed outputs of `scripts/otlp-fixtures.sh`; tests never need buf. Each file is a
full OTLP export request body, so one decoded body must give the same result whatever
its encoding.

Per `<payload>-<signal>`:

| File | Content |
| --- | --- |
| `<payload>-<signal>.binpb` | protobuf `Export{Logs,Metrics,Trace}ServiceRequest` |
| `<payload>-<signal>.binpb.gz` | the `.binpb` gzipped |
| `<payload>-<signal>.json.gz` | the source OTLP/JSON (hex ids) gzipped |

Sources:

| Payload | Signal | Source JSON |
| --- | --- | --- |
| `claude-code-2.1.316` | logs, metrics | `crates/cainary-core/tests/otel-payloads/claude-code-2.1.316/{logs,metrics}.json` |
| `codex-0.166.0` | logs | `crates/cainary-core/tests/otel-payloads/codex-0.166.0/logs.json` |
| `synthetic` | traces | `traces.json` here (hand-written; 2 spans, 1 event, 1 link, `user.email` = `alice@example.com` matches the `email` red-flag preset) |

`codex-0.166.0-logs.multi.json.gz` is a two-member gzip stream: the bytes of the codex
logs JSON split at the midpoint, each half gzipped separately, then concatenated. Decoding
every member and joining them yields the original document (a decoder reading only the
first member gets truncated JSON).

OTLP/JSON writes `traceId`/`spanId`/`parentSpanId` as hex; buf expects proto3-JSON base64,
so the script rewrites those with `jq` before `buf convert`. The `.json.gz` files keep the
original hex. Output is deterministic (`gzip -n`).

Regenerate (needs mise, jq, gzip):

```sh
scripts/otlp-fixtures.sh
```

The buf version is pinned in the script and fetched through `mise exec aqua:bufbuild/buf@<version>`.
