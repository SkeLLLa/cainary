# Vendored opentelemetry-proto (test-only)

Source: <https://github.com/open-telemetry/opentelemetry-proto>, tag `v1.5.0`
(commit `2bd940b2b77c1ab57c27166af21384906da7bb2b`), Apache-2.0 (see `LICENSE`).

Only `opentelemetry/proto/{common,resource,logs,metrics,trace}/v1/*.proto` and
`opentelemetry/proto/collector/{logs,metrics,trace}/v1/*.proto` are copied, unmodified.
They exist only so `scripts/otlp-fixtures.sh` can build the binary fixtures in `../otlp/`;
nothing in the build or the tests reads them.
