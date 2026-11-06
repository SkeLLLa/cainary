# Sanitized OTLP/JSON payload fixtures

Structure-only OTLP/JSON captured from claude-code 2.1.316 and codex 0.166.0
(see `poc/mitm/README.md`). Every attribute value is a type placeholder
(`<string>`, `"0"`, `0`, `false`); timestamps are `"0"`, trace/span ids are empty.
Only event names, attribute keys, metric names/units/types, scope names and the
constants `service.name`, `service.version` and `event.name` keep real values.
Each distinct (event name, attribute key set) or (metric, data-point key set)
appears once.

Regenerate (fish):

```fish
python3 -I scripts/otel-fixture-sanitize.py /tmp/otel-fixtures poc/mitm/logs/otel/*.json
```

The script writes `<vendor>/{logs,metrics}.json`; copy them into the versioned
directories here. This directory lives outside `tests/fixtures/` because
`tests/golden.rs` treats every subdirectory of that as a scan fixture.
