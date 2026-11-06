#!/bin/sh
# A collector: records its pid, argv and the stdin config line (files named by the CAINARY_STUB_*
# variables), prints a hello and a future-type line, then waits for stdin EOF, the lifeline.
[ -n "${CAINARY_STUB_PIDFILE:-}" ] && echo $$ > "$CAINARY_STUB_PIDFILE"
[ -n "${CAINARY_STUB_ARGS:-}" ] && echo "$*" >> "$CAINARY_STUB_ARGS"
IFS= read -r config
[ -n "${CAINARY_STUB_CONFIG:-}" ] && printf '%s\n' "$config" >> "$CAINARY_STUB_CONFIG"
echo '{"v":1,"type":"hello","ts":"2026-01-01T12:00:00Z","endpoint":"http://127.0.0.1:4318","setup":{"claudeCode":["A=1"],"codex":[],"notes":[]}}'
echo '{"v":1,"type":"leak","ts":"2026-01-01T12:00:01Z"}'
while read -r _; do :; done
