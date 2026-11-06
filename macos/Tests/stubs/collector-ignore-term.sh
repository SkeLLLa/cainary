#!/bin/sh
# A collector that ignores SIGTERM and stdin EOF: only SIGKILL stops it.
trap '' TERM
[ -n "${CAINARY_STUB_PIDFILE:-}" ] && echo $$ > "$CAINARY_STUB_PIDFILE"
echo '{"v":1,"type":"hello","ts":"2026-01-01T12:00:00Z"}'
while :; do sleep 1; done
