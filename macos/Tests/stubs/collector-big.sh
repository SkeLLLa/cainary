#!/bin/sh
# A collector that prints one 5000-byte line (over the 1024-byte cap the test sets), then idles.
[ -n "${CAINARY_STUB_PIDFILE:-}" ] && echo $$ > "$CAINARY_STUB_PIDFILE"
echo '{"v":1,"type":"hello","ts":"2026-01-01T12:00:00Z"}'
head -c 5000 /dev/zero | tr '\0' x
echo
while :; do sleep 1; done
