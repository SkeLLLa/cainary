#!/bin/sh
# Scan-driven: 60 KiB of stderr, then the report padded with 1 MiB of spaces.
# Draining stdout before stderr (or the reverse) would deadlock on a full pipe.
for f; do :; done
dd if=/dev/zero bs=1024 count=60 2>/dev/null | tr "\0" "e" >&2
cat "$f"
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr "\0" " "
