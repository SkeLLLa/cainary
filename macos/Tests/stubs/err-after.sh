#!/bin/sh
# Scan-driven: the report padded with 1 MiB of spaces, then 60 KiB of stderr.
for f; do :; done
cat "$f"
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr "\0" " "
dd if=/dev/zero bs=1024 count=60 2>/dev/null | tr "\0" "e" >&2
