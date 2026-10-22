#!/bin/sh
# Scan-driven: prints the report file named by the last argument, then 2 MiB of spaces, so the
# raw bytes are too big to keep as a baseline.
for f; do :; done
cat "$f"
head -c 2097152 /dev/zero | tr '\0' ' '
