#!/bin/sh
# Scan-driven, for the store tests: the last two arguments are a counter file and the report to
# print (the scan may add `--since -` before them).
for a; do counter=$report; report=$a; done
echo x >> "$counter"
sleep 0.3
cat "$report"
