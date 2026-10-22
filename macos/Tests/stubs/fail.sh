#!/bin/sh
# Exits 1 with a message on stderr.
echo "boom: the scanner broke" >&2
echo "second line" >&2
exit 1
