#!/bin/sh
# 1 MiB on stderr, over the 64 KiB cap.
dd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr "\0" "e" >&2
