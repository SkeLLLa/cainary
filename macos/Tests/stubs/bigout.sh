#!/bin/sh
# 9 MiB on stdout, over the 8 MiB cap.
dd if=/dev/zero bs=1048576 count=9 2>/dev/null | tr "\0" " "
