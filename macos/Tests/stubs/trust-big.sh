#!/bin/sh
# Prints 2 MB without a newline: over the client's 1 MiB cap.
head -c 2000000 /dev/zero | tr '\0' x
