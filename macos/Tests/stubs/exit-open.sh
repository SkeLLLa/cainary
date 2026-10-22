#!/bin/sh
# $1: pid file. Exits 0, but a descendant still holds the pipes.
echo $$ > "$1"
sleep 15 &
exit 0
