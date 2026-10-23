#!/bin/sh
# $1: pid file. Exits 0, but a descendant still holds the pipes.
case $1 in /*) ;; *) echo "$0: needs an absolute pid file path" >&2; exit 64 ;; esac
echo $$ > "$1"
sleep 15 &
exit 0
