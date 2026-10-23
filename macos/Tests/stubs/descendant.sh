#!/bin/sh
# $1: pid file. A descendant keeps the pipes open after the helper dies.
case $1 in /*) ;; *) echo "$0: needs an absolute pid file path" >&2; exit 64 ;; esac
echo $$ > "$1"
sleep 15 &
exec sleep 15
