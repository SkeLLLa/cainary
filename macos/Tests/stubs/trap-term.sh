#!/bin/sh
# $1: pid file. Ignores SIGTERM, so only SIGKILL stops it.
case $1 in /*) ;; *) echo "$0: needs an absolute pid file path" >&2; exit 64 ;; esac
echo $$ > "$1"
trap "" TERM
sleep 15
