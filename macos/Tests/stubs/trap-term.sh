#!/bin/sh
# $1: pid file. Ignores SIGTERM, so only SIGKILL stops it.
echo $$ > "$1"
trap "" TERM
sleep 15
