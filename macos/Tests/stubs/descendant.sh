#!/bin/sh
# $1: pid file. A descendant keeps the pipes open after the helper dies.
echo $$ > "$1"
sleep 15 &
exec sleep 15
