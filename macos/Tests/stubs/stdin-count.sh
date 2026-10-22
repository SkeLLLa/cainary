#!/bin/sh
# Prints how many bytes arrived on stdin.
wc -c | tr -d " \n"
