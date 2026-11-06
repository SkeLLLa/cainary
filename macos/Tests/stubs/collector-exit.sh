#!/bin/sh
# A collector that can't bind its port.
echo "cainary-otel-debug: bind 127.0.0.1:4318: address in use" >&2
echo "second line" >&2
exit 1
