#!/bin/sh
set -eu

# Keep s6-overlay as PID 1. Long-running children receive only the path to the
# runtime bootstrap file; the resolver passes its value solely to each
# short-lived `op` subprocess.
exec /init /opt/hermes/docker/main-wrapper.sh "$@"