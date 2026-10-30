#!/bin/sh
# scripts/network.sh — create the shared network if it does not exist.
set -eu
podman network exists krot-internal || podman network create krot-internal >/dev/null
