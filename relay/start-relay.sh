#!/bin/sh
set -eu
umask 077
# Configuration, including the relay password, goes directly into GOST's stdin.
# Fly handles public TLS; GOST listens for WebSocket upgrades internally.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/gost_config.py"
