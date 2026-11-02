#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
  build|run|install|install_sudo|publish_flyio)
    build_action="$1"
    shift
    exec make "$build_action" "$@"
    ;;
  *)
    printf 'Usage: ./b {build|run|install|install_sudo|publish_flyio}\n' >&2
    exit 2
    ;;
esac
