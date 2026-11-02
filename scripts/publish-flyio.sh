#!/usr/bin/env bash
set -euo pipefail
umask 077
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f .env ]] || cp .env.example .env
chmod 600 .env
# Read only known NAME=VALUE fields; do not execute .env as a shell script.
while IFS='=' read -r setting value || [[ -n "${setting:-}" ]]; do
  case "$setting" in
    FLY_APP) FLY_APP="$value";;
    FLY_ORG) FLY_ORG="$value";;
    FLY_REGION) FLY_REGION="$value";;
    WGPROXY_DOMAIN) WGPROXY_DOMAIN="$value";;
    WGPROXY_USERNAME) WGPROXY_USERNAME="$value";;
    WGPROXY_PASSWORD) WGPROXY_PASSWORD="$value";;
    WGPROXY_UDP_PORT) WGPROXY_UDP_PORT="$value";;
    WGPROXY_ALLOWED_DOMAIN_PATTERN) WGPROXY_ALLOWED_DOMAIN_PATTERN="$value";;
    WGPROXY_ALLOWED_DOMAINS) WGPROXY_ALLOWED_DOMAINS="$value";;
  esac
done < .env
: "${FLY_APP:?Set FLY_APP in .env}"
: "${FLY_ORG:?Set FLY_ORG in .env}"
: "${FLY_REGION:?Set FLY_REGION in .env}"
: "${WGPROXY_DOMAIN:?Set WGPROXY_DOMAIN in .env}"
[[ "$FLY_APP" =~ ^[a-z][a-z0-9-]+$ && "$FLY_REGION" =~ ^[a-z]{3}$ ]] || { echo 'Invalid Fly app name or region' >&2; exit 1; }
[[ "$WGPROXY_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$WGPROXY_DOMAIN" == *.* && "$WGPROXY_DOMAIN" != *..* ]] || { echo 'Invalid proxy domain' >&2; exit 1; }
WGPROXY_UDP_PORT="${WGPROXY_UDP_PORT:-51820}"
WGPROXY_USERNAME="${WGPROXY_USERNAME:-relay-user}"
if [[ -z "${WGPROXY_ALLOWED_DOMAINS:-}" && "${WGPROXY_ALLOWED_DOMAIN_PATTERN:-^.*$}" != '^.*$' ]]; then
  echo 'Replace WGPROXY_ALLOWED_DOMAIN_PATTERN with WGPROXY_ALLOWED_DOMAINS hostname wildcards in .env.' >&2
  exit 1
fi
WGPROXY_ALLOWED_DOMAINS="${WGPROXY_ALLOWED_DOMAINS:-*}"
[[ "$WGPROXY_UDP_PORT" =~ ^[0-9]+$ && "$WGPROXY_UDP_PORT" -ge 1 && "$WGPROXY_UDP_PORT" -le 65535 ]] || { echo 'Invalid relay UDP port' >&2; exit 1; }
if [[ -z "${WGPROXY_PASSWORD:-}" ]]; then
  WGPROXY_PASSWORD="$(openssl rand -hex 32)"
  # This file contains deployment metadata and relay credentials, never WG keys.
  ENV_STAGE="$(mktemp "$PROJECT_ROOT/.env.XXXXXX")"
  trap 'rm -f "$ENV_STAGE"' EXIT
  awk '!/^WGPROXY_(USERNAME|PASSWORD)=/' .env > "$ENV_STAGE"
  printf 'WGPROXY_USERNAME=%s\nWGPROXY_PASSWORD=%s\n' "$WGPROXY_USERNAME" "$WGPROXY_PASSWORD" >> "$ENV_STAGE"
  mv "$ENV_STAGE" .env
fi
WGPROXY_USERNAME="$WGPROXY_USERNAME" WGPROXY_PASSWORD="$WGPROXY_PASSWORD" WGPROXY_UDP_PORT="$WGPROXY_UDP_PORT" \
  WGPROXY_ALLOWED_DOMAINS="$WGPROXY_ALLOWED_DOMAINS" python3 relay/gost_config.py --check
if [[ "${1:-}" == --prepare ]]; then
  printf 'Prepared .env for the configured proxy domain in %s (credentials retained; values not printed).\n' "$FLY_REGION"
  exit 0
fi
[[ $# -eq 0 ]] || { echo 'Usage: ./b publish_flyio' >&2; exit 2; }
FLY="$(command -v flyctl || command -v fly || true)"
[[ -n "$FLY" ]] || { echo 'Install flyctl and run flyctl auth login first.' >&2; exit 1; }
command -v jq >/dev/null || { echo 'Install jq (brew install jq).' >&2; exit 1; }
"$FLY" auth whoami
APPS="$("$FLY" apps list --json)"
if ! printf '%s' "$APPS" | jq -e --arg name "$FLY_APP" 'any(.[]; .Name == $name)' >/dev/null; then
  "$FLY" apps create "$FLY_APP" --org "$FLY_ORG" --yes
fi
# Import over stdin so credentials are absent from command arguments and image layers.
printf 'WGPROXY_USERNAME=%s\nWGPROXY_PASSWORD=%s\nWGPROXY_UDP_PORT=%s\nWGPROXY_ALLOWED_DOMAINS=%s\n' \
  "$WGPROXY_USERNAME" "$WGPROXY_PASSWORD" "$WGPROXY_UDP_PORT" "$WGPROXY_ALLOWED_DOMAINS" |
  "$FLY" secrets import --app "$FLY_APP" --stage
"$FLY" config validate --config relay/fly.toml --app "$FLY_APP" --strict
"$FLY" deploy "$PROJECT_ROOT/relay" --config "$PROJECT_ROOT/relay/fly.toml" \
  --app "$FLY_APP" --primary-region "$FLY_REGION" --remote-only --ha=false --yes
"$FLY" status --app "$FLY_APP"
printf '\nDeployment complete. Copy WGPROXY_DOMAIN, WGPROXY_USERNAME, and WGPROXY_PASSWORD from .env into WGApp.\nProtocol: GOST relay over WSS (/ws)\nRegion: %s\n' "$FLY_REGION"
printf 'The Mac proxy client must also use GOST; wstunnel clients are incompatible.\n'
