#!/usr/bin/env bash
set -euo pipefail

: "${GATEWAY_PASSWORD:?GATEWAY_PASSWORD is required}"
: "${GATEWAY_SECRET:?GATEWAY_SECRET is required}"

export PORT="${PORT:-8080}"
export AUTH_PORT="${AUTH_PORT:-9000}"

envsubst '${PORT} ${AUTH_PORT}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf

python3 -u /auth_server.py &

nginx -t
exec nginx -g 'daemon off;'
