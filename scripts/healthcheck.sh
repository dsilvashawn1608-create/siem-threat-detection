#!/bin/bash
# Quick smoke test against a running stack (docker compose or ./scripts/dev.sh).
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
provided_username="${AUTH_ADMIN_USERNAME:-}"
provided_password="${AUTH_ADMIN_PASSWORD:-}"
file_username=""
file_password=""
if [[ -f .env ]]; then
  while IFS='=' read -r key value; do
    value="${value%$'\r'}"
    case "$key" in
      AUTH_ADMIN_USERNAME) file_username="$value" ;;
      AUTH_ADMIN_PASSWORD) file_password="$value" ;;
    esac
  done < .env
fi
AUTH_ADMIN_USERNAME="${provided_username:-$file_username}"
AUTH_ADMIN_PASSWORD="${provided_password:-$file_password}"
: "${AUTH_ADMIN_USERNAME:?Set AUTH_ADMIN_USERNAME in the environment or .env}"
: "${AUTH_ADMIN_PASSWORD:?Set AUTH_ADMIN_PASSWORD in the environment or .env}"

echo "==> Signing in"
login_payload="$(
  AUTH_ADMIN_USERNAME="$AUTH_ADMIN_USERNAME" AUTH_ADMIN_PASSWORD="$AUTH_ADMIN_PASSWORD" \
    python -c 'import json, os; print(json.dumps({"username": os.environ["AUTH_ADMIN_USERNAME"], "password": os.environ["AUTH_ADMIN_PASSWORD"]}))'
)"
login_response="$(
  curl -fsS -X POST "$BACKEND_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    --data-binary "$login_payload"
)"
access_token="$(
  printf '%s' "$login_response" |
    python -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
)"
: "${access_token:?Login response did not include an access token}"

echo "==> Backend health"
curl -fsS "$BACKEND_URL/api/v1/health"
echo

echo "==> Backend readiness (database)"
curl -fsS "$BACKEND_URL/api/v1/ready"
echo

echo "==> Alerts endpoint"
curl -fsS "$BACKEND_URL/api/v1/alerts?limit=1" \
  -H "Authorization: Bearer $access_token"
echo

echo "==> Incidents endpoint"
curl -fsS "$BACKEND_URL/api/v1/incidents?limit=1" \
  -H "Authorization: Bearer $access_token"
echo

echo "==> ML models endpoint"
curl -fsS "$BACKEND_URL/api/v1/ml/models" \
  -H "Authorization: Bearer $access_token"
echo
