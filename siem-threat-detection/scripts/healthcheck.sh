#!/bin/bash
# Quick smoke test against a running stack (docker compose or ./scripts/dev.sh).
set -uo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"

echo "==> Backend health"
curl -fsS "$BACKEND_URL/api/v1/health" && echo || echo "FAILED: backend not reachable at $BACKEND_URL"

echo "==> Alerts endpoint"
curl -fsS "$BACKEND_URL/api/v1/alerts?limit=1" && echo || echo "FAILED: alerts endpoint"

echo "==> Incidents endpoint"
curl -fsS "$BACKEND_URL/api/v1/incidents?limit=1" && echo || echo "FAILED: incidents endpoint"

echo "==> ML models endpoint"
curl -fsS "$BACKEND_URL/api/v1/ml/models" && echo || echo "FAILED: ml models endpoint"
