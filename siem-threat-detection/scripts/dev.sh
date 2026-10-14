#!/bin/bash
# Runs the backend (uvicorn --reload) and frontend (vite) dev servers
# together, without Docker — for fast local iteration. Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() {
    echo "Stopping dev servers..."
    kill "${BACKEND_PID:-}" "${FRONTEND_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

cd backend
. .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo "Backend:  http://localhost:8000/docs"
echo "Frontend: http://localhost:5173"
wait
