#!/bin/bash
# One-time local dev setup: backend venv + deps + migration, frontend deps.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Backend: creating venv and installing requirements"
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "==> Backend: applying migrations"
alembic upgrade head
cd ..

if [ ! -f .env ]; then
    echo "==> Creating .env from .env.example"
    cp .env.example .env
fi

echo "==> Frontend: installing npm dependencies"
cd frontend
npm install
cd ..

echo "Setup complete. Run './scripts/dev.sh' to start the backend + frontend dev servers."
