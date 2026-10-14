.PHONY: setup dev test backend-test frontend-build up down logs healthcheck migrate

setup:
	./scripts/setup.sh

dev:
	./scripts/dev.sh

test: backend-test

backend-test:
	cd backend && . .venv/bin/activate && pytest -q

frontend-build:
	cd frontend && npm run build

migrate:
	cd backend && . .venv/bin/activate && alembic upgrade head

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

healthcheck:
	./scripts/healthcheck.sh
