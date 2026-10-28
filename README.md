# SIEM Threat Detection Platform

A lab-scale Security Operations Center platform: Snort (network IDS) and
Splunk (log/event SIEM) alerts flow into a FastAPI backend, which
correlates them into incidents, scores them with a scikit-learn anomaly
model, and surfaces everything in a React/TypeScript console-style
dashboard.

All 9 build phases are complete (Foundation → Splunk → Snort →
Integration → Incident Engine → AI → UI → Testing → Documentation) — see
`CHANGELOG.md` for what each phase added.

```
Snort (IDS) ──┐
              ├─> FastAPI backend ─> SQLite/Postgres ─> React dashboard
Splunk (SIEM)─┘        │
                        └─> Isolation Forest anomaly scoring (Phase 6)
```

## Stack

- **Backend**: FastAPI, SQLAlchemy 2.x, Alembic, Pydantic v2
- **SIEM**: Splunk (HTTP Event Collector ingest + REST search API)
- **IDS**: Snort 2.9.20 (`alert_fast` log parsing)
- **ML**: scikit-learn `IsolationForest` over per-source-IP alert features
- **Frontend**: React 18, TypeScript, Tailwind, Vite
- **Orchestration**: Docker Compose

## Quick start

### Docker Compose (full stack)

```bash
cp .env.example .env
# Generate unique secrets, then put the values into .env:
python -c "import secrets; print('AUTH_SECRET_KEY=' + secrets.token_hex(32)); print('AUTH_ADMIN_PASSWORD=' + secrets.token_urlsafe(24)); print('SPLUNK_HEC_TOKEN=' + secrets.token_hex(32)); print('SPLUNK_PASSWORD=' + secrets.token_urlsafe(24))"
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs
- Splunk Web: http://localhost:8001
- Sign in with the `AUTH_ADMIN_USERNAME` and `AUTH_ADMIN_PASSWORD` values from
  `.env`. Keep `.env` private; the Compose file refuses to start without the
  required local secrets.

The API requires bearer-token authentication except for `GET /api/v1/health`,
`GET /api/v1/ready`, and `POST /api/v1/auth/login`. The first configured local user is bootstrapped
as an administrator. Administrators can create analyst accounts with
`POST /api/v1/auth/users`; analyst accounts can read and triage alerts and
incidents, while sensor sync, model training, detection-rule changes, user
management, and audit-log access require an administrator. Access tokens
expire after eight hours. Audit actor names are taken from the authenticated
account rather than a caller-supplied query parameter.

The backend uses SQLite in the persistent `backend_data` Docker volume. This
is not a PostgreSQL service; an old, stopped `db` container from a previous
Compose configuration is not used by this stack. Database files and ML model
files are mounted separately from the application code so they do not mask
new builds.

Gemini analysis is optional. To enable it, create a Gemini API key in
[Google AI Studio](https://aistudio.google.com/apikey), put it in `.env` as
`GEMINI_API_KEY`, and restart the backend. The key stays on the backend;
with no key the rest of the SIEM continues to work. The optional analysis
uses the stable `gemini-2.5-flash` model and sends selected alert/incident
fields (not raw logs, raw event payloads, credentials, or audit records) to
Google. Generated analysis is unverified advice and never triggers actions.
See [deployment instructions](docs/DEPLOYMENT.md#optional-gemini-analysis).

For a controlled dashboard demo, an administrator can use **Gemini Lab
Simulation** from the Alerts tab with a single natural-language request.
Gemini chooses only among fixed port-scan, failed-login, and benign web-probe
scenarios; the backend adds clearly labeled synthetic alerts and sends no
network traffic. This demonstrates the SIEM workflow, not real sensor detection.

### Local dev (no Docker)

For a backend-only development setup on Windows, from the repository root:

```powershell
Copy-Item .env.example .env # if .env does not already exist
# Set AUTH_SECRET_KEY (at least 32 characters) and AUTH_ADMIN_PASSWORD
# (at least 12 characters) in .env before starting the API.
.\scripts\setup-backend.ps1
.\scripts\dev-backend.ps1
```

The backend API is at http://localhost:8000 and its interactive docs are at
http://localhost:8000/docs. This local setup uses `backend\siem.db`, regardless
of the Docker database path in `.env`; Splunk/Snort auto-sync remain off unless
enabled and configured.

On Linux/macOS, or when setting up the full frontend and backend together:

```bash
./scripts/setup.sh   # creates backend venv, installs deps, runs migrations, npm install
./scripts/dev.sh      # runs uvicorn --reload + vite together
```

Run the test suites:

```bash
cd backend && . .venv/bin/activate && pytest -q
cd frontend && npx vitest run
```

## Documentation

This README is the quick-start. For everything else, see `docs/`:

| Doc | Covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Tech stack, system/process architecture, data-flow diagrams, design rationale |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | Every endpoint — params, request/response bodies, status codes |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | ER diagram and field-by-field notes for the database tables |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Docker Compose & local dev setup, full env var reference, production considerations |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Analyst walkthrough of the dashboard's 4 tabs |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Repo layout, running tests, how to extend the platform |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operational procedures — retrain the model, tune detection, troubleshoot syncs |
| [`CHANGELOG.md`](CHANGELOG.md) | What each of the 9 build phases added |

## Project layout

```
backend/            FastAPI app, SQLAlchemy models, services, API routes, tests
  app/
    models/          ORM models (alerts, incidents, configs, users, audit, model registry)
    schemas/         Pydantic request/response schemas
    services/        splunk_service, snort_service, alert_ingest, correlation, ml_service
    api/routes/      health, auth, audit, splunk, snort, alerts, incidents, detection_configs, ml
    scheduler.py     background periodic sync loop
    main.py          app factory + lifespan (startup sync, default configs)
  alembic/           migrations
  tests/             pytest suite (see below)
frontend/            React + TypeScript + Tailwind SOC dashboard, Vitest tests
snort/               snort.conf, local.rules, Docker image, demo pcap + generator
config/settings.yaml lowest-priority settings layer (env vars / .env override it)
docker-compose.yml   backend + frontend + splunk + snort services
scripts/             setup.sh, dev.sh, healthcheck.sh
docs/                architecture, API reference, data model, deployment, user guide, development, runbook
```

## How detection flows into an incident

1. **Ingest** — `POST /api/v1/snort/sync` tails Snort's alert log and
   parses each `alert_fast` block; `POST /api/v1/splunk/sync` runs a
   saved Splunk search and pulls matching events. Both paths create
   `Alert` rows through a shared idempotent helper
   (`services/alert_ingest.py`) keyed on a per-source `external_id`, so
   re-running a sync never duplicates alerts.
2. **Correlate** — `POST /api/v1/incidents/correlate` (or the background
   scheduler, if `AUTO_CORRELATE_ENABLED=true`) groups un-escalated
   alerts by `source_ip` within a tunable window and opens an `Incident`
   once the count crosses a threshold (both stored as a `DetectionConfig`
   row named `source_ip_burst`, editable via `/api/v1/detection-configs`).
3. **Score** — `POST /api/v1/ml/train` fits an `IsolationForest` on
   per-source-IP alert features (alert count, distinct signatures/ports,
   severity mix); `POST /api/v1/ml/score-and-alert` scores current
   activity and creates `ML_ANOMALY`-sourced alerts for outliers, which
   flow back through the same triage/correlation pipeline.
4. **Triage** — analysts work alerts/incidents via `PATCH
   /api/v1/alerts/{id}` and `PATCH /api/v1/incidents/{id}`; every
   mutation writes an `AuditRecord` (actor, action, before/after, note).

## Configuration

Settings resolve in this order (highest wins): real environment variables
→ `.env` → `config/settings.yaml` → field defaults in
`backend/app/config.py`. See that file's docstring for the custom
`YamlSettingsSource` that implements this, and
`backend/tests/test_config.py` for the regression coverage (a Phase 1 bug
where YAML subkeys were prefixed with their section name is specifically
guarded against there).

## Testing

`backend/tests/` covers config precedence, ORM models, the Snort parser
(including a fixture captured
from a **real installed Snort binary** run against the generated demo
pcap — see `snort/pcaps/README.md`), the Splunk HEC/search client
(mocked via `respx`), alert ingestion idempotency, the correlation
engine, the background scheduler, every API route, the ML
training/scoring service, and a full end-to-end pipeline test
(ingest → correlate → triage → ML train → score) through the real HTTP
API. `frontend/src/` (Vitest + React Testing Library) covers the shared
components and a fetch-mocked integration suite over the whole dashboard.
Run both suites against the current checkout before citing test counts or
coverage figures. See `docs/DEVELOPMENT.md` for commands.

## Known limitations (lab scope)

- SQLite by default; `DATABASE_URL` accepts any SQLAlchemy-supported URL
  (e.g. Postgres) for anything beyond a single-box lab.
- ML scores are Isolation Forest `decision_function` values, not
  probabilities. `f1_score` remains null until a labeled, held-out
  evaluation has been run; there is no ground truth in the bundled lab
  traffic.
- Snort runs in pcap-replay mode by default in Docker Compose (no live
  traffic capture needed to see the stack work end-to-end); set
  `SNORT_MODE=live` + `SNORT_INTERFACE` for a real interface.
