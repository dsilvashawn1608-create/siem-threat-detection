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
cp .env.example .env   # fill in SPLUNK_HEC_TOKEN etc. once Splunk is up
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs
- Splunk Web: http://localhost:8001

### Local dev (no Docker)

```bash
./scripts/setup.sh   # creates backend venv, installs deps, runs migrations, npm install
./scripts/dev.sh      # runs uvicorn --reload + vite together
```

Run the test suites:

```bash
cd backend && . .venv/bin/activate && pytest -q   # 113 tests, 100% line coverage
cd frontend && npx vitest run                       # 23 tests
```

## Documentation

This README is the quick-start. For everything else, see `docs/`:

| Doc | Covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Tech stack, system/process architecture, data-flow diagrams, design rationale |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | Every endpoint — params, request/response bodies, status codes |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | ER diagram and field-by-field notes for all 5 tables |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Docker Compose & local dev setup, full env var reference, production considerations |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Analyst walkthrough of the dashboard's 4 tabs |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Repo layout, running tests, how to extend the platform |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operational procedures — retrain the model, tune detection, troubleshoot syncs |
| [`CHANGELOG.md`](CHANGELOG.md) | What each of the 9 build phases added |

## Project layout

```
backend/            FastAPI app, SQLAlchemy models, services, API routes, tests
  app/
    models/          ORM models (Alert, Incident, DetectionConfig, AuditRecord, MLModelMetadata)
    schemas/         Pydantic request/response schemas
    services/        splunk_service, snort_service, alert_ingest, correlation, ml_service
    api/routes/      health, splunk, snort, alerts, incidents, detection_configs, ml
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

`backend/tests/` (113 tests, 100% line coverage) covers config
precedence, ORM models, the Snort parser (including a fixture captured
from a **real installed Snort binary** run against the generated demo
pcap — see `snort/pcaps/README.md`), the Splunk HEC/search client
(mocked via `respx`), alert ingestion idempotency, the correlation
engine, the background scheduler, every API route, the ML
training/scoring service, and a full end-to-end pipeline test
(ingest → correlate → triage → ML train → score) through the real HTTP
API. `frontend/src/` (23 tests, Vitest + React Testing Library) covers
the shared components and a fetch-mocked integration suite over the
whole dashboard. See `docs/DEVELOPMENT.md` for commands and the
coverage philosophy behind the 100% figure.

## Known limitations (lab scope)

- SQLite by default; `DATABASE_URL` accepts any SQLAlchemy-supported URL
  (e.g. Postgres) for anything beyond a single-box lab.
- The Isolation Forest's `f1_score` field in `MLModelMetadata` is a
  training-time diagnostic (fraction *not* flagged as anomalous), not a
  held-out metric — there's no ground-truth label in lab-generated
  traffic to score against.
- Snort runs in pcap-replay mode by default in Docker Compose (no live
  traffic capture needed to see the stack work end-to-end); set
  `SNORT_MODE=live` + `SNORT_INTERFACE` for a real interface.
