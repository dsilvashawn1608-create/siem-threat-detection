# Development Guide

## Setup

### Windows (backend only)

From the repository root, create `.env` from `.env.example` if needed, then
set `AUTH_SECRET_KEY` to a random value of at least 32 characters and
`AUTH_ADMIN_PASSWORD` to a value of at least 12 characters. Keep `.env`
private. Install Python 3.12 (the backend's pinned dependency/runtime
version), then run:

```powershell
.\scripts\setup-backend.ps1
.\scripts\dev-backend.ps1
```

The setup script creates `backend\.venv`, installs the pinned backend
requirements, and applies Alembic migrations to the local `backend\siem.db`.
The development script starts Uvicorn at `http://localhost:8000`; Swagger UI
is at `http://localhost:8000/docs`. The backend loads the repository-root
`.env` regardless of its working directory. Docker's `/data/backend/siem.db`
path is overridden for local runs, so Docker and local development use
separate databases.

Run backend tests on Windows with:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest -q .\backend\tests
```

### Linux/macOS (full local stack)

```bash
./scripts/setup.sh   # backend venv + deps + alembic upgrade head, npm install
./scripts/dev.sh      # uvicorn --reload (8000) + vite (5173) together
```

See `docs/DEPLOYMENT.md` for the full environment-variable reference and the
Docker Compose alternative.

## Repo layout

```
backend/
  app/
    models/          ORM models (Alert, Incident, DetectionConfig, AuditRecord, MLModelMetadata)
    schemas/          Pydantic request/response schemas (one module per resource)
    services/          splunk_service, snort_service, alert_ingest, correlation, ml_service
    api/routes/        health, splunk, snort, alerts, incidents, detection_configs, ml
    scheduler.py        background periodic sync loop (asyncio)
    config.py            Settings (env > .env > settings.yaml > defaults)
    database.py           engine/session factory, Base
    logging_config.py      structured JSON logging
    main.py                 app factory + lifespan
  alembic/              migrations
  tests/                pytest suite — one test module per source module, plus
                          test_end_to_end_pipeline.py (full-stack scenario)
frontend/
  src/
    App.tsx             the whole dashboard (single-file by design — see below)
    components/          StatusDot, ConsoleField, Modal/FormField (presentational, reused across App.tsx)
    __tests__/            App-level integration tests (fetch-mocked)
    components/__tests__/  per-component unit tests
snort/                  snort.conf, local.rules, Docker image, demo pcap + generator
config/settings.yaml    lowest-priority settings layer
docs/                   this directory
```

### Why `App.tsx` is one file

The dashboard is intentionally a single component file rather than
split into per-tab files/contexts. At its current size (four tabs, three
modals, shared fetch/refresh state) a context/store layer would add
indirection without a real payoff; `docs/ARCHITECTURE.md`'s "why these
design choices" section applies the same lab-scale-appropriate reasoning
used elsewhere in the project. If the dashboard grows meaningfully (a
fifth tab, nested routing, real-time updates), splitting `App.tsx` by
tab and introducing a small data-fetching layer (e.g. a `useResource`
hook per entity) would be the natural next refactor — do that before
adding more state to the existing file, not after.

## Running tests

Backend:
```bash
cd backend && source .venv/bin/activate
python -m pytest -q                                    # fast run
python -m pytest --cov=app --cov-report=term-missing   # with coverage report
```

Tests use isolated database fixtures; do not delete the development or
Docker database to run them.

Frontend:
```bash
cd frontend
npx vitest run          # run once
npx vitest               # watch mode
npx tsc -b --noEmit      # typecheck — this runs over test files too (see note below)
npm run build             # full production build (tsc -b && vite build)
```

**Always run `npm run build` (or at least `tsc -b --noEmit`) after
touching frontend test files, not just `vitest run`.** Vitest type-checks
loosely at runtime; `tsc -b` is stricter and checks every file under
`tsconfig.json`'s `"include": ["src"]`, which includes test files even
though they're never bundled into the production Vite output. A test
file that passes `vitest run` can still fail `npm run build`. See
`learnings.md` in the project's working notes for a concrete case this
bit (a `vi.fn()` mock typed loosely enough that `.mock.calls` became
`any[][]`, silently breaking a `.find()` callback's type only under
`tsc -b`).

Run the coverage command against the current checkout before publishing a
coverage figure. Prefer tests for reachable behavior over adding coverage
exclusions for untested branches.

## Adding things

### A new API endpoint
1. Add/extend a Pydantic schema in `app/schemas/`.
2. Add the route function in the matching `app/api/routes/*.py` (or a
   new router + `app.include_router(...)` in `main.py` for a new
   resource).
3. Put any non-trivial logic in `app/services/`, not the route function
   — routes should stay thin (see any existing route file for the
   pattern: resolve the DB row, call a service function or inline a
   short query, return the schema).
4. Write the test in the matching `backend/tests/test_api_*.py` before
   checking coverage — don't rely on the end-to-end test to cover a new
   route's edge cases.

### A new detection rule type
The `DetectionConfig.rule_type` enum (`snort_rule | ml_threshold |
splunk_search | correlation`) already has room for rule types beyond
`correlation`, which is the only one actually evaluated today (by
`correlation.py`). To wire up a new one:
1. Add a service function that reads the relevant `DetectionConfig` row
   (see `correlation._get_burst_config` for the pattern: read by `name`,
   fall back to `Settings` defaults if the row doesn't exist) and the
   evaluation logic.
2. Call it from wherever it should run — a new scheduler step
   (`app/scheduler.py`), a new API trigger endpoint, or inline during
   ingestion.
3. Seed a default row for it in `ensure_default_detection_configs()` if
   it should exist out of the box.

### A new ML feature
Add the column to `ml_service.FEATURE_NAMES` and compute it inside
`build_feature_table()`'s per-source_ip record. No schema migration
needed — `MLModelMetadata.feature_names` is a JSON column that already
captures whatever `FEATURE_NAMES` was at training time, and scoring
always uses the feature list stored with the loaded model (not the
current `FEATURE_NAMES`), so old and new models can coexist; retrain to
pick up the new feature.

### A frontend tab/panel
Follow the existing tab pattern in `App.tsx` (`Tab` union type, a
`{tab === "x" && <Panel/>}` block, a matching entry in the `nav`
buttons). Add fetch-mocked integration tests in
`src/__tests__/App.test.tsx` the same way the existing tabs are tested —
mock the new endpoint(s) in `beforeEach`'s `fetchMock` router, then
assert on rendered text/interactions.

### An audit-log viewer (a known gap — see `docs/USER_GUIDE.md`)
There's no `GET /api/v1/audit-records` route yet. Adding one is a
10-minute addition following the existing list-endpoint pattern (see
`app/api/routes/alerts.py::list_alerts` for the shape: optional filters,
`limit`/`offset`, a `*ListResponse` schema) plus a `AuditRecordRead`
schema and a dashboard tab or panel to show it.

## Code conventions

- Routes stay thin; business logic lives in `app/services/`.
- Every service function takes an explicit `Session` and (where it needs
  config) `Settings` as parameters rather than reaching for a global —
  this is what makes the test suite's dependency injection work cleanly
  (see the Phase 4/6 lessons in the project's working notes about
  `app.dependency_overrides` only covering `Depends(...)`-injected
  calls, not direct `get_settings()`/import-time-bound calls).
- Alert/Incident mutations that change a tracked field write an
  `AuditRecord` — keep that pattern for any new mutating endpoint
  (`docs/DATA_MODEL.md` has the field shapes).
- Idempotency for anything ingested from an external system goes through
  a stable `external_id` and `get_or_create_alert()` — don't add a
  second raw `db.add(Alert(...))` path that could duplicate rows on
  retry.
- Frontend: Tailwind utility classes inline, no CSS modules/styled-
  components; shared presentational bits go in `src/components/` and get
  their own unit test.
