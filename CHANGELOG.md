# Changelog

All notable work on the SIEM Threat Detection Platform, by build phase
(the project follows a 9-phase gated build plan — see
`docs/ARCHITECTURE.md`). Phases 1–7 were rebuilt from scratch after two
sandbox resets lost the working tree; the content below reflects the
final, verified state of each phase rather than a literal build
timeline.

## Phase 9 — Documentation
- Added `docs/ARCHITECTURE.md`: tech stack, system/process architecture
  and high-level data-flow diagrams (Mermaid), the detection → incident
  → triage pipeline explained, and the reasoning behind the major design
  choices.
- Added `docs/API_REFERENCE.md`: full endpoint-by-endpoint reference for
  all seven route groups (health, alerts, incidents, detection-configs,
  ml, snort, splunk), with request/response shapes and an end-to-end
  `curl` walkthrough.
- Added `docs/DATA_MODEL.md`: ER diagram and field-by-field notes for all
  five ORM tables, plus the Alembic migration workflow.
- Added `docs/DEPLOYMENT.md`: Docker Compose and local-dev setup, a full
  environment-variable reference table, and a production-considerations
  section (auth, SQLite vs. Postgres, scheduler scaling, secrets, TLS,
  CORS).
- Added `docs/USER_GUIDE.md`: analyst-facing walkthrough of the
  dashboard's four tabs (Alerts, Incidents, ML, Detection Configs) and a
  suggested daily-triage flow.
- Added `docs/DEVELOPMENT.md`: repo layout, test commands, the coverage
  philosophy behind the Phase 8 100%-coverage pass, and step-by-step
  guides for extending the platform (new endpoint, new detection rule
  type, new ML feature, new frontend tab, the missing audit-log viewer).
- Added `docs/RUNBOOK.md`: operational procedures — retrain the model,
  force a sync, tune detection sensitivity, rotate the Splunk token,
  troubleshoot Splunk/Snort sync failures, reset to a clean demo state.
- Updated `README.md` to link out to `docs/` instead of duplicating its
  content, and marked all nine phases complete.

## Phase 8 — Testing
- Backend test suite expanded from 59 to 113 tests, reaching 100% line
  coverage (1174/1174 statements) via iterative gap-closing against
  `pytest --cov=app --cov-report=term-missing`.
- Added `backend/tests/test_end_to_end_pipeline.py`: a single scenario
  exercising ingest → correlate → triage → ML train → score through the
  real HTTP API, to catch composition regressions per-module unit tests
  can't.
- Added `backend/tests/test_database.py`, `test_logging_config.py`, and
  `test_main.py` (new coverage areas with no prior dedicated test
  modules).
- Annotated one genuinely defensive/unreachable line in
  `correlation.run_correlation_once` with `# pragma: no cover` and an
  explanatory comment, rather than writing a contrived test for it.
- Stood up the frontend test suite from zero: Vitest + jsdom + React
  Testing Library + jest-dom, 23 tests across component tests
  (`StatusDot`, `ConsoleField`, `Modal`/`FormField`) and a full
  App-level integration suite (fetch-mocked backend, covering every
  tab, filter, and triage/escalation/correlation action).
- Fixed a `tsc -b`-only TypeScript error in the new frontend test mocks
  (an untyped `vi.fn()` made `.mock.calls` resolve to `any[][]`,
  breaking a `.find()` callback's destructured-tuple typing) by typing
  the mock against an explicit `FetchFn` function type.

## Phase 7 — UI
- Built the React/TypeScript/Tailwind SOC-console dashboard: Alerts and
  Incidents tables with filter bars (source/severity/status + free-text
  search), a Detection Configs tab with an enable/disable toggle and
  create form, manual create modals for alerts/incidents/configs,
  one-click "Escalate to Incident" from the alert detail panel, and a
  "Run Correlation" button.
- 59/59 backend tests still passing (frontend-only phase); frontend
  typechecks and builds clean.

## Phase 6 — AI / Anomaly Detection
- Added `app/services/ml_service.py`: per-source_ip feature extraction
  over alert history, `IsolationForest` training (joblib-persisted,
  versioned via `MLModelMetadata`, one active model at a time), and
  scoring that creates idempotent `ML_ANOMALY`-sourced alerts for
  outliers, re-entering the same triage/correlation pipeline.
- Added `/api/v1/ml/train`, `/score`, `/score-and-alert`, `/models`.
- Fixed a Snort alert-line regex bug: a single combined IPv4/IPv6
  address character class greedily swallowed the optional `:PORT`
  suffix on IPv4 addresses, leaving ports `None` for every alert that
  had one.
- Fixed a FastAPI test-isolation bug: `app.dependency_overrides` only
  redirects `Depends(...)`-injected calls, not `get_settings()` called
  directly in `main.py`'s `lifespan` — fixed by pre-seeding
  `app.config._settings_singleton` directly in the test fixture.

## Phase 5 — Incident Engine
- Added `app/services/correlation.py`: groups alerts by `source_ip`
  within a tunable window/threshold (stored in a `DetectionConfig` row,
  `source_ip_burst`) and opens an `Incident`, escalating the
  contributing alerts.
- Added `/api/v1/incidents` CRUD and `/correlate`.
- Every triage mutation (alert or incident `PATCH`) now writes an
  `AuditRecord`.

## Phase 4 — Integration
- Unified idempotent alert ingestion into `app/services/alert_ingest.py`,
  shared by both the Snort and Splunk sync paths.
- Added the background auto-sync scheduler
  (`app/scheduler.py::periodic_sync_loop`, gated by
  `AUTO_SYNC_ENABLED`) and the unified `/api/v1/alerts` query/triage API.
- Fixed a significant config bug: `config/settings.yaml`'s nested
  sections were being flattened with a section-name prefix (e.g.
  `splunk_hec_url` became the lookup key `splunk_splunk_hec_url`),
  silently making every YAML value a no-op since Phase 1.

## Phase 3 — Snort
- Stood up a real Snort 2.9.20 install to validate the `alert_fast` text
  parser against genuine binary output (Snort 2.9 has no built-in JSON
  alert format) from a Scapy-generated demo pcap.
- Added the `snort/` Docker image, `local.rules`, and the pcap-replay
  entrypoint.

## Phase 2 — Splunk
- Added the Splunk HEC ingest client and REST search-job client.
- Added `/api/v1/splunk/events`, `/search`, `/sync` (idempotent via
  `Alert.external_id`).

## Phase 1 — Foundation
- Monorepo skeleton; `Settings` with env var → `.env` → YAML → defaults
  precedence; structured JSON logging; SQLAlchemy 2.x database layer
  (SQLite/Postgres-agnostic); the five ORM models (`Alert`, `Incident`,
  `DetectionConfig`, `MLModelMetadata`, `AuditRecord`); Alembic
  migrations.
