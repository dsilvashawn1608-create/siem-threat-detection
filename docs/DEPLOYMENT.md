# Deployment Guide

## Option A: Docker Compose (full stack)

```bash
cp .env.example .env
# Generate unique values for AUTH_SECRET_KEY, AUTH_ADMIN_PASSWORD,
# SPLUNK_HEC_TOKEN, and SPLUNK_PASSWORD; put them in .env before startup.
python -c "import secrets; print('AUTH_SECRET_KEY=' + secrets.token_hex(32)); print('AUTH_ADMIN_PASSWORD=' + secrets.token_urlsafe(24)); print('SPLUNK_HEC_TOKEN=' + secrets.token_hex(32)); print('SPLUNK_PASSWORD=' + secrets.token_urlsafe(24))"
docker compose up --build
```

This starts four services:

| Service | Image/build | Ports (host) | Purpose |
|---|---|---|---|
| `backend` | `./backend` | `8000` | FastAPI app |
| `frontend` | `./frontend` | `5173` | React dashboard |
| `splunk` | `splunk/splunk:9.2` | `8001`→8000 (Web UI), `8088` (HEC), `8089` (REST API) | SIEM |
| `snort` | `./snort` | — | IDS (pcap-replay by default) |

`backend` depends on `splunk` and `snort` being up (not necessarily fully
initialized — Splunk in particular takes 30–60s to finish its first-boot
setup, so the first `/api/v1/splunk/*` call may briefly fail until it's
ready). `frontend` depends on `backend`.

Named volumes (`backend_data`, `snort_data`, `splunk_data`) persist the
SQLite database, Snort's alert log, and Splunk's index data across
`docker compose down`/`up` cycles; `docker compose down -v` wipes them
for a clean slate.

**First boot checklist:**
1. Put the generated secrets in `.env` before running Compose; both Splunk
   and the backend require them at startup. Do not commit or share `.env`.
2. Run `docker compose up --build` and wait for Splunk's Web UI
   (`http://localhost:8001`) to respond.
3. Sign in to the dashboard at `http://localhost:5173` with
   `AUTH_ADMIN_USERNAME` and `AUTH_ADMIN_PASSWORD`. The HEC token is
   configured for Splunk by Compose.
4. Visit `http://localhost:8000/docs` for interactive API docs.
5. Run `bash ./scripts/healthcheck.sh` for an authenticated smoke test of
   the health, alerts, incidents, and model endpoints. It reads the admin
   credentials from `.env` when they are not already exported.

## Authentication and roles

All API routes require a bearer token except `GET /api/v1/health`,
`GET /api/v1/ready`, and `POST /api/v1/auth/login`. The configured bootstrap user is an admin.
Admins can create analyst accounts with `POST /api/v1/auth/users`.
Analysts can read and triage alerts/incidents; sensor sync, model training,
detection configuration changes, user administration, and audit-log reads
are admin-only. Tokens expire after eight hours; deactivating a user
invalidates that user's token on the next request.

## Optional Gemini analysis

Create or manage a Gemini API key through
[Google AI Studio](https://aistudio.google.com/apikey), then set
`GEMINI_API_KEY` in the ignored local `.env` file. Never add a real key to
source, share it in chat, or expose it to the browser. Compose passes it
only to the backend. Recreate the backend after changing it:

```bash
docker compose up -d --build backend
```

The integration uses Google's official `google-genai` Python SDK and the
stable `gemini-2.5-flash` model listed in the
[Gemini model documentation](https://ai.google.dev/gemini-api/docs/models).
The browser can query `GET /api/v1/ai/status` (authenticated) to learn only
whether analysis is configured and which model is selected; the key is
never returned.

Analysts and admins can request `POST /api/v1/ai/alerts/{id}/analysis` or
`POST /api/v1/ai/incidents/{id}/analysis`. The backend sends only
allow-listed alert/incident fields, truncates free-text fields, limits an
incident request to its latest 20 linked alerts, excludes raw event
payloads and audit records, and treats the evidence as untrusted data.
Google processes the selected evidence to produce an explanation and
investigation suggestions; review the provider's data-handling policies
before enabling it for sensitive events. Responses separate observed
evidence from AI-generated interpretation. The model has no tools and
cannot invoke system actions; analysts must verify suggestions.

Administrators can also submit one natural-language lab request to
`POST /api/v1/ai/simulations`, or use **Gemini Lab Simulation** in the
Alerts tab. Gemini only classifies it as a port-scan pattern, repeated SSH
login failures, benign web probe, or unsupported request. The backend creates
fixed synthetic alert records marked `[SIMULATION]` with `synthetic: true`;
it uses documentation-only IP addresses, ignores user-supplied targets, and
never transmits packets, credentials, probes, or commands. Normal configured
correlation may group those records into an incident. Requests outside the
three fixed scenarios are rejected. This is demo telemetry, not validation
that a real sensor detected an attack.

Without `GEMINI_API_KEY`, the main SIEM remains available and the status
endpoint reports the optional feature as unavailable. Provider timeout,
quota/rate limit, key-authentication, connection, and malformed-response
errors are returned as sanitized user-facing messages; API credentials and
provider response details are not logged.

## SQLite backup and recovery

The Compose database is `/data/backend/siem.db` in the `backend_data`
volume. To make a consistent online backup, use SQLite's backup API inside
the backend container, then copy the result out to a separate host location:

```bash
docker compose exec -T backend python -c "import sqlite3; src=sqlite3.connect('/data/backend/siem.db'); dst=sqlite3.connect('/tmp/siem-backup.db'); src.backup(dst); dst.close(); src.close()"
docker compose cp backend:/tmp/siem-backup.db ./siem-backup.db
```

Keep backups outside the Compose volume and periodically verify recovery by
restoring into a separate test environment. Never use `docker compose down
-v` as a backup or routine troubleshooting step; it permanently removes
named-volume data.

## Option B: Local dev (no Docker)

### Windows backend-only setup

From the repository root, create `.env` from `.env.example` if it does not
already exist. Set a private `AUTH_SECRET_KEY` (at least 32 characters) and
`AUTH_ADMIN_PASSWORD` (at least 12 characters), install Python 3.12, then run:

```powershell
.\scripts\setup-backend.ps1
.\scripts\dev-backend.ps1
```

This creates `backend\.venv`, installs `backend\requirements.txt`, applies
database migrations to `backend\siem.db`, and starts the API at
`http://localhost:8000`. Interactive API documentation is available at
`http://localhost:8000/docs`. The local backend uses a separate SQLite file
from the Docker Compose volume. Splunk/Snort integrations are not required to
start the API; leave their auto-sync settings disabled unless those services
are available.

Run the backend tests with:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest -q .\backend\tests
```

### Linux/macOS full local stack

```bash
./scripts/setup.sh   # backend venv + deps + alembic upgrade head, npm install
./scripts/dev.sh      # uvicorn --reload (8000) + vite (5173) together, Ctrl-C stops both
```

These Bash scripts set up both backend and frontend. This is the faster loop
for backend/frontend iteration — no image rebuilds — but you're responsible
for having a Splunk instance and a Snort alert log reachable yourself (or
running with `AUTO_SYNC_ENABLED=false` and working purely through
`POST /api/v1/alerts` / the dashboard's manual-create forms).

## Configuration reference

Settings resolve in this order (highest wins): **real environment
variables → `.env` → `config/settings.yaml` → field defaults in
`backend/app/config.py`**. `.env.example` is the quick-start subset;
every field below can also be set there or as a real env var.

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | free-form label, surfaced on `/health`; production requires secure auth/TLS settings |
| `DEBUG` | `false` | |
| `API_V1_PREFIX` | `/api/v1` | |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | comma-separated, **not** JSON (see `config.py` docstring) |
| `AUTH_SECRET_KEY` | *(empty)* | required by Compose; at least 32 characters |
| `AUTH_ADMIN_USERNAME` | *(empty)* | required by Compose; bootstrap administrator |
| `AUTH_ADMIN_PASSWORD` | *(empty)* | required by Compose; at least 12 characters |
| `GEMINI_API_KEY` | *(empty)* | optional; private Google Gemini API key, backend only |
| `DATABASE_URL` | `sqlite:///./siem.db` | any SQLAlchemy URL, e.g. `postgresql://user:pass@host/db` |
| `LOG_LEVEL` | `INFO` | |
| `LOG_JSON` | `true` | structured JSON logs when true, plain text when false |
| `SPLUNK_HEC_URL` | `https://localhost:8088` | |
| `SPLUNK_HEC_TOKEN` | *(empty)* | **required** for `/splunk/events` and auto-sync to work |
| `SPLUNK_HEC_INDEX` | `siem_threat_detection` | |
| `SPLUNK_HEC_SOURCE` | `siem-backend` | |
| `SPLUNK_HEC_SOURCETYPE` | `_json` | |
| `SPLUNK_API_URL` | `https://localhost:8089` | REST Search API (management port) |
| `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` | `admin` / *(empty)* | used by the search-job client |
| `SPLUNK_VERIFY_TLS` | `false` | Splunk's self-signed default cert in dev |
| `SPLUNK_REQUEST_TIMEOUT_SECONDS` | `10.0` | |
| `SPLUNK_SEARCH_POLL_INTERVAL_SECONDS` / `SPLUNK_SEARCH_MAX_POLL_ATTEMPTS` | `0.5` / `20` | search-job polling backoff |
| `SNORT_ALERT_LOG_PATH` | `/data/snort/log/alert` | must match the Snort container's volume mount |
| `SNORT_RULES_PATH` | `/data/snort/rules/local.rules` | |
| `SNORT_LOG_STALE_AFTER_SECONDS` | `300.0` | |
| `SNORT_FORWARD_TO_SPLUNK` | `false` | |
| `AUTO_SYNC_ENABLED` | `false` | turns on the background scheduler (both syncs, every `SYNC_INTERVAL_SECONDS`) |
| `SYNC_INTERVAL_SECONDS` | `60.0` | |
| `SYNC_SPLUNK_QUERY` | `search index=siem_threat_detection sourcetype=snort_alert_json` | used by both the scheduler and `/splunk/sync` |
| `SYNC_SPLUNK_EARLIEST_TIME` | `-5m` | |
| `CORRELATION_DEFAULT_THRESHOLD` | `3` | seeds the `source_ip_burst` detection config on first boot only |
| `CORRELATION_DEFAULT_WINDOW_SECONDS` | `300.0` | ditto |
| `AUTO_CORRELATE_ENABLED` | `false` | ditto; after first boot, edit the DB row via `PATCH /api/v1/detection-configs` instead |
| `ML_MODEL_DIR` | `/app/models` | where trained `.joblib` files live |
| `ML_MODEL_NAME` | `isolation-forest-alert-features` | |
| `ML_CONTAMINATION` | `0.1` | IsolationForest's expected anomaly fraction |
| `ML_MIN_TRAINING_SAMPLES` | `20` | distinct source_ips with recent activity needed to train |
| `ML_SCORE_ON_INGEST_ENABLED` | `false` | reserved for a future "score every sync" hook; not currently wired into the scheduler |
| `ML_ANOMALY_SEVERITY_THRESHOLD` | `-0.2` | `decision_function` score below this ⇒ flagged anomalous |

Docker Compose also sets a few of these directly in
`docker-compose.yml`'s `environment:` block (pointing `SPLUNK_HEC_URL`/
`SPLUNK_API_URL` at the `splunk` service by container name, for
instance) — those override `.env` for the containerized backend, per the
precedence order above.

## Snort modes

`SNORT_MODE` (set on the `snort` service, not the backend):
- `pcap` (default) — replays the bundled demo pcap
  (`snort/pcaps/demo-lab-traffic.pcap`) on a loop every
  `SNORT_REPLAY_INTERVAL_SECONDS` (default 120s), so the stack produces
  alerts out of the box with no real network needed.
- `live` — requires `SNORT_INTERFACE` and a real interface to listen on
  (and the container's `NET_ADMIN`/`NET_RAW` capabilities, already
  granted in `docker-compose.yml`).

## Production considerations (beyond lab scope)

This is explicitly a lab-scale academic build; the following would need
addressing before any production use:

- **Local authentication only.** The platform provides local
  username/password accounts and analyst/admin roles, but not enterprise
  SSO, MFA, password reset, or automated account lifecycle integration.
- **No distributed rate limiter.** Put the API behind a rate-limiting
  gateway before exposing authentication or resource-intensive endpoints
  beyond the local lab.
- **ML evaluation is pending.** No labeled held-out scenario set or
  precision/recall/F1 results are currently provided; model scores are
  anomaly scores, not attack probabilities.
- **Protect `ML_MODEL_DIR`.** `joblib` uses pickle-based deserialization;
  keep the model directory writable only by the backend and trusted
  administrators, and never place user-supplied artifacts there.
- **SQLite's single-writer model** is fine for one analyst and a modest
  alert volume; point `DATABASE_URL` at PostgreSQL for concurrent
  writers or higher throughput.
- **Single-process background scheduler**: `AUTO_SYNC_ENABLED`'s loop
  runs in-process via asyncio, not a separate worker — it doesn't scale
  horizontally (running two backend replicas would double-sync) and a
  backend crash loses the in-flight cycle (harmless, since the next
  cycle just re-syncs; nothing is lost, only delayed).
- **Secrets in `.env`/plain environment variables** — fine for a lab,
  not for a shared or internet-facing deployment; use a real secrets
  manager.
- **`SPLUNK_VERIFY_TLS=false`** is a dev-only default for Splunk's
  self-signed certificate; set it `true` with a real CA-signed cert
  anywhere that matters.
- **CORS defaults are for local development**; set `CORS_ORIGINS` to the
  exact frontend origin(s) in any shared deployment.
