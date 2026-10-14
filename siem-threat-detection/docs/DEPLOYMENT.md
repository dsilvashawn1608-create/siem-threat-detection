# Deployment Guide

## Option A: Docker Compose (full stack)

```bash
cp .env.example .env   # fill in SPLUNK_HEC_TOKEN etc. once Splunk is up
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
1. `docker compose up --build` and wait for Splunk's Web UI
   (`http://localhost:8001`) to respond.
2. In Splunk Web, create an HEC token for index `siem_threat_detection`
   and put it in `.env` as `SPLUNK_HEC_TOKEN`, then `docker compose up -d
   --build backend` to pick it up (the backend reads `.env` at startup,
   not live).
3. Visit `http://localhost:5173` for the dashboard, `http://localhost:8000/docs`
   for interactive API docs.
4. `./scripts/healthcheck.sh` for a one-shot smoke test of the
   health/alerts/incidents/ml endpoints.

## Option B: Local dev (no Docker)

```bash
./scripts/setup.sh   # backend venv + deps + alembic upgrade head, npm install
./scripts/dev.sh      # uvicorn --reload (8000) + vite (5173) together, Ctrl-C stops both
```

This is the faster loop for backend/frontend iteration — no image
rebuilds — but you're responsible for having a Splunk instance and a
Snort alert log reachable yourself (or running with
`AUTO_SYNC_ENABLED=false` and working purely through `POST
/api/v1/alerts` / the dashboard's manual-create forms).

## Configuration reference

Settings resolve in this order (highest wins): **real environment
variables → `.env` → `config/settings.yaml` → field defaults in
`backend/app/config.py`**. `.env.example` is the quick-start subset;
every field below can also be set there or as a real env var.

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | free-form label, surfaced on `/health` |
| `DEBUG` | `false` | |
| `API_V1_PREFIX` | `/api/v1` | |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | comma-separated, **not** JSON (see `config.py` docstring) |
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

- **No authentication/authorization.** Every endpoint is open, and
  `actor` on triage actions is a client-supplied query parameter, not an
  authenticated identity. Add an auth layer (API keys, OIDC, etc.)
  before exposing this beyond an isolated lab network.
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
- **CORS is wide open to the two dev origins** by default; tighten
  `CORS_ORIGINS` to the real frontend origin(s) in any shared
  deployment.
