# Operational Runbook

Common procedures for operating the lab stack. Assumes Docker Compose
unless noted; see `docs/DEPLOYMENT.md` for the local-dev equivalents.

---

## Retrain the ML model

**When**: after a meaningful amount of new alert history has
accumulated, if scoring seems off (too many/few anomalies), or after
changing `ml_contamination`/`ml_anomaly_severity_threshold`.

```bash
curl -X POST localhost:8000/api/v1/ml/train
```

- Fails with `422` if fewer than `ML_MIN_TRAINING_SAMPLES` (default 20)
  distinct source_ips have alerts in the training window — ingest more
  first (see "Force a sync" below), or lower the setting for a small
  demo dataset.
- The new model is activated immediately; the previous active version is
  deactivated but its file and metadata row are kept (visible via `GET
  /api/v1/ml/models`), so nothing is lost.
- To roll back to a previous model without retraining: there's no API
  for this today — set the desired row's `is_active=true` and the
  current active row's to `false` directly in the database (see
  `docs/DATA_MODEL.md`'s `MLModelMetadata` section), or add a `POST
  /api/v1/ml/models/{id}/activate` endpoint following the pattern in
  `docs/DEVELOPMENT.md`.

## Force a sync (don't want to wait for the scheduler)

```bash
curl -X POST localhost:8000/api/v1/snort/sync
curl -X POST localhost:8000/api/v1/splunk/sync
```

Safe to run anytime — both are idempotent, so re-running after a
scheduled sync just reports more `skipped_duplicates`, never duplicate
alerts. Useful right before a demo, or after manually dropping a new pcap
into the Snort container.

## Run correlation on demand

```bash
curl -X POST localhost:8000/api/v1/incidents/correlate
```

Returns the newly created incidents (empty list if nothing crossed
threshold, or if the `source_ip_burst` config is disabled — check `GET
/api/v1/detection-configs`).

## Investigate why a burst didn't become an incident

1. `GET /api/v1/detection-configs` — confirm `source_ip_burst.enabled`
   is `true`, note its `threshold` and `parameters.window_seconds`.
2. `GET /api/v1/alerts?source_ip=<ip>&status=new` — count how many
   un-escalated alerts exist for that IP and check their `created_at`
   spread against the window. An alert already `escalated` (attached to
   an earlier incident) or outside the window doesn't count toward a new
   burst.
3. If the count is below threshold, either wait for more, lower the
   threshold (`PATCH /api/v1/detection-configs/{id}` with a smaller
   `threshold`), or widen the window
   (`{"parameters": {"window_seconds": 600}}`).

## Tune detection sensitivity

```bash
# make the source_ip_burst rule fire sooner (lower threshold)
curl -X PATCH localhost:8000/api/v1/detection-configs/<config-id> \
  -H "content-type: application/json" -d '{"threshold": 2}'

# widen the correlation window to 10 minutes
curl -X PATCH localhost:8000/api/v1/detection-configs/<config-id> \
  -H "content-type: application/json" -d '{"parameters": {"window_seconds": 600}}'

# turn a rule off entirely
curl -X PATCH localhost:8000/api/v1/detection-configs/<config-id> \
  -H "content-type: application/json" -d '{"enabled": false}'
```
Takes effect on the next correlation pass — no restart needed.

## Rotate the Splunk HEC token

1. In Splunk Web (`http://localhost:8001`), generate a new HEC token for
   index `siem_threat_detection` and disable/delete the old one.
2. Update `SPLUNK_HEC_TOKEN` in `.env`.
3. `docker compose up -d --build backend` — the backend only reads
   `.env` at process startup, so a config-only change still needs a
   container restart (not a full rebuild if you're running local dev —
   just stop/restart `uvicorn`).

## Troubleshoot: dashboard shows "Unexpected token '<' ... is not valid JSON"

The frontend code calls relative paths like `/api/v1/alerts`. In Docker
Compose, the `frontend` container serves the production build through
nginx, which proxies `/api/` to the `backend` service
(`frontend/nginx.conf`) — without that proxy, a request to `/api/v1/...`
just falls through to the SPA's own `index.html`, and the browser's
`fetch` then fails trying to parse HTML as JSON. If you see this error:

1. Confirm you're running the current `frontend/Dockerfile` (nginx-based,
   not the old `serve`-based one) and `frontend/nginx.conf` exists.
2. Rebuild just the frontend container: `docker compose up -d --build
   frontend`.
3. If it's still broken, check the `backend` service is actually up
   (`docker compose ps`) — nginx's proxy target is the Compose service
   name `backend:8000`, which only resolves inside the Compose network.

This doesn't affect local dev (`./scripts/dev.sh`) — Vite's own dev
server proxy (`vite.config.ts`) handles `/api` there instead.

## Troubleshoot: Splunk sync returning 502

- `502` from `/api/v1/splunk/sync` or `/search` means the HEC/REST call
  itself failed (`SplunkServiceError`), not a validation problem.
- Check Splunk is actually up: `curl -k https://localhost:8089/services/server/info`
  (or the Compose service name `splunk` from inside the backend
  container).
- Check `SPLUNK_HEC_TOKEN`/`SPLUNK_USERNAME`/`SPLUNK_PASSWORD` are
  correct and the token is enabled for the right index.
- Check `SPLUNK_VERIFY_TLS` — with Splunk's self-signed dev certificate,
  this should be `false` (the lab default); a `true` value against a
  self-signed cert will fail every call with a TLS error, surfaced here
  as the same `502`.

## Troubleshoot: Snort sync creating 0 alerts

1. `cat` or `tail` the file at `SNORT_ALERT_LOG_PATH` (default
   `/data/snort/log/alert`, mounted from the `snort_data` volume) —
   if it's empty, Snort itself isn't generating alerts yet. Check the
   `snort` container's logs for `"0 Snort rules read"` (a `snort.conf`
   pointing at the wrong `$RULE_PATH` — see `docs/ARCHITECTURE.md`'s
   environment notes) or confirm `SNORT_MODE=pcap` is actually replaying
   (`SNORT_REPLAY_INTERVAL_SECONDS`, default 120s — the demo pcap is
   small, so give it a full cycle).
2. If the log has content but `skipped_unparseable` is nonzero in the
   sync response, a line didn't match the expected `alert_fast` block
   format — compare against `snort/pcaps/README.md`'s captured sample
   and `backend/app/services/snort_service.py`'s parser.
3. If `parsed` is nonzero but `created` is 0 and `skipped_duplicates`
   equals `parsed`, you're re-syncing already-ingested alerts — this is
   expected and not an error (see "Force a sync" above).

## Reset to a clean demo state

```bash
docker compose down -v   # drops backend_data/snort_data/splunk_data volumes
docker compose up --build
```
Or, for local dev without Docker:
```bash
cd backend && source .venv/bin/activate
rm -f siem.db
alembic upgrade head
```
Either wipes all alerts/incidents/configs/models/audit history. The
`source_ip_burst` detection config is reseeded automatically on next
backend startup (`ensure_default_detection_configs`).

## Check system health quickly

```bash
./scripts/healthcheck.sh
```
Hits `/health`, `/alerts?limit=1`, `/incidents?limit=1`, and
`/ml/models`; reports `FAILED: ...` per endpoint rather than stopping at
the first failure, so one down dependency doesn't hide others.
