# API Reference

Base URL: `http://localhost:8000` (Docker Compose) · every route below,
including `/health`, is mounted under the `/api/v1` prefix. The backend also serves live,
interactive docs generated straight from the same Pydantic schemas at
`/docs` (Swagger UI) and `/redoc` — this file is a narrative companion to
those, not a replacement.

All request/response bodies are JSON. All `datetime` fields are ISO 8601
UTC. All resource IDs are UUID4 strings.

## Authentication

All routes require `Authorization: Bearer <access_token>` except
`GET /api/v1/health`, `GET /api/v1/ready`, and `POST /api/v1/auth/login`.
Tokens expire after eight hours. The bootstrap account configured in
`.env` has the `admin` role; administrators can create analyst accounts.
Sensitive operations
(ingestion/sync, model training and alerting, detection-rule changes, user
administration, audit reads) require an admin token.

### `POST /api/v1/auth/login`
Body: `{"username": "admin", "password": "<configured password>"}`.
Returns `{"access_token": "...", "token_type": "bearer", "expires_in": 28800}`.

### `GET /api/v1/auth/me`
Returns the authenticated user's `id`, `username`, `role`, `is_active`,
and `created_at`.

### `GET /api/v1/auth/users` (admin)
Returns the user list.

### `POST /api/v1/auth/users` (admin)
Creates an analyst or admin account from
`{"username": "...", "password": "...", "role": "analyst"}`. Passwords
must have at least 12 characters. Returns `201`.

### `PATCH /api/v1/auth/users/{user_id}/deactivate` (admin)
Disables a user; tokens for that account stop working immediately.
Admins cannot deactivate their own account.

## Audit

### `GET /api/v1/audit` (admin)
Returns audit records, newest first. Accepts `limit` (default 100,
maximum 500) and `offset` (default 0).

## Gemini analysis — `/api/v1/ai`

The optional Gemini assistant helps analysts interpret existing SIEM
records. Its lab simulator can create only bounded, clearly labeled synthetic
alerts; it does not send network traffic or execute actions.

### `GET /api/v1/ai/status`
Authenticated. Returns `{"available": true, "model": "gemini-2.5-flash"}`
or `available: false` when `GEMINI_API_KEY` is unset. It never returns
the key.

### `POST /api/v1/ai/alerts/{alert_id}/analysis`
Authenticated analyst or admin. Returns a structured object separating
`observed_evidence` (selected fields from the stored alert) and
`ai_interpretation`, with model, timestamp, and disclaimer. Does not send
`raw_data`, audit records, or credentials to Google.

### `POST /api/v1/ai/incidents/{incident_id}/analysis`
Authenticated analyst or admin. Analyzes the incident and up to its 20
most recent linked alerts, using the same allow-list and response shape.
Both analysis routes return `404` for an unknown resource, `503` when the
feature is not configured or provider quota/key access is unavailable,
`504` for timeout, or a sanitized `502` for provider/response failures.

### `POST /api/v1/ai/simulations` (admin)
Body: `{"prompt": "Simulate a port scan in the lab"}` (3–500 characters).
Gemini classifies the request into one of three fixed demo scenarios:
`port_scan`, `failed_logins`, or `web_probe`. The backend then creates the
corresponding bounded synthetic alerts with `[SIMULATION]` signatures, a
`synthetic: true` marker, and documentation-only IP addresses; Gemini cannot
select targets or generate executable behavior. The response reports alert
IDs and whether the currently configured correlation rule opened incidents.
No real packets, login attempts, probes, or external attack traffic are sent.
Out-of-scope requests are rejected with `422`. A missing API key returns
`503`; provider failures are sanitized as for the analysis routes.

## Conventions

- **Pagination**: list endpoints that support it take `limit` (default
  50, 1–500) and `offset` (default 0) query params and return `{items,
  total}`.
- **Audit trail**: alert/incident changes and admin user/detection-config
  changes write an `AuditRecord` (see `docs/DATA_MODEL.md`). Actor
  identity comes from the bearer token, never a caller-supplied query
  parameter. An optional `note` is included in triage audit records.
- **Errors**: `404` for an unknown resource ID, `409` for a uniqueness
  conflict (duplicate detection-config name), `422` for a validation
  error or an ML operation attempted in an invalid state (e.g. scoring
  with no trained model), `502` when a Splunk call fails.

---

## Health

### `GET /api/v1/health`
No auth, no params. Returns `{"status": "ok", "app_name": ..., "environment": ...}`.
Used by `scripts/healthcheck.sh`.

### `GET /api/v1/ready`
No auth, no params. Checks database connectivity and returns
`{"status": "ready", "database": "ok"}`. Returns `503` when the database
cannot be queried.

---

## Alerts — `/api/v1/alerts`

### `GET /api/v1/alerts`
List alerts, newest first.

| Query param | Type | Notes |
|---|---|---|
| `source` | `snort \| splunk \| ml_anomaly \| manual` | optional filter |
| `severity` | `low \| medium \| high \| critical` | optional filter |
| `status` | `new \| acknowledged \| escalated \| closed \| false_positive` | optional filter |
| `source_ip` | string | optional exact-match filter |
| `limit`, `offset` | int | pagination |

Returns `AlertListResponse`: `{items: AlertRead[], total: int}`.

### `GET /api/v1/alerts/{alert_id}`
Returns a single `AlertRead`, or `404`.

### `POST /api/v1/alerts`
Creates an alert manually (`source: manual` is typical, but any source is
accepted — this is also how the dashboard's "+ New Alert" form and the
ingestion services create rows under the hood).

Body (`AlertCreate`):
```json
{
  "source": "manual", "severity": "high", "signature": "string (required)",
  "category": "string | null", "description": "string | null",
  "source_ip": "string | null", "source_port": "int | null",
  "dest_ip": "string | null", "dest_port": "int | null",
  "protocol": "string | null", "confidence_score": "float | null",
  "raw_data": "object | null", "external_id": "string | null",
  "event_time": "datetime | null"
}
```
Returns `201` + `AlertRead`.

### `PATCH /api/v1/alerts/{alert_id}`
Triage an alert. Body (`AlertUpdate`, all fields optional):
```json
{"status": "acknowledged", "severity": "high", "description": "string", "note": "string"}
```
Changed `status`, `severity`, and `description` fields are audited.
Returns the updated `AlertRead`, or `404`.

---

## Incidents — `/api/v1/incidents`

### `GET /api/v1/incidents`
List incidents, newest first. Query params: `status`
(`open|investigating|contained|resolved|closed`), `severity`
(`low|medium|high|critical`), `limit`, `offset`. Returns
`IncidentListResponse`.

### `GET /api/v1/incidents/{incident_id}`
Returns `IncidentRead`, or `404`.

### `POST /api/v1/incidents`
Opens an incident manually and, if `alert_ids` is given, escalates those
alerts onto it (`Alert.status → escalated`).

Body (`IncidentCreate`):
```json
{
  "title": "string (required)", "description": "string | null",
  "severity": "high", "assigned_to": "string | null",
  "alert_ids": ["alert-uuid", "..."]
}
```
Returns `201` + `IncidentRead`.

### `PATCH /api/v1/incidents/{incident_id}`
Body (`IncidentUpdate`, all optional):
```json
{"status": "resolved", "severity": "high", "assigned_to": "string", "resolution_notes": "string", "note": "string"}
```
Setting `status` to `resolved` or `closed` stamps `resolved_at`
automatically. Returns the updated `IncidentRead`, or `404`.

### `POST /api/v1/incidents/correlate`
Manually runs one pass of the correlation engine (the same logic the
background scheduler runs on a timer if `AUTO_CORRELATE_ENABLED=true`).
No body. Returns `IncidentRead[]` — the incidents newly created by this
pass (empty if the `source_ip_burst` detection config is disabled or
nothing crossed threshold).

---

## Detection Configs — `/api/v1/detection-configs`

Tunable detection rules/thresholds, independent of which engine
evaluates them (`rule_type`: `snort_rule | ml_threshold | splunk_search |
correlation`). The platform seeds one row automatically on startup —
`source_ip_burst` (`rule_type: correlation`) — see
`correlation.ensure_default_detection_configs`.

### `GET /api/v1/detection-configs`
Returns `DetectionConfigRead[]`, ordered by name. No pagination (lab-scale
list).

### `GET /api/v1/detection-configs/{config_id}`
Returns `DetectionConfigRead`, or `404`.

### `POST /api/v1/detection-configs` (admin)
Body (`DetectionConfigCreate`):
```json
{
  "name": "string (required, unique)", "rule_type": "correlation",
  "enabled": true, "threshold": "float | null",
  "parameters": "object | null", "description": "string | null"
}
```
Returns `201` + `DetectionConfigRead`, or `409` if `name` already exists.

### `PATCH /api/v1/detection-configs/{config_id}` (admin)
Body (`DetectionConfigUpdate`, all optional — only fields present are
applied, via `model_dump(exclude_unset=True)`):
```json
{"enabled": false, "threshold": 5, "parameters": {"window_seconds": 600}, "description": "string"}
```
This is how the dashboard's config-tab ON/OFF toggle and the
`source_ip_burst` threshold/window are tuned at runtime without a
redeploy. Returns the updated `DetectionConfigRead`, or `404`.

---

## ML — `/api/v1/ml`

### `GET /api/v1/ml/models`
Returns `MLModelMetadataRead[]`, newest first — the full training
history, including which version (if any) `is_active`.

### `POST /api/v1/ml/train` (admin)
Builds the feature table from alert history (see
`docs/ARCHITECTURE.md` §4), fits a fresh `IsolationForest`, persists it
to `ML_MODEL_DIR` via joblib, deactivates any previously-active model of
the same name, and registers the new `MLModelMetadata` row as active.

Returns `MLTrainResponse`:
```json
{"metadata": {"...": "MLModelMetadataRead"}, "training_samples": 42, "feature_names": ["alert_count", "..."]}
```
`422` if fewer than `ML_MIN_TRAINING_SAMPLES` distinct source_ips have
recent alerts.

### `POST /api/v1/ml/score`
Scores every `source_ip` with recent activity against the active model.
Returns `MLScoreResponse`:
```json
{
  "model_version": "20261007T160000Z",
  "results": [{"source_ip": "10.0.0.5", "score": -0.31, "is_anomaly": true, "features": {"alert_count": 12.0, "...": "..."}}],
  "anomalies_flagged": 1
}
```
Sorted most-anomalous first (lowest `decision_function` score). `422` if
no active model exists yet — train one first. These are uncalibrated
anomaly scores, not probabilities or confidence percentages.

### `POST /api/v1/ml/score-and-alert` (admin)
Runs the same scoring pass and, for every `source_ip` flagged
`is_anomaly`, creates (idempotently, once per source_ip per UTC day) an
`Alert` with `source=ml_anomaly`. Returns the list of newly created
alert IDs (`string[]`; empty if nothing new was anomalous or everything
anomalous today was already alerted). `422` under the same no-model
condition as `/score`.

---

## Snort — `/api/v1/snort`

### `POST /api/v1/snort/sync`
Admin-only. Reads and parses `SNORT_ALERT_LOG_PATH` (an `alert_fast`-format log —
see `docs/ARCHITECTURE.md`), creates one `Alert` per new, parseable
block (`source=snort`, idempotent on an `external_id` built from the
alert's gid/sid/rev/timestamp). No body.

Returns `SnortSyncResponse`:
```json
{"read_lines": 120, "parsed": 8, "created": 6, "skipped_duplicates": 2, "skipped_unparseable": 0}
```

---

## Splunk — `/api/v1/splunk`

### `POST /api/v1/splunk/events`
Admin-only. Forwards one event to Splunk's HTTP Event Collector (HEC). Body
(`SplunkEventIn`):
```json
{"event": {"...": "any JSON object, required"}, "source_ip": "string | null", "severity": "string | null", "signature": "string | null", "time": "datetime | null"}
```
Returns Splunk's own HEC acknowledgement JSON as-is. `502` if the HEC
call fails (bad token, Splunk unreachable, etc.).

### `POST /api/v1/splunk/search`
Admin-only. Runs an ad-hoc Splunk search job to completion (create → poll → fetch
results, via the REST Search API) and returns the raw results. Body
(`SplunkSearchRequest`):
```json
{"query": "search index=siem_threat_detection ...", "earliest_time": "-15m", "latest_time": "now"}
```
Returns `SplunkSearchResult`: `{"results": [{"...": "event fields"}], "result_count": 12}`.
`502` on a Splunk-side error.

### `POST /api/v1/splunk/sync`
Admin-only. Runs the configured `SYNC_SPLUNK_QUERY` (from `Settings`, not a request
body) over `SYNC_SPLUNK_EARLIEST_TIME`, and creates one `Alert` per new
result (`source=splunk`, idempotent on an `external_id` derived from the
result, severity parsed from the result's `severity` field and falling
back to `medium` if unrecognized). No body.

Returns `SplunkSyncResponse`:
```json
{"fetched": 10, "created": 7, "skipped_duplicates": 3}
```
`502` if the underlying search fails.

---

## Trying it end-to-end

```bash
# Sign in once and attach the bearer token to every protected request.
TOKEN="$(curl -sS -X POST localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<AUTH_ADMIN_PASSWORD>"}' |
  python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
AUTH=(-H "Authorization: Bearer $TOKEN")

# 1. ingest from both sensors
curl "${AUTH[@]}" -X POST localhost:8000/api/v1/snort/sync
curl "${AUTH[@]}" -X POST localhost:8000/api/v1/splunk/sync

# 2. correlate bursts into incidents
curl "${AUTH[@]}" -X POST localhost:8000/api/v1/incidents/correlate

# 3. train + score for anomalies
curl "${AUTH[@]}" -X POST localhost:8000/api/v1/ml/train
curl "${AUTH[@]}" -X POST localhost:8000/api/v1/ml/score-and-alert

# 4. triage
curl "${AUTH[@]}" -X PATCH "localhost:8000/api/v1/alerts/<id>" \
  -H "content-type: application/json" \
  -d '{"status": "acknowledged", "note": "looks like a scan, watching it"}'
```

`backend/tests/test_end_to_end_pipeline.py` exercises exactly this
sequence as an automated regression test.
