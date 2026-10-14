# User Guide — SOC Dashboard

This is a walkthrough of the React dashboard (`http://localhost:5173`)
for an analyst using the platform day to day. Everything here is also
reachable directly through the API (`docs/API_REFERENCE.md`) — the
dashboard is a thin client over it, auto-refreshing every 15 seconds and
on-demand via the **REFRESH** button.

## Layout

```
┌─────────────────────────────────────────────────────────────┐
│ SIEM THREAT DETECTION PLATFORM         last sync 10:42:03 ⟳ │
├───────────────┬───────────────┬───────────────┬─────────────┤
│  New Alerts   │ Open Incidents│ Total Alerts  │ Active Model│
│      4        │       1       │      37       │ 2026…T1600Z │
├───────────────┴───────────────┴───────────────┴─────────────┤
│  alerts   incidents   ml   Detection Configs    [+ New Alert]│
│  [Source ▾] [Severity ▾] [Status ▾] [search...]      12 / 37 │
├────────────────────────────────────────────┬─────────────────┤
│  table (click a row to open its detail)     │  Detail Panel   │
└──────────────────────────────────────────────────────────────┘
```

The four stat tiles at the top are always visible regardless of which
tab is open: **New Alerts** (status=`new`), **Open Incidents**
(status=`open` or `investigating`), **Total Alerts**, and **Active ML
Model** (the currently-active trained model's version, or "none
trained").

## Alerts tab

The default view. A filterable, sortable (newest-first) table of every
alert.

- **Filters**: Source (`snort`/`splunk`/`ml_anomaly`/`manual`), Severity,
  Status, and a free-text search box that matches against the
  signature, source IP, and dest IP. Filters combine (AND), and the
  counter in the top-right shows `filtered / total`.
- **Row click** opens the **Alert Detail** panel on the right: full
  fields (source, severity, status, signature, category, source/dest
  IP+port, which incident it's attached to if any, created time), plus
  an **Escalate to Incident** button — shown only for alerts not already
  attached to an incident — which opens a new incident with this alert
  escalated onto it in one click.
- **ACK button**: appears inline on any row with status `new`; one click
  acknowledges it (`PATCH .../alerts/{id}` with `status: acknowledged`)
  without opening the detail panel.
- **+ New Alert**: opens a form to create an alert by hand (source,
  severity, signature, optional source/dest IP) — useful for a tabletop
  exercise or logging something observed outside the two sensors.

## Incidents tab

Incidents are what the correlation engine (or a manual escalation)
produces when alerts from the same `source_ip` pile up.

- **Filters**: Severity, Status.
- **Row click** opens the **Incident Detail** panel: title, severity,
  status, assignee, description, created/resolved timestamps.
- **RESOLVE button**: inline on any row not already `resolved`/`closed`;
  marks it resolved in one click.
- **Run Correlation**: manually triggers one correlation pass right now
  (`POST /incidents/correlate`) instead of waiting for the background
  scheduler — useful right after a sync, or when
  `AUTO_CORRELATE_ENABLED` is off and you want to run it on demand. The
  action banner reports how many new incidents it created.
- **+ New Incident**: opens an incident by hand, with no alerts attached
  yet (attach alerts afterward by escalating them from the Alerts tab).

> If this tab is empty, remember an incident only opens once a
> `source_ip` crosses the `source_ip_burst` config's threshold within
> its window — a handful of alerts from different IPs, or alerts already
> below threshold, won't show up here. Check the Detection Configs tab
> to see or raise the current threshold.

## ML tab

Controls for the anomaly-detection pipeline (`docs/ARCHITECTURE.md` §4
has the full mechanics).

- **Train Isolation Forest**: fits a fresh model on current alert
  history and registers it as the new active version. Fails with an
  error message if there isn't enough recent alert history yet (see
  `ML_MIN_TRAINING_SAMPLES` in `docs/DEPLOYMENT.md`).
- **Score & Create Anomaly Alerts**: scores current activity against the
  active model and creates `ml_anomaly`-sourced alerts (visible back on
  the Alerts tab, filterable by Source = `ml_anomaly`) for any
  `source_ip` that comes back anomalous. Safe to click repeatedly — at
  most one new anomaly alert is created per source_ip per day.
- The table below lists every trained model version, its sample count,
  when it was trained, and which one is **ACTIVE**.

## Detection Configs tab

Runtime-tunable detection rules — no redeploy needed to change
sensitivity.

- Table columns: Name, Rule Type, Threshold, Description, and an
  **ON/OFF toggle** button.
- Click the toggle to enable/disable a rule immediately
  (`PATCH .../detection-configs/{id}`).
- **+ New Config**: define a new named rule (name, rule type, optional
  numeric threshold, description). Note the dashboard's quick-create
  form doesn't expose the `parameters` JSON field (e.g. a
  correlation rule's `window_seconds`) — set that via the API directly
  (`docs/API_REFERENCE.md`) if you need to change it from the row's
  default.
- The platform seeds one config automatically on first boot:
  **`source_ip_burst`** (rule type `correlation`) — the threshold/window
  that drives everything shown on the Incidents tab. Lowering its
  threshold or widening its window makes the correlation engine more
  sensitive (more incidents from the same traffic); raising/narrowing
  does the opposite.

## A typical session

1. Open the **Incidents** tab, click **Run Correlation** to pick up
   anything that's crossed threshold since the last scheduled pass.
2. Review any new incidents; click one to see which alerts fed it.
3. Switch to **Alerts**, filter by Status=`new`, and triage: **ACK** the
   ones that are routine, **Escalate to Incident** anything that looks
   like it should be tracked but didn't already cross the correlation
   threshold on its own.
4. Occasionally visit **ML**, click **Score & Create Anomaly Alerts** —
   anything it flags shows up back on the Alerts tab as a normal alert
   to triage like any other.
5. If a detection rule is too noisy or too quiet, open **Detection
   Configs** and toggle it off or adjust its threshold.

## Limitations to know about

- Sign in with the local account provisioned in `.env`. Admins can
  create analyst accounts through `POST /api/v1/auth/users`; actor
  identity on triage actions comes from the signed-in account.
- Sensor synchronization, ML training/scoring, detection-rule editing,
  user administration, and audit-log access are admin-only. Analysts
  can read and triage alerts/incidents.
- The dashboard polls every 15 seconds; it is not a live/streaming view,
  so a second analyst's change may take up to 15s to appear.
- There's no dedicated audit-log view in the UI yet. Admins can query
  records through `GET /api/v1/audit`.
