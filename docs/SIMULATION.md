# Gemini Lab Simulation (v2)

Generates realistic **synthetic** alerts so the dashboard, correlation engine
and Isolation Forest have something meaningful to work on. Nothing here sends
network traffic or touches real hosts.

```
"slow APT intrusion, some noise"
        │
        ▼
  planner.py ── Gemini (structured JSON) ──┐   no key / error / junk output
        │                                   ├─> keyword fallback planner
        ▼                                   ┘
  schemas.py   validate + clamp  (trust boundary)
        │
        ▼
  generator.py  deterministic, seeded -> timestamped alerts (cap: 300)
        │
        ▼
  your ingest adapter -> Alert rows -> correlation / ML / dashboard
```

## Try it now (no app wiring needed)

```bash
cd backend
python -m app.services.simulation "heavy ransomware attack" --offline --seed 42
GEMINI_API_KEY=... python -m app.services.simulation "slow APT intrusion with some noise"
python -m app.services.simulation "ssh brute force" --json
pytest tests/test_simulation.py -q        # 42 tests, 100% line coverage of the package
```

I have not called the live Gemini API from here (the request/response shape
follows the public `generateContent` REST format and is covered by mocked
tests), so run the second command once with your key to confirm it end to end.

## What it can simulate

| Scenario | Source | MITRE | Notes |
|---|---|---|---|
| `port_scan` | Snort | T1046 | burst, ascending port sweep |
| `ssh_brute_force` | Splunk | T1110.001 | at intensity >= 4 ends with a *successful* login (critical) |
| `failed_login_spray` | Splunk | T1110.003 | many usernames, slow |
| `web_sql_injection` | Snort | T1190 | |
| `malware_download` | Snort | T1105 | internal host -> external server |
| `c2_beaconing` | Snort | T1071.001 | periodic with ±10% jitter |
| `lateral_movement_smb` | Splunk | T1021.002 | internal -> internal |
| `dns_tunneling` | Snort | T1071.004 | long high-entropy queries to `*.example.net` |
| `data_exfiltration` | Splunk | T1041 | ends with a cumulative-volume alert |
| `benign_web_probe` | Snort | - | harmless noise for false-positive testing |

**Campaign mode** (`campaign: true`, chosen by Gemini or by keywords like
"kill chain", "APT", "ransomware") lays the scenarios out back to back in time
and reuses the same actors: one external attacker scans and brute-forces a
victim; that victim later beacons to, and exfiltrates to, the same external
server. Your correlation engine groups by `source_ip`, so you get a believable
pair of incidents (attacker, compromised host) instead of unrelated noise.

## Safety properties (all tested)

- Gemini only **chooses from a fixed enum** and sets bounded numbers; it never
  writes alerts. `schemas.py` clamps every value and drops unknown scenario
  types, so a hallucinated or prompt-injected reply can't do anything outside
  the allowlist. Caps: 5 scenarios, intensity 1-5, 240-minute window, 300
  alerts total, 500-character request.
- Only RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and your `10.20.0.0/16` lab net are used; domains are
  `example.net`. No real host can be implicated.
- Every signature starts with `[SIMULATED]`; every `raw_data` has
  `synthetic: true` and the run id; every `external_id` starts with `sim:`.
- Only the admin's request text goes to Google. No alerts, hosts or
  credentials are sent. The API key is sent in the `x-goog-api-key` header
  (not the URL), and error notes never include it.
- `raw_data` is JSON-safe (no `datetime` objects, per the Phase 3 lesson).
- If Gemini is missing, down, rate-limited or returns junk, the offline
  keyword planner takes over and `plan.planner` / `plan.planner_note` say so.

## Wiring it into the app (what I couldn't do without your source)

The package is decoupled on purpose: `run_simulation(...)` takes an
`ingest_alert` callback instead of importing your ORM. Add a route and one
adapter. **Names below are sketches; adapt them to your code.**

```python
# backend/app/api/routes/simulation.py
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.services.simulation import (
    MAX_PROMPT_CHARS, build_simulation, catalog, run_simulation,
)

router = APIRouter(prefix="/simulation", tags=["simulation"])

class SimulationRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    seed: int | None = None          # set for a repeatable demo

@router.get("/scenarios")
def scenarios(user=Depends(get_current_user)):
    return catalog()

@router.post("/preview")             # nothing is saved
def preview(req: SimulationRequest, user=Depends(require_admin), settings=Depends(get_settings)):
    return build_simulation(req.prompt, api_key=settings.gemini_api_key, seed=req.seed).summary()

@router.post("/run")
def run(req: SimulationRequest, db=Depends(get_db), user=Depends(require_admin),
        settings=Depends(get_settings)):
    def ingest(alert: dict) -> bool:
        # ADAPT: call your shared helper in services/alert_ingest.py. It should be
        # idempotent on external_id and return True only when a row was created.
        # Map alert["severity"] ("low|medium|high|critical") if your enum differs.
        return ingest_alert(db, source=alert["source"], external_id=alert["external_id"],
                            signature=alert["signature"], severity=alert["severity"],
                            source_ip=alert["source_ip"], dest_ip=alert["dest_ip"],
                            source_port=alert["source_port"], dest_port=alert["dest_port"],
                            event_time=alert["event_time"], raw_data=alert["raw_data"])
    summary = run_simulation(req.prompt, ingest_alert=ingest,
                             api_key=settings.gemini_api_key, seed=req.seed)
    write_audit(db, actor=user.username, action="simulation.run",
                note=f"{summary['title']} ({summary['created']} alerts)")   # ADAPT
    db.commit()
    return summary

@router.delete("/simulated")         # "Clear simulated data"
def clear(db=Depends(get_db), user=Depends(require_admin)):
    n = db.query(Alert).filter(Alert.external_id.like("sim:%")).delete(synchronize_session=False)
    write_audit(db, actor=user.username, action="simulation.clear", note=f"{n} alerts")
    db.commit()
    return {"deleted": n}
```

Decide how "clear" treats incidents opened from simulated alerts (delete
incidents whose alerts are all simulated, or leave them closed). Rate-limit
`/run` since each call can hit Gemini.

**Frontend (Alerts tab, admin only):** replace the single button with a request
box plus preset chips (Kill chain, SSH brute force, Ransomware, Noise only), a
**Preview** button that renders `summary` (planner badge Gemini/Offline, alert
counts, scenario rows with MITRE tags, time window), a **Run** button, and a
**Clear simulated data** button. Show a "SIMULATED" badge on any alert whose
`raw_data.synthetic` is true.

**README:** replace the "Gemini Lab Simulation" paragraph with: *Gemini plans a
simulation (up to five scenarios from ten attack types, optionally as one
multi-stage campaign); the backend generates clearly labelled synthetic alerts
and sends no network traffic. Without a Gemini key an offline keyword planner
is used.*

## Using it to exercise the rest of the SIEM

- **Correlation:** the `source_ip_burst` rule fires on any scenario whose
  alert count exceeds your threshold; run `kill chain` then **Run Correlation**.
- **Isolation Forest:** train on a quiet baseline (`benign web probe`), then run
  a heavy scenario and `score-and-alert`; the attacker IP's count/distinct
  port/severity features should stand out.
- **False positives:** mix `benign_web_probe` into a campaign to check triage
  isn't swamped.

## Keys

The `.env` you shared contained a live Gemini key, a Splunk HEC token and an
admin password. Rotate them (they're now in a chat transcript); `.env` is
already gitignored.
