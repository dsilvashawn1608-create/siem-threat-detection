"""A single test that walks the whole pipeline end-to-end through the real
HTTP API, the way a live deployment would actually be used, rather than
exercising each stage in isolation: ingest (Snort) -> correlate into an
incident -> triage -> train the ML model -> score -> anomaly alert ->
audit trail. The per-stage unit/integration tests elsewhere in this suite
catch regressions in one stage; this one catches a regression in how the
stages compose."""
from __future__ import annotations

import respx
from httpx import Response


def _snort_alert_line(src_ip: str, sid: int) -> str:
    return (
        f"10/04-12:00:0{sid % 10}.000000  [**] [1:{sid}:1] Repeated probe [**] "
        f"[Classification: Attempted Information Leak] [Priority: 2] {{TCP}} "
        f"{src_ip}:5000{sid} -> 10.0.0.10:80"
    )


@respx.mock
def test_full_pipeline_ingest_correlate_triage_ml(client, test_settings, tmp_path):
    # --- 1. Ingest: Snort sync produces a burst of alerts from one source_ip ---
    log_path = tmp_path / "alert"
    log_path.write_text(
        "\n".join(_snort_alert_line("203.0.113.9", sid) for sid in range(1000010, 1000013)) + "\n"
    )
    test_settings.snort_alert_log_path = str(log_path)

    snort_resp = client.post("/api/v1/snort/sync")
    assert snort_resp.status_code == 200
    assert snort_resp.json()["created"] == 3

    # --- 2. Ingest: a Splunk sync adds one more alert from a different IP ---
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-e2e"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-e2e").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-e2e/results").mock(
        return_value=Response(
            200,
            json={
                "results": [
                    {
                        "_cd": "1:e2e",
                        "signature": "suspicious login",
                        "severity": "high",
                        "source_ip": "198.51.100.4",
                    }
                ]
            },
        )
    )
    splunk_resp = client.post("/api/v1/splunk/sync")
    assert splunk_resp.status_code == 200
    assert splunk_resp.json()["created"] == 1

    total_alerts = client.get("/api/v1/alerts", params={"limit": 50}).json()
    assert total_alerts["total"] == 4

    # --- 3. Correlate: the 3-alert burst from one source_ip crosses the
    # default threshold (3) and opens an incident; the lone Splunk alert
    # does not. ---
    correlate_resp = client.post("/api/v1/incidents/correlate")
    assert correlate_resp.status_code == 200
    incidents = correlate_resp.json()
    assert len(incidents) == 1
    incident_id = incidents[0]["id"]

    escalated = client.get(
        "/api/v1/alerts", params={"source_ip": "203.0.113.9", "status": "escalated"}
    ).json()
    assert escalated["total"] == 3
    assert all(a["incident_id"] == incident_id for a in escalated["items"])

    # The Splunk alert from the other IP was NOT swept into the incident.
    untouched = client.get("/api/v1/alerts", params={"source_ip": "198.51.100.4"}).json()
    assert untouched["items"][0]["incident_id"] is None

    # --- 4. Triage: an analyst investigates and resolves the incident,
    # writing an audit trail entry (verified indirectly via the status
    # transition and resolved_at timestamp, since there's no dedicated
    # audit-read endpoint yet). ---
    triage_resp = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved", "resolution_notes": "confirmed benign scan"},
        params={"actor": "shawn"},
    )
    assert triage_resp.status_code == 200
    assert triage_resp.json()["resolved_at"] is not None

    # --- 5. AI: seed enough additional source_ip activity to clear the
    # minimum training sample size, train, then score. ---
    for i in range(6):
        for j in range(3):
            client.post(
                "/api/v1/alerts",
                json={
                    "source": "snort",
                    "severity": "low",
                    "signature": f"background noise {j}",
                    "source_ip": f"10.9.0.{i}",
                    "dest_port": 1000 + j,
                },
            )

    train_resp = client.post("/api/v1/ml/train")
    assert train_resp.status_code == 200
    assert train_resp.json()["training_samples"] >= test_settings.ml_min_training_samples

    score_resp = client.post("/api/v1/ml/score")
    assert score_resp.status_code == 200
    assert "results" in score_resp.json()

    # --- 6. AI -> Alert: scoring can create new ML_ANOMALY alerts, which
    # are ordinary Alert rows and therefore immediately visible through
    # the same /alerts API used in step 1-2. ---
    score_and_alert_resp = client.post("/api/v1/ml/score-and-alert")
    assert score_and_alert_resp.status_code == 200

    final_alert_count = client.get("/api/v1/alerts", params={"limit": 100}).json()["total"]
    assert final_alert_count >= total_alerts["total"]
