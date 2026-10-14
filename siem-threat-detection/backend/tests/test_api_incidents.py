from __future__ import annotations


def test_create_incident_with_alerts_escalates_them(client):
    alert = client.post(
        "/api/v1/alerts",
        json={"source": "snort", "severity": "high", "signature": "probe"},
    ).json()

    resp = client.post(
        "/api/v1/incidents",
        json={
            "title": "Suspicious scan",
            "severity": "high",
            "alert_ids": [alert["id"]],
        },
    )
    assert resp.status_code == 201
    incident = resp.json()
    assert incident["status"] == "open"

    updated_alert = client.get(f"/api/v1/alerts/{alert['id']}").json()
    assert updated_alert["status"] == "escalated"
    assert updated_alert["incident_id"] == incident["id"]


def test_update_incident_status_sets_resolved_at(client):
    incident = client.post(
        "/api/v1/incidents",
        json={"title": "Test incident", "severity": "medium"},
    ).json()

    resp = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"status": "resolved", "resolution_notes": "false alarm"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] is not None


def test_get_incident_by_id(client):
    created = client.post(
        "/api/v1/incidents", json={"title": "Fetchable incident", "severity": "low"}
    ).json()
    resp = client.get(f"/api/v1/incidents/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Fetchable incident"


def test_update_incident_severity_change(client):
    incident = client.post(
        "/api/v1/incidents", json={"title": "Escalating", "severity": "low"}
    ).json()
    resp = client.patch(f"/api/v1/incidents/{incident['id']}", json={"severity": "critical"})
    assert resp.status_code == 200
    assert resp.json()["severity"] == "critical"


def test_get_incident_404(client):
    resp = client.get("/api/v1/incidents/does-not-exist")
    assert resp.status_code == 404


def test_update_incident_404(client):
    resp = client.patch("/api/v1/incidents/does-not-exist", json={"status": "resolved"})
    assert resp.status_code == 404


def test_list_incidents_filters_by_status_and_severity(client):
    client.post("/api/v1/incidents", json={"title": "Low one", "severity": "low"})
    client.post("/api/v1/incidents", json={"title": "Critical one", "severity": "critical"})

    resp = client.get("/api/v1/incidents", params={"severity": "critical"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Critical one"

    resp2 = client.get("/api/v1/incidents", params={"status": "open"})
    assert resp2.status_code == 200
    assert resp2.json()["total"] >= 2


def test_update_incident_assigned_to_and_resolution_notes(client):
    incident = client.post(
        "/api/v1/incidents", json={"title": "Needs owner", "severity": "medium"}
    ).json()
    resp = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"assigned_to": "shawn", "resolution_notes": "investigating further"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["assigned_to"] == "shawn"
    assert body["resolution_notes"] == "investigating further"


def test_correlate_endpoint_creates_incident_from_bursts(client):
    for _ in range(3):
        client.post(
            "/api/v1/alerts",
            json={
                "source": "snort",
                "severity": "medium",
                "signature": "burst probe",
                "source_ip": "10.0.0.99",
            },
        )
    resp = client.post("/api/v1/incidents/correlate")
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) == 1
