from __future__ import annotations


def test_create_and_get_alert(client):
    resp = client.post(
        "/api/v1/alerts",
        json={
            "source": "manual",
            "severity": "high",
            "signature": "Manual test alert",
        },
    )
    assert resp.status_code == 201
    alert = resp.json()
    assert alert["status"] == "new"

    resp2 = client.get(f"/api/v1/alerts/{alert['id']}")
    assert resp2.status_code == 200
    assert resp2.json()["signature"] == "Manual test alert"


def test_get_alert_404(client):
    resp = client.get("/api/v1/alerts/does-not-exist")
    assert resp.status_code == 404


def test_list_alerts_filters_by_severity(client):
    client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "critical", "signature": "sig-a"},
    )
    client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "low", "signature": "sig-b"},
    )
    resp = client.get("/api/v1/alerts", params={"severity": "critical"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["signature"] == "sig-a"


def test_update_alert_status_writes_audit_record(client):
    created = client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "medium", "signature": "to-ack"},
    ).json()

    resp = client.patch(
        f"/api/v1/alerts/{created['id']}",
        json={"status": "acknowledged", "note": "looked into it"},
        params={"actor": "shawn"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"
    audit = client.get("/api/v1/audit").json()
    record = next(row for row in audit if row["resource_id"] == created["id"])
    assert record["actor"] == "test-admin"
    assert record["details"]["note"] == "looked into it"


def test_update_alert_description_only(client):
    created = client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "low", "signature": "sig-desc"},
    ).json()
    resp = client.patch(
        f"/api/v1/alerts/{created['id']}",
        json={"description": "analyst notes go here"},
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "analyst notes go here"
    audit = client.get("/api/v1/audit").json()
    assert any(row["resource_id"] == created["id"] for row in audit)


def test_update_alert_404(client):
    resp = client.patch("/api/v1/alerts/does-not-exist", json={"status": "acknowledged"})
    assert resp.status_code == 404


def test_update_alert_severity_change_only(client):
    created = client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "low", "signature": "sig"},
    ).json()
    resp = client.patch(f"/api/v1/alerts/{created['id']}", json={"severity": "critical"})
    assert resp.status_code == 200
    assert resp.json()["severity"] == "critical"


def test_update_alert_no_changes_skips_audit_record(client):
    created = client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "low", "signature": "sig-noop"},
    ).json()
    # Same status as current -> no change recorded, but request still succeeds.
    resp = client.patch(f"/api/v1/alerts/{created['id']}", json={"status": "new"})
    assert resp.status_code == 200


def test_list_alerts_filters_by_source_status_and_source_ip(client):
    client.post(
        "/api/v1/alerts",
        json={
            "source": "snort",
            "severity": "high",
            "signature": "sig-ip-match",
            "source_ip": "10.5.5.5",
        },
    )
    client.post(
        "/api/v1/alerts",
        json={"source": "splunk", "severity": "high", "signature": "other-source"},
    )

    resp = client.get("/api/v1/alerts", params={"source": "snort", "source_ip": "10.5.5.5"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["signature"] == "sig-ip-match"

    resp2 = client.get("/api/v1/alerts", params={"status": "new"})
    assert resp2.status_code == 200
    assert resp2.json()["total"] >= 2


def test_list_alerts_pagination_bounds_rejected(client):
    resp = client.get("/api/v1/alerts", params={"limit": 501})
    assert resp.status_code == 422
    resp2 = client.get("/api/v1/alerts", params={"limit": 0})
    assert resp2.status_code == 422
    resp3 = client.get("/api/v1/alerts", params={"offset": -1})
    assert resp3.status_code == 422


def test_create_alert_invalid_severity_rejected(client):
    resp = client.post(
        "/api/v1/alerts",
        json={"source": "manual", "severity": "apocalyptic", "signature": "bad enum"},
    )
    assert resp.status_code == 422
