from __future__ import annotations


def test_create_list_update_detection_config(client):
    resp = client.post(
        "/api/v1/detection-configs",
        json={
            "name": "custom_rule",
            "rule_type": "ml_threshold",
            "enabled": True,
            "threshold": 0.5,
        },
    )
    assert resp.status_code == 201
    config = resp.json()

    resp2 = client.get("/api/v1/detection-configs")
    assert resp2.status_code == 200
    assert any(c["name"] == "custom_rule" for c in resp2.json())

    resp3 = client.patch(
        f"/api/v1/detection-configs/{config['id']}",
        json={"enabled": False},
    )
    assert resp3.status_code == 200
    assert resp3.json()["enabled"] is False


def test_duplicate_name_conflict(client):
    payload = {"name": "dup_rule", "rule_type": "snort_rule", "enabled": True}
    resp1 = client.post("/api/v1/detection-configs", json=payload)
    assert resp1.status_code == 201
    resp2 = client.post("/api/v1/detection-configs", json=payload)
    assert resp2.status_code == 409


def test_get_detection_config_404(client):
    resp = client.get("/api/v1/detection-configs/does-not-exist")
    assert resp.status_code == 404


def test_update_detection_config_404(client):
    resp = client.patch("/api/v1/detection-configs/does-not-exist", json={"enabled": False})
    assert resp.status_code == 404


def test_get_detection_config_by_id(client):
    created = client.post(
        "/api/v1/detection-configs",
        json={"name": "fetchable_rule", "rule_type": "correlation", "enabled": True},
    ).json()
    resp = client.get(f"/api/v1/detection-configs/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "fetchable_rule"
