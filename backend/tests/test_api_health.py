from __future__ import annotations


def test_health_check(client):
    client.headers.pop("Authorization")
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


def test_readiness_check_includes_database(client):
    client.headers.pop("Authorization")
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}
