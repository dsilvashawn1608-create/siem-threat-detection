from __future__ import annotations


def test_health_is_public_and_protected_routes_require_bearer(client):
    client.headers.pop("Authorization")
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/alerts").status_code == 401
    client.headers["Authorization"] = "Bearer invalid"
    assert client.get("/api/v1/alerts").status_code == 401


def test_bootstrap_admin_can_log_in(client, test_settings):
    client.headers.pop("Authorization")
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": test_settings.auth_admin_username,
            "password": test_settings.auth_admin_password,
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] > 0
    client.headers["Authorization"] = f"Bearer {token}"
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


def test_invalid_password_is_rejected(client, test_settings):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": test_settings.auth_admin_username, "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_analyst_can_triage_but_cannot_administer_detection(client):
    created = client.post(
        "/api/v1/auth/users",
        json={"username": "analyst-1", "password": "strong-analyst-password", "role": "analyst"},
    )
    assert created.status_code == 201

    analyst_login = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst-1", "password": "strong-analyst-password"},
    )
    assert analyst_login.status_code == 200
    client.headers["Authorization"] = f"Bearer {analyst_login.json()['access_token']}"

    assert client.get("/api/v1/alerts").status_code == 200
    assert client.get("/api/v1/audit").status_code == 403
    assert client.post(
        "/api/v1/detection-configs",
        json={"name": "analyst-rule", "rule_type": "correlation", "enabled": True},
    ).status_code == 403
    assert client.post("/api/v1/snort/sync").status_code == 403


def test_admin_cannot_deactivate_self(client):
    me = client.get("/api/v1/auth/me").json()
    response = client.patch(f"/api/v1/auth/users/{me['id']}/deactivate")
    assert response.status_code == 409
