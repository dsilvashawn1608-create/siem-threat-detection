from __future__ import annotations

from datetime import datetime, timezone

from app.schemas.ai_analysis import AIAnalysisResponse
from app.services.gemini_service import AI_DISCLAIMER


def test_ai_status_when_key_is_not_configured(client, test_settings):
    test_settings.gemini_api_key = ""
    response = client.get("/api/v1/ai/status")
    assert response.status_code == 200
    assert response.json() == {"available": False, "model": "gemini-2.5-flash"}


def test_ai_status_never_returns_configured_api_key(client, test_settings):
    test_settings.gemini_api_key = "test-gemini-secret"
    response = client.get("/api/v1/ai/status")
    assert response.status_code == 200
    assert response.json() == {"available": True, "model": "gemini-2.5-flash"}
    assert "test-gemini-secret" not in response.text


def test_ai_status_requires_authentication(client):
    client.headers.pop("Authorization")
    assert client.get("/api/v1/ai/status").status_code == 401


def test_alert_analysis_returns_distinguished_evidence_and_interpretation(
    client, test_settings, monkeypatch
):
    alert = client.post(
        "/api/v1/alerts",
        json={
            "source": "snort",
            "severity": "high",
            "signature": "Repeated probe",
            "source_ip": "10.0.0.5",
        },
    ).json()
    test_settings.gemini_api_key = "test-gemini-secret"
    monkeypatch.setattr(
        "app.api.routes.ai_analysis.gemini_service.analyze_alert",
        lambda db, alert_id, settings: AIAnalysisResponse(
            resource_type="alert",
            resource_id=alert_id,
            model=settings.gemini_model,
            generated_at=datetime.now(timezone.utc),
            observed_evidence={"signature": "Repeated probe"},
            ai_interpretation="This could indicate reconnaissance.",
            disclaimer=AI_DISCLAIMER,
        ),
    )

    response = client.post(f"/api/v1/ai/alerts/{alert['id']}/analysis")
    assert response.status_code == 200
    body = response.json()
    assert body["observed_evidence"] == {"signature": "Repeated probe"}
    assert body["ai_interpretation"] == "This could indicate reconnaissance."
    assert "unverified" in body["disclaimer"]
    assert "test-gemini-secret" not in response.text


def test_incident_analysis_missing_incident_returns_404(client):
    response = client.post("/api/v1/ai/incidents/unknown/analysis")
    assert response.status_code == 404


def test_incident_analysis_includes_linked_alert_evidence(
    client, test_settings, monkeypatch
):
    alert = client.post(
        "/api/v1/alerts",
        json={
            "source": "snort",
            "severity": "high",
            "signature": "Repeated probe",
            "source_ip": "10.0.0.5",
            "raw_data": {"secret": "must-not-be-sent"},
        },
    ).json()
    incident = client.post(
        "/api/v1/incidents",
        json={
            "title": "Source burst",
            "severity": "high",
            "alert_ids": [alert["id"]],
        },
    ).json()
    test_settings.gemini_api_key = "test-gemini-secret"
    monkeypatch.setattr(
        "app.services.gemini_service._generate",
        lambda settings, resource_type, evidence: "Investigate this source.",
    )

    response = client.post(
        f"/api/v1/ai/incidents/{incident['id']}/analysis"
    )

    assert response.status_code == 200
    observed = response.json()["observed_evidence"]
    assert observed["incident"]["severity"] == "high"
    assert observed["alerts"][0]["signature"] == "Repeated probe"
    assert "raw_data" not in observed["alerts"][0]
    assert "must-not-be-sent" not in response.text


def test_analysis_route_returns_sanitized_provider_error(client, test_settings, monkeypatch):
    alert = client.post(
        "/api/v1/alerts",
        json={"source": "snort", "severity": "medium", "signature": "Error mapping"},
    ).json()
    test_settings.gemini_api_key = "test-gemini-secret"

    def fail(settings, resource_type, evidence):
        from app.services.gemini_service import GeminiAnalysisError

        raise GeminiAnalysisError(503, "Gemini rate limit or quota was reached.")

    monkeypatch.setattr("app.services.gemini_service._generate", fail)
    response = client.post(f"/api/v1/ai/alerts/{alert['id']}/analysis")

    assert response.status_code == 503
    assert response.json()["detail"] == "Gemini rate limit or quota was reached."
    assert "test-gemini-secret" not in response.text


def test_analysis_without_key_returns_clear_unavailable_response(
    client, test_settings
):
    alert = client.post(
        "/api/v1/alerts",
        json={"source": "snort", "severity": "medium", "signature": "No key test"},
    ).json()
    test_settings.gemini_api_key = ""
    response = client.post(f"/api/v1/ai/alerts/{alert['id']}/analysis")
    assert response.status_code == 503
    assert "GEMINI_API_KEY is not configured" in response.json()["detail"]


def test_synthetic_simulation_creates_marked_alerts_and_runs_correlation(
    client, monkeypatch
):
    monkeypatch.setattr(
        "app.services.simulation_service.classify_simulation_prompt",
        lambda settings, prompt: "port_scan",
    )

    response = client.post(
        "/api/v1/ai/simulations",
        json={"prompt": "Simulate a port scan in the lab"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["scenario"] == "port_scan"
    assert body["synthetic"] is True
    assert body["alerts_created"] == 4
    assert body["incidents_created"] == 1
    assert "No real attack traffic was sent" in body["message"]

    alerts_response = client.get("/api/v1/alerts?source_ip=192.0.2.55")
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()["items"]
    assert len(alerts) == 4
    assert all(alert["source"] == "manual" for alert in alerts)
    assert all(alert["dest_ip"] == "198.51.100.25" for alert in alerts)
    assert all(alert["raw_data"]["synthetic"] is True for alert in alerts)
    assert all("[SIMULATION]" in alert["signature"] for alert in alerts)
    assert len({alert["raw_data"]["simulation_id"] for alert in alerts}) == 1


def test_synthetic_simulation_requires_configured_gemini_key(client, test_settings):
    test_settings.gemini_api_key = ""
    response = client.post(
        "/api/v1/ai/simulations",
        json={"prompt": "Simulate a failed-login burst"},
    )
    assert response.status_code == 503
    assert "GEMINI_API_KEY is not configured" in response.json()["detail"]


def test_synthetic_simulation_is_admin_only(client, test_settings):
    created = client.post(
        "/api/v1/auth/users",
        json={
            "username": "simulation-analyst",
            "password": "a-long-test-password",
            "role": "analyst",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "simulation-analyst",
            "password": "a-long-test-password",
        },
    )
    assert login.status_code == 200
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"

    response = client.post(
        "/api/v1/ai/simulations",
        json={"prompt": "Simulate a port scan in the lab"},
    )

    assert response.status_code == 403


def test_synthetic_simulation_validates_prompt(client):
    response = client.post("/api/v1/ai/simulations", json={"prompt": "x"})
    assert response.status_code == 422
