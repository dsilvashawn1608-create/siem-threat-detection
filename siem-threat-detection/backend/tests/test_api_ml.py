from __future__ import annotations


def _seed(client, n=6):
    for i in range(n):
        for j in range(6):
            client.post(
                "/api/v1/alerts",
                json={
                    "source": "snort",
                    "severity": "medium",
                    "signature": f"sig-{j}",
                    "source_ip": f"10.1.0.{i}",
                    "dest_port": 80 + j,
                },
            )


def test_train_endpoint_requires_min_samples(client):
    resp = client.post("/api/v1/ml/train")
    assert resp.status_code == 422


def test_train_and_score_endpoints(client):
    _seed(client)
    train_resp = client.post("/api/v1/ml/train")
    assert train_resp.status_code == 200
    assert train_resp.json()["training_samples"] == 6

    score_resp = client.post("/api/v1/ml/score")
    assert score_resp.status_code == 200
    body = score_resp.json()
    assert "results" in body

    models_resp = client.get("/api/v1/ml/models")
    assert models_resp.status_code == 200
    assert len(models_resp.json()) == 1


def test_score_without_trained_model_422(client):
    resp = client.post("/api/v1/ml/score")
    assert resp.status_code == 422


def test_score_and_alert_without_trained_model_422(client):
    resp = client.post("/api/v1/ml/score-and-alert")
    assert resp.status_code == 422


def test_score_and_alert_creates_anomaly_alerts(client, test_settings):
    _seed(client, n=6)
    client.post("/api/v1/ml/train")
    test_settings.ml_anomaly_severity_threshold = 10.0  # force everything "anomalous"

    resp = client.post("/api/v1/ml/score-and-alert")
    assert resp.status_code == 200
    created_ids = resp.json()
    assert len(created_ids) > 0

    alerts_resp = client.get("/api/v1/alerts", params={"source": "ml_anomaly"})
    assert alerts_resp.json()["total"] == len(created_ids)
