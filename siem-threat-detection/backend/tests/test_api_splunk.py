from __future__ import annotations

import respx
from httpx import Response


@respx.mock
def test_send_event_endpoint(client, test_settings):
    respx.post(f"{test_settings.splunk_hec_url}/services/collector/event").mock(
        return_value=Response(200, json={"text": "Success", "code": 0})
    )
    resp = client.post(
        "/api/v1/splunk/events",
        json={"event": {"message": "hello"}, "source_ip": "1.2.3.4"},
    )
    assert resp.status_code == 200
    assert resp.json()["code"] == 0


@respx.mock
def test_send_event_endpoint_http_error_returns_502(client, test_settings):
    respx.post(f"{test_settings.splunk_hec_url}/services/collector/event").mock(
        return_value=Response(500)
    )
    resp = client.post("/api/v1/splunk/events", json={"event": {"message": "hello"}})
    assert resp.status_code == 502


@respx.mock
def test_search_endpoint(client, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-search-ep"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-search-ep").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(
        f"{test_settings.splunk_api_url}/services/search/jobs/job-search-ep/results"
    ).mock(return_value=Response(200, json={"results": [{"_raw": "hit"}]}))

    resp = client.post("/api/v1/splunk/search", json={"query": "index=main"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["result_count"] == 1


@respx.mock
def test_search_endpoint_http_error_returns_502(client, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(500)
    )
    resp = client.post("/api/v1/splunk/search", json={"query": "index=main"})
    assert resp.status_code == 502


@respx.mock
def test_sync_endpoint_http_error_returns_502(client, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(500)
    )
    resp = client.post("/api/v1/splunk/sync")
    assert resp.status_code == 502


@respx.mock
def test_sync_endpoint_falls_back_to_medium_on_unrecognized_severity(client, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-sev"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-sev").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-sev/results").mock(
        return_value=Response(
            200,
            json={
                "results": [
                    {"_cd": "1:9", "signature": "weird sev", "severity": "not-a-real-severity"}
                ]
            },
        )
    )
    resp = client.post("/api/v1/splunk/sync")
    assert resp.status_code == 200
    assert resp.json()["created"] == 1

    alerts = client.get("/api/v1/alerts", params={"source": "splunk"}).json()["items"]
    matching = [a for a in alerts if a["signature"] == "weird sev"]
    assert matching[0]["severity"] == "medium"


@respx.mock
def test_sync_endpoint_creates_alerts(client, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-1"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-1").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-1/results").mock(
        return_value=Response(
            200,
            json={
                "results": [
                    {"_cd": "1:1", "signature": "test sig", "severity": "high", "_raw": "raw"}
                ]
            },
        )
    )
    resp = client.post("/api/v1/splunk/sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["fetched"] == 1
    assert body["created"] == 1

    # Re-syncing the same result is idempotent (skipped_duplicates > 0).
    resp2 = client.post("/api/v1/splunk/sync")
    assert resp2.json()["skipped_duplicates"] == 1
