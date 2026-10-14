from __future__ import annotations

from datetime import datetime, timezone

import respx
from httpx import Response

from app.config import Settings
from app.services.splunk_service import (
    SplunkService,
    SplunkServiceError,
    _json_safe,
    build_external_id,
)


def test_json_safe_stringifies_nested_datetimes():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    payload = {"when": now, "nested": {"when": now}, "list": [now, "plain"]}
    safe = _json_safe(payload)
    assert safe["when"] == now.isoformat()
    assert safe["nested"]["when"] == now.isoformat()
    assert safe["list"][0] == now.isoformat()
    assert safe["list"][1] == "plain"


def _settings() -> Settings:
    return Settings(
        database_url="sqlite://",
        splunk_hec_url="https://splunk.test:8088",
        splunk_hec_token="abc123",
        splunk_api_url="https://splunk.test:8089",
        splunk_search_poll_interval_seconds=0.0,
    )


@respx.mock
def test_send_event_success():
    settings = _settings()
    respx.post("https://splunk.test:8088/services/collector/event").mock(
        return_value=Response(200, json={"text": "Success", "code": 0})
    )
    service = SplunkService(settings)
    result = service.send_event({"message": "test"}, source_ip="1.2.3.4")
    assert result["code"] == 0


@respx.mock
def test_send_event_with_all_optional_fields():
    settings = _settings()
    route = respx.post("https://splunk.test:8088/services/collector/event").mock(
        return_value=Response(200, json={"text": "Success", "code": 0})
    )
    service = SplunkService(settings)
    result = service.send_event(
        {"message": "test"},
        source_ip="1.2.3.4",
        severity="high",
        signature="suspicious thing",
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result["code"] == 0
    sent_body = route.calls.last.request.content
    assert b"suspicious thing" in sent_body
    assert b"1.2.3.4" in sent_body


@respx.mock
def test_send_event_http_error_raises_service_error():
    settings = _settings()
    respx.post("https://splunk.test:8088/services/collector/event").mock(
        return_value=Response(500)
    )
    service = SplunkService(settings)
    try:
        service.send_event({"message": "test"})
        assert False, "expected SplunkServiceError"
    except SplunkServiceError:
        pass


@respx.mock
def test_search_full_cycle():
    settings = _settings()
    respx.post("https://splunk.test:8089/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-123"})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-123").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-123/results").mock(
        return_value=Response(200, json={"results": [{"_raw": "event one"}]})
    )
    service = SplunkService(settings)
    results = service.search("index=main")
    assert results == [{"_raw": "event one"}]


@respx.mock
def test_search_job_never_completes_raises():
    settings = _settings()
    settings = settings.model_copy(update={"splunk_search_max_poll_attempts": 2})
    respx.post("https://splunk.test:8089/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-456"})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-456").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": False}}]})
    )
    service = SplunkService(settings)
    try:
        service.search("index=main")
        assert False, "expected SplunkServiceError"
    except SplunkServiceError:
        pass


@respx.mock
def test_create_search_job_http_error_raises():
    settings = _settings()
    respx.post("https://splunk.test:8089/services/search/jobs").mock(return_value=Response(500))
    service = SplunkService(settings)
    try:
        service.search("index=main")
        assert False, "expected SplunkServiceError"
    except SplunkServiceError:
        pass


@respx.mock
def test_create_search_job_missing_sid_raises():
    settings = _settings()
    respx.post("https://splunk.test:8089/services/search/jobs").mock(
        return_value=Response(201, json={})
    )
    service = SplunkService(settings)
    try:
        service.search("index=main")
        assert False, "expected SplunkServiceError"
    except SplunkServiceError as exc:
        assert "missing sid" in str(exc)


@respx.mock
def test_wait_for_job_http_error_raises():
    settings = _settings()
    respx.post("https://splunk.test:8089/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-err"})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-err").mock(
        return_value=Response(500)
    )
    service = SplunkService(settings)
    try:
        service.search("index=main")
        assert False, "expected SplunkServiceError"
    except SplunkServiceError as exc:
        assert "poll" in str(exc)


@respx.mock
def test_fetch_results_http_error_raises():
    settings = _settings()
    respx.post("https://splunk.test:8089/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-fetch-err"})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-fetch-err").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get("https://splunk.test:8089/services/search/jobs/job-fetch-err/results").mock(
        return_value=Response(500)
    )
    service = SplunkService(settings)
    try:
        service.search("index=main")
        assert False, "expected SplunkServiceError"
    except SplunkServiceError as exc:
        assert "fetch" in str(exc)


def test_build_external_id_prefers_cd():
    assert build_external_id({"_cd": "1:234"}) == "splunk:1:234"
    assert build_external_id({"event_id": "abc"}) == "splunk:abc"
    assert build_external_id({}) is None
