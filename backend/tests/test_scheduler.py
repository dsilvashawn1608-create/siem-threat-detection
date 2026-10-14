from __future__ import annotations

import asyncio

import respx
from httpx import Response

from app.scheduler import periodic_sync_loop, run_sync_once, sync_snort_once, sync_splunk_once


def test_sync_snort_once_empty_log(db_session, test_settings, tmp_path):
    log_path = tmp_path / "alert"
    settings = test_settings.model_copy(update={"snort_alert_log_path": str(log_path)})
    result = sync_snort_once(db_session, settings)
    assert result["created"] == 0
    assert result["read_lines"] == 0


def test_sync_snort_once_creates_alerts(db_session, test_settings, tmp_path):
    log_path = tmp_path / "alert"
    log_path.write_text(
        "10/04-12:34:56.789012  [**] [1:1000001:1] ICMP Test Rule Triggered [**] "
        "[Classification: Potentially Bad Traffic] [Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.10\n"
    )
    settings = test_settings.model_copy(update={"snort_alert_log_path": str(log_path)})
    result = sync_snort_once(db_session, settings)
    assert result["created"] == 1

    # Re-running is idempotent.
    result2 = sync_snort_once(db_session, settings)
    assert result2["created"] == 0
    assert result2["skipped_duplicates"] == 1


def test_run_sync_once_uses_injected_session_factory(test_engine, test_settings, tmp_path):
    from sqlalchemy.orm import sessionmaker

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    log_path = tmp_path / "alert"
    log_path.write_text("")
    settings = test_settings.model_copy(
        update={"snort_alert_log_path": str(log_path), "splunk_hec_token": ""}
    )

    result = run_sync_once(settings, TestingSessionLocal)
    assert "snort" in result
    assert "splunk" not in result  # no HEC token configured -> skipped


@respx.mock
def test_sync_splunk_once_creates_alerts(db_session, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-sched-1"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-sched-1").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-sched-1/results").mock(
        return_value=Response(
            200,
            json={"results": [{"_cd": "1:1", "signature": "scheduled sig", "severity": "low"}]},
        )
    )
    result = sync_splunk_once(db_session, test_settings)
    assert result["fetched"] == 1
    assert result["created"] == 1


@respx.mock
def test_sync_splunk_once_falls_back_to_medium_on_unrecognized_severity(db_session, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-sched-sev"})
    )
    respx.get(f"{test_settings.splunk_api_url}/services/search/jobs/job-sched-sev").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(
        f"{test_settings.splunk_api_url}/services/search/jobs/job-sched-sev/results"
    ).mock(
        return_value=Response(
            200,
            json={"results": [{"_cd": "1:2", "signature": "sig", "severity": "nonsense"}]},
        )
    )
    result = sync_splunk_once(db_session, test_settings)
    assert result["created"] == 1


@respx.mock
def test_sync_splunk_once_handles_service_error(db_session, test_settings):
    respx.post(f"{test_settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(500)
    )
    result = sync_splunk_once(db_session, test_settings)
    assert result["fetched"] == 0
    assert "error" in result


@respx.mock
def test_run_sync_once_includes_splunk_and_correlation_when_enabled(
    test_engine, test_settings, tmp_path
):
    from sqlalchemy.orm import sessionmaker

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    log_path = tmp_path / "alert"
    log_path.write_text("")
    settings = test_settings.model_copy(
        update={"snort_alert_log_path": str(log_path), "auto_correlate_enabled": True}
    )

    respx.post(f"{settings.splunk_api_url}/services/search/jobs").mock(
        return_value=Response(201, json={"sid": "job-sched-2"})
    )
    respx.get(f"{settings.splunk_api_url}/services/search/jobs/job-sched-2").mock(
        return_value=Response(200, json={"entry": [{"content": {"isDone": True}}]})
    )
    respx.get(f"{settings.splunk_api_url}/services/search/jobs/job-sched-2/results").mock(
        return_value=Response(200, json={"results": []})
    )

    result = run_sync_once(settings, TestingSessionLocal)
    assert "splunk" in result
    assert "incidents_created" in result


async def _run_one_loop_cycle(settings, session_factory):
    stop_event = asyncio.Event()

    async def stop_after_first_cycle():
        await asyncio.sleep(0.05)
        stop_event.set()

    await asyncio.gather(
        periodic_sync_loop(settings, session_factory, stop_event=stop_event),
        stop_after_first_cycle(),
    )


def test_periodic_sync_loop_runs_and_stops(test_engine, test_settings, tmp_path):
    from sqlalchemy.orm import sessionmaker

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    log_path = tmp_path / "alert"
    log_path.write_text(
        "10/04-12:34:56.789012  [**] [1:1000001:1] ICMP Test Rule Triggered [**] "
        "[Classification: Potentially Bad Traffic] [Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.10\n"
    )
    settings = test_settings.model_copy(
        update={
            "snort_alert_log_path": str(log_path),
            "splunk_hec_token": "",
            "sync_interval_seconds": 0.01,
        }
    )

    asyncio.run(_run_one_loop_cycle(settings, TestingSessionLocal))

    # The loop's first cycle should have synced the one Snort alert.
    from app.models.alert import Alert

    session = TestingSessionLocal()
    try:
        assert session.query(Alert).count() == 1
    finally:
        session.close()
