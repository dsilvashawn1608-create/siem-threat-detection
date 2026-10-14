from __future__ import annotations

from datetime import datetime, timezone

from app.models.alert import AlertSeverity, AlertSource
from app.services.alert_ingest import (
    _json_safe,
    alert_exists,
    create_alert,
    get_or_create_alert,
)


def test_json_safe_handles_list_of_datetimes():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = _json_safe([now, "plain", {"nested": now}])
    assert result[0] == now.isoformat()
    assert result[1] == "plain"
    assert result[2]["nested"] == now.isoformat()


def test_alert_exists_false_for_none_or_empty_external_id(db_session):
    assert alert_exists(db_session, None) is False
    assert alert_exists(db_session, "") is False


def test_create_alert_commits_by_default(db_session):
    alert = create_alert(
        db_session,
        source=AlertSource.MANUAL,
        severity=AlertSeverity.LOW,
        signature="manual test",
    )
    assert alert.id is not None


def test_create_alert_json_safe_datetime_in_raw_data(db_session):
    alert = create_alert(
        db_session,
        source=AlertSource.SNORT,
        severity=AlertSeverity.LOW,
        signature="sig",
        raw_data={"event_time": datetime.now(timezone.utc)},
    )
    assert isinstance(alert.raw_data["event_time"], str)


def test_get_or_create_alert_deduplicates_on_external_id(db_session):
    alert1, created1 = get_or_create_alert(
        db_session,
        external_id="dup-123",
        source=AlertSource.SPLUNK,
        severity=AlertSeverity.MEDIUM,
        signature="sig-1",
    )
    db_session.commit()
    assert created1 is True
    assert alert1 is not None

    alert2, created2 = get_or_create_alert(
        db_session,
        external_id="dup-123",
        source=AlertSource.SPLUNK,
        severity=AlertSeverity.MEDIUM,
        signature="sig-1-retry",
    )
    assert created2 is False
    assert alert2 is None
