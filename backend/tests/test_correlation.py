from __future__ import annotations

from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.services.correlation import (
    _get_burst_config,
    _severity_for_count,
    ensure_default_detection_configs,
    run_correlation_once,
)


def _make_alert(db, source_ip="10.0.0.5"):
    alert = Alert(
        source=AlertSource.SNORT,
        severity=AlertSeverity.MEDIUM,
        signature="repeated probe",
        source_ip=source_ip,
        status=AlertStatus.NEW,
    )
    db.add(alert)
    db.flush()
    return alert


def test_ensure_default_detection_configs_creates_once(db_session, test_settings):
    ensure_default_detection_configs(db_session, test_settings)
    ensure_default_detection_configs(db_session, test_settings)  # idempotent
    from app.models.detection_config import DetectionConfig

    rows = db_session.query(DetectionConfig).filter(
        DetectionConfig.name == "source_ip_burst"
    ).all()
    assert len(rows) == 1


def test_correlation_creates_incident_above_threshold(db_session, test_settings):
    ensure_default_detection_configs(db_session, test_settings)
    for _ in range(3):
        _make_alert(db_session)
    db_session.commit()

    incidents = run_correlation_once(db_session, test_settings)
    assert len(incidents) == 1
    assert incidents[0].severity is not None

    db_session.expire_all()
    escalated = (
        db_session.query(Alert)
        .filter(Alert.source_ip == "10.0.0.5", Alert.status == AlertStatus.ESCALATED)
        .count()
    )
    assert escalated == 3


def test_correlation_below_threshold_creates_nothing(db_session, test_settings):
    ensure_default_detection_configs(db_session, test_settings)
    _make_alert(db_session)
    _make_alert(db_session)
    db_session.commit()

    incidents = run_correlation_once(db_session, test_settings)
    assert incidents == []


def test_get_burst_config_falls_back_to_settings_when_no_row_exists(db_session, test_settings):
    # No DetectionConfig row at all (ensure_default_detection_configs not called).
    threshold, window, enabled = _get_burst_config(db_session, test_settings)
    assert threshold == test_settings.correlation_default_threshold
    assert window == test_settings.correlation_default_window_seconds
    assert enabled == test_settings.auto_correlate_enabled


def test_severity_for_count_escalates_with_volume():
    assert _severity_for_count(count=3, threshold=3) == "medium"
    assert _severity_for_count(count=6, threshold=3) == "high"
    assert _severity_for_count(count=9, threshold=3) == "critical"


def test_correlation_disabled_does_nothing(db_session, test_settings):
    from app.models.detection_config import DetectionConfig, DetectionRuleType

    db_session.add(
        DetectionConfig(
            name="source_ip_burst",
            rule_type=DetectionRuleType.CORRELATION,
            enabled=False,
            threshold=3,
            parameters={"window_seconds": 300.0},
        )
    )
    db_session.commit()
    for _ in range(5):
        _make_alert(db_session)
    db_session.commit()

    incidents = run_correlation_once(db_session, test_settings)
    assert incidents == []
