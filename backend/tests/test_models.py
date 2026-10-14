from __future__ import annotations

from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus


def test_create_alert_and_fetch(db_session):
    alert = Alert(
        source=AlertSource.MANUAL,
        severity=AlertSeverity.HIGH,
        signature="Test signature",
    )
    db_session.add(alert)
    db_session.commit()

    fetched = db_session.get(Alert, alert.id)
    assert fetched is not None
    assert fetched.status == AlertStatus.NEW
    assert fetched.source == AlertSource.MANUAL


def test_alert_external_id_unique(db_session):
    db_session.add(
        Alert(
            source=AlertSource.SNORT,
            severity=AlertSeverity.LOW,
            signature="sig-1",
            external_id="dup-id",
        )
    )
    db_session.commit()

    db_session.add(
        Alert(
            source=AlertSource.SNORT,
            severity=AlertSeverity.LOW,
            signature="sig-2",
            external_id="dup-id",
        )
    )
    import pytest
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_incident_alert_relationship(db_session):
    incident = Incident(title="Burst from 10.0.0.5", severity=IncidentSeverity.HIGH)
    db_session.add(incident)
    db_session.flush()

    alert = Alert(
        source=AlertSource.SNORT,
        severity=AlertSeverity.HIGH,
        signature="sig",
        incident_id=incident.id,
    )
    db_session.add(alert)
    db_session.commit()

    db_session.refresh(incident)
    assert len(incident.alerts) == 1
    assert incident.alerts[0].id == alert.id
    assert incident.status == IncidentStatus.OPEN
