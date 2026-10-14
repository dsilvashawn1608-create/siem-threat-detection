"""Correlation engine: groups recent alerts by source_ip within a tunable
time window and, once the count crosses a threshold, opens an Incident and
escalates the contributing alerts. Threshold/window come from a
`DetectionConfig` row named `source_ip_burst` (falls back to the Settings
defaults if that row doesn't exist yet)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_config import get_logger
from app.models.alert import Alert, AlertStatus
from app.models.audit_record import AuditRecord
from app.models.detection_config import DetectionConfig, DetectionRuleType
from app.models.incident import Incident, IncidentSeverity, IncidentStatus

logger = get_logger(__name__)

SOURCE_IP_BURST_CONFIG_NAME = "source_ip_burst"


def ensure_default_detection_configs(db: Session, settings: Settings) -> None:
    existing = (
        db.query(DetectionConfig)
        .filter(DetectionConfig.name == SOURCE_IP_BURST_CONFIG_NAME)
        .first()
    )
    if existing:
        return
    db.add(
        DetectionConfig(
            name=SOURCE_IP_BURST_CONFIG_NAME,
            rule_type=DetectionRuleType.CORRELATION,
            enabled=settings.auto_correlate_enabled,
            threshold=float(settings.correlation_default_threshold),
            parameters={"window_seconds": settings.correlation_default_window_seconds},
            description=(
                "Opens an incident when the same source_ip produces at least "
                "`threshold` alerts within `window_seconds`."
            ),
        )
    )
    db.commit()


def _get_burst_config(db: Session, settings: Settings) -> tuple[int, float, bool]:
    row = (
        db.query(DetectionConfig)
        .filter(DetectionConfig.name == SOURCE_IP_BURST_CONFIG_NAME)
        .first()
    )
    if row is None:
        return (
            settings.correlation_default_threshold,
            settings.correlation_default_window_seconds,
            settings.auto_correlate_enabled,
        )
    threshold = int(row.threshold or settings.correlation_default_threshold)
    window = float(
        (row.parameters or {}).get("window_seconds", settings.correlation_default_window_seconds)
    )
    return threshold, window, row.enabled


def _severity_for_count(count: int, threshold: int) -> IncidentSeverity:
    if count >= threshold * 3:
        return IncidentSeverity.CRITICAL
    if count >= threshold * 2:
        return IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM


def run_correlation_once(
    db: Session,
    settings: Settings,
    *,
    actor: str = "correlation_engine",
) -> list[Incident]:
    """Scans un-escalated alerts, groups by source_ip, and opens incidents
    for any group whose count (within the window) meets the threshold.
    Returns the list of newly created incidents."""
    threshold, window_seconds, enabled = _get_burst_config(db, settings)
    if not enabled:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    rows = (
        db.query(Alert.source_ip, func.count(Alert.id))
        .filter(
            Alert.source_ip.isnot(None),
            Alert.status == AlertStatus.NEW,
            Alert.incident_id.is_(None),
            Alert.created_at >= cutoff,
        )
        .group_by(Alert.source_ip)
        .having(func.count(Alert.id) >= threshold)
        .all()
    )

    created_incidents: list[Incident] = []
    for source_ip, count in rows:
        alerts = (
            db.query(Alert)
            .filter(
                Alert.source_ip == source_ip,
                Alert.status == AlertStatus.NEW,
                Alert.incident_id.is_(None),
                Alert.created_at >= cutoff,
            )
            .all()
        )
        if len(alerts) < threshold:  # pragma: no cover
            # Defensive only: the GROUP BY/HAVING query above already
            # applied this exact filter set, so this refetch can't
            # legitimately come back shorter within the same call. Kept
            # as a guard against the two queries ever drifting apart
            # (e.g. a future filter added to one but not the other)
            # rather than something exercised in normal operation.
            continue

        incident = Incident(
            title=f"Repeated alerts from {source_ip} ({len(alerts)} in {int(window_seconds)}s)",
            description=(
                f"Correlation engine grouped {len(alerts)} alerts from source_ip="
                f"{source_ip} within a {int(window_seconds)}s window (threshold={threshold})."
            ),
            severity=_severity_for_count(len(alerts), threshold),
            status=IncidentStatus.OPEN,
        )
        db.add(incident)
        db.flush()

        for alert in alerts:
            alert.incident_id = incident.id
            alert.status = AlertStatus.ESCALATED

        db.add(
            AuditRecord(
                actor=actor,
                action="incident_created",
                resource_type="incident",
                resource_id=incident.id,
                details={
                    "reason": "source_ip_burst_correlation",
                    "source_ip": source_ip,
                    "alert_count": len(alerts),
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "alert_ids": [a.id for a in alerts],
                },
            )
        )
        created_incidents.append(incident)

    if created_incidents:
        db.commit()
        for incident in created_incidents:
            db.refresh(incident)
    return created_incidents
