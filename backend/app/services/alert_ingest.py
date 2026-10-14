"""Shared alert-creation path for every source (Snort sync, Splunk sync,
manual API, ML scoring). Centralizing this keeps the idempotency rule
(dedupe on `external_id`) in exactly one place."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def alert_exists(db: Session, external_id: str | None) -> bool:
    if not external_id:
        return False
    return (
        db.query(Alert.id).filter(Alert.external_id == external_id).first() is not None
    )


def create_alert(
    db: Session,
    *,
    source: AlertSource,
    severity: AlertSeverity,
    signature: str,
    category: str | None = None,
    description: str | None = None,
    source_ip: str | None = None,
    source_port: int | None = None,
    dest_ip: str | None = None,
    dest_port: int | None = None,
    protocol: str | None = None,
    confidence_score: float | None = None,
    raw_data: dict | None = None,
    external_id: str | None = None,
    event_time: datetime | None = None,
    commit: bool = True,
) -> Alert:
    alert = Alert(
        source=source,
        severity=severity,
        status=AlertStatus.NEW,
        signature=signature,
        category=category,
        description=description,
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        confidence_score=confidence_score,
        raw_data=_json_safe(raw_data) if raw_data else None,
        external_id=external_id,
        event_time=event_time or datetime.now(timezone.utc),
    )
    db.add(alert)
    if commit:
        db.commit()
        db.refresh(alert)
    else:
        db.flush()
    return alert


def get_or_create_alert(
    db: Session,
    *,
    external_id: str | None,
    **kwargs: Any,
) -> tuple[Alert | None, bool]:
    """Returns (alert_or_none, created). `alert` is None when the record
    already existed and the caller didn't ask for it back (kept cheap for
    bulk sync loops that just need the created/skipped counts)."""
    if external_id and alert_exists(db, external_id):
        return None, False
    alert = create_alert(db, external_id=external_id, commit=False, **kwargs)
    return alert, True
