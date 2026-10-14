from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.api.dependencies import get_current_user
from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.models.audit_record import AuditRecord
from app.models.user import User
from app.schemas.alert import AlertCreate, AlertListResponse, AlertRead, AlertUpdate
from app.services.alert_ingest import create_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    db: Session = Depends(get_db),
    source: AlertSource | None = None,
    severity: AlertSeverity | None = None,
    status: AlertStatus | None = None,
    source_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AlertListResponse:
    query = db.query(Alert)
    if source is not None:
        query = query.filter(Alert.source == source)
    if severity is not None:
        query = query.filter(Alert.severity == severity)
    if status is not None:
        query = query.filter(Alert.status == status)
    if source_ip is not None:
        query = query.filter(Alert.source_ip == source_ip)

    total = query.count()
    items = (
        query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    )
    return AlertListResponse(items=items, total=total)


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("", response_model=AlertRead, status_code=201)
def create_alert_endpoint(payload: AlertCreate, db: Session = Depends(get_db)) -> Alert:
    return create_alert(
        db,
        source=payload.source,
        severity=payload.severity,
        signature=payload.signature,
        category=payload.category,
        description=payload.description,
        source_ip=payload.source_ip,
        source_port=payload.source_port,
        dest_ip=payload.dest_ip,
        dest_port=payload.dest_port,
        protocol=payload.protocol,
        confidence_score=payload.confidence_score,
        raw_data=payload.raw_data,
        external_id=payload.external_id,
        event_time=payload.event_time,
    )


@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert(
    alert_id: str,
    payload: AlertUpdate,
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes: dict = {}
    if payload.status is not None and payload.status != alert.status:
        changes["status"] = {
            "from": getattr(alert.status, "value", alert.status),
            "to": payload.status.value,
        }
        alert.status = payload.status
    if payload.severity is not None and payload.severity != alert.severity:
        changes["severity"] = {
            "from": getattr(alert.severity, "value", alert.severity),
            "to": payload.severity.value,
        }
        alert.severity = payload.severity
    if payload.description is not None and payload.description != alert.description:
        changes["description"] = {
            "from": alert.description,
            "to": payload.description,
        }
        alert.description = payload.description

    if changes or payload.note is not None:
        db.add(
            AuditRecord(
                actor=actor.username,
                action="alert_updated",
                resource_type="alert",
                resource_id=alert.id,
                details={**changes, "note": payload.note},
            )
        )

    db.commit()
    db.refresh(alert)
    return alert
