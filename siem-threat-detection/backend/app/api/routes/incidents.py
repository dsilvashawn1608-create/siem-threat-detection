from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.audit_record import AuditRecord
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.schemas.incident import (
    IncidentCreate,
    IncidentListResponse,
    IncidentRead,
    IncidentUpdate,
)
from app.services.correlation import run_correlation_once

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    db: Session = Depends(get_db),
    status: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> IncidentListResponse:
    query = db.query(Incident)
    if status is not None:
        query = query.filter(Incident.status == status)
    if severity is not None:
        query = query.filter(Incident.severity == severity)

    total = query.count()
    items = (
        query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    )
    return IncidentListResponse(items=items, total=total)


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("", response_model=IncidentRead, status_code=201)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)) -> Incident:
    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_to=payload.assigned_to,
    )
    db.add(incident)
    db.flush()

    if payload.alert_ids:
        alerts = db.query(Alert).filter(Alert.id.in_(payload.alert_ids)).all()
        for alert in alerts:
            alert.incident_id = incident.id
            alert.status = AlertStatus.ESCALATED

    db.commit()
    db.refresh(incident)
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    actor: str = Query(default="analyst"),
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes: dict = {}
    if payload.status is not None and payload.status != incident.status:
        changes["status"] = {"from": incident.status, "to": payload.status}
        incident.status = payload.status
        if payload.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
            incident.resolved_at = datetime.now(timezone.utc)
    if payload.severity is not None and payload.severity != incident.severity:
        changes["severity"] = {"from": incident.severity, "to": payload.severity}
        incident.severity = payload.severity
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
    if payload.resolution_notes is not None:
        incident.resolution_notes = payload.resolution_notes

    if changes:
        db.add(
            AuditRecord(
                actor=actor,
                action="incident_updated",
                resource_type="incident",
                resource_id=incident.id,
                details={**changes, "note": payload.note},
            )
        )

    db.commit()
    db.refresh(incident)
    return incident


@router.post("/correlate", response_model=list[IncidentRead])
def trigger_correlation(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> list[Incident]:
    return run_correlation_once(db, settings, actor="manual_trigger")
