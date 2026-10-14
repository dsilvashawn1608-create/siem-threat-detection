from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.incident import IncidentSeverity, IncidentStatus


class IncidentBase(BaseModel):
    title: str
    description: str | None = None
    severity: IncidentSeverity
    assigned_to: str | None = None


class IncidentCreate(IncidentBase):
    alert_ids: list[str] = []


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    assigned_to: str | None = None
    resolution_notes: str | None = None
    note: str | None = None


class IncidentRead(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: IncidentStatus
    resolution_notes: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


class IncidentListResponse(BaseModel):
    items: list[IncidentRead]
    total: int
