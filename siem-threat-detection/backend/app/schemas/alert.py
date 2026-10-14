from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.alert import AlertSeverity, AlertSource, AlertStatus


class AlertBase(BaseModel):
    source: AlertSource
    severity: AlertSeverity
    signature: str
    category: str | None = None
    description: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    confidence_score: float | None = None
    raw_data: dict | None = None
    external_id: str | None = None
    event_time: datetime | None = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    severity: AlertSeverity | None = None
    description: str | None = None
    note: str | None = None


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: AlertStatus
    incident_id: str | None = None
    created_at: datetime
    updated_at: datetime


class AlertListResponse(BaseModel):
    items: list[AlertRead]
    total: int
