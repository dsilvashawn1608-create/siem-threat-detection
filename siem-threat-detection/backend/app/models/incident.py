from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.alert import _now, _uuid


class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(Base):
    """A grouping of one or more related alerts that an analyst is tracking
    as a single security event, through triage to resolution."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[IncidentSeverity] = mapped_column(String(20), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        String(20), nullable=False, default=IncidentStatus.OPEN
    )
    assigned_to: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident id={self.id} status={self.status} severity={self.severity}>"
