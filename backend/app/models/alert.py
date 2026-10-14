from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


class AlertSource(str, enum.Enum):
    SNORT = "snort"
    SPLUNK = "splunk"
    ML_ANOMALY = "ml_anomaly"
    MANUAL = "manual"


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(Base):
    """A single detection event, from Snort, Splunk, or the ML pipeline."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_source_severity", "source", "severity"),
        Index("ix_alerts_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source: Mapped[AlertSource] = mapped_column(String(20), nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(String(20), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        String(20), nullable=False, default=AlertStatus.NEW
    )
    signature: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_port: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Stable identifier from the originating system (e.g. Splunk's `_cd`
    # bucket/offset pair) — lets a re-run sync be idempotent instead of
    # duplicating alerts already pulled in.
    external_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id"), nullable=True
    )
    incident: Mapped["Incident | None"] = relationship(back_populates="alerts")

    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert id={self.id} source={self.source} severity={self.severity}>"
