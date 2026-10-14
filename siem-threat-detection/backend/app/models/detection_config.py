from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.database import Base
from app.models.alert import _now, _uuid


class DetectionRuleType(str, enum.Enum):
    SNORT_RULE = "snort_rule"
    ML_THRESHOLD = "ml_threshold"
    SPLUNK_SEARCH = "splunk_search"
    CORRELATION = "correlation"


class DetectionConfig(Base):
    """A tunable detection rule/threshold, independent of which engine
    (Snort, the ML pipeline, or a saved Splunk search) evaluates it."""

    __tablename__ = "detection_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    rule_type: Mapped[DetectionRuleType] = mapped_column(String(30), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    parameters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DetectionConfig name={self.name} enabled={self.enabled}>"
