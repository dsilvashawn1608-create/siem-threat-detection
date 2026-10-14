from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.database import Base
from app.models.alert import _now, _uuid


class MLModelMetadata(Base):
    """Registry entry for a trained Isolation Forest model artifact, so the
    serving layer knows which file to load and analysts can see how it
    was trained/evaluated."""

    __tablename__ = "ml_model_metadata"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    model_name: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)

    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    training_samples: Mapped[int | None] = mapped_column(nullable=True)
    feature_names: Mapped[list | None] = mapped_column(JSON, nullable=True)
    hyperparameters: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    accuracy: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    f1_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MLModelMetadata {self.model_name}:{self.version} active={self.is_active}>"
