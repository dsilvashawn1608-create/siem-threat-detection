from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.detection_config import DetectionRuleType


class DetectionConfigBase(BaseModel):
    name: str
    rule_type: DetectionRuleType
    enabled: bool = True
    threshold: float | None = None
    parameters: dict | None = None
    description: str | None = None


class DetectionConfigCreate(DetectionConfigBase):
    pass


class DetectionConfigUpdate(BaseModel):
    enabled: bool | None = None
    threshold: float | None = None
    parameters: dict | None = None
    description: str | None = None


class DetectionConfigRead(DetectionConfigBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime
