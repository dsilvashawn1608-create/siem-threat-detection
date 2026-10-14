from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    details: dict | None
    timestamp: datetime
