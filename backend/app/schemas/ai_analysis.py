from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AIAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_type: Literal["alert", "incident"]
    resource_id: str
    model: str
    generated_at: datetime
    observed_evidence: dict[str, Any]
    ai_interpretation: str = Field(min_length=1, max_length=12000)
    disclaimer: str


class AIAvailabilityResponse(BaseModel):
    available: bool
    model: str


class AISimulationRequest(BaseModel):
    prompt: str = Field(min_length=3, max_length=500)


class AISimulationResponse(BaseModel):
    simulation_id: str
    scenario: Literal["port_scan", "failed_logins", "web_probe"]
    synthetic: Literal[True] = True
    alert_ids: list[str]
    alerts_created: int
    incidents_created: int
    message: str
