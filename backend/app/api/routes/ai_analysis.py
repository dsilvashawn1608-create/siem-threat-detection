from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.api.dependencies import require_admin
from app.models.user import User
from app.schemas.ai_analysis import (
    AIAnalysisResponse,
    AIAvailabilityResponse,
    AISimulationRequest,
    AISimulationResponse,
)
from app.services import gemini_service
from app.services.simulation_service import create_synthetic_simulation

router = APIRouter(prefix="/ai", tags=["AI analysis"])


@router.get("/status", response_model=AIAvailabilityResponse)
def get_ai_status(
    settings: Settings = Depends(get_settings),
) -> AIAvailabilityResponse:
    return AIAvailabilityResponse(
        available=gemini_service.is_available(settings),
        model=settings.gemini_model,
    )


@router.post("/simulations", response_model=AISimulationResponse, status_code=201)
def create_simulation(
    payload: AISimulationRequest,
    actor: User = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AISimulationResponse:
    try:
        return create_synthetic_simulation(
            db, prompt=payload.prompt, actor=actor, settings=settings
        )
    except gemini_service.GeminiAnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.post("/alerts/{alert_id}/analysis", response_model=AIAnalysisResponse)
def analyze_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AIAnalysisResponse:
    try:
        return gemini_service.analyze_alert(db, alert_id, settings)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except gemini_service.GeminiAnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.post("/incidents/{incident_id}/analysis", response_model=AIAnalysisResponse)
def analyze_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AIAnalysisResponse:
    try:
        return gemini_service.analyze_incident(db, incident_id, settings)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except gemini_service.GeminiAnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
