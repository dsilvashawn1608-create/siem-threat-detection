from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models.ml_model_metadata import MLModelMetadata
from app.schemas.ml_model import (
    MLModelMetadataRead,
    MLScoreResponse,
    MLScoreResultOut,
    MLTrainResponse,
)
from app.services import ml_service

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/models", response_model=list[MLModelMetadataRead])
def list_models(db: Session = Depends(get_db)) -> list[MLModelMetadata]:
    return db.query(MLModelMetadata).order_by(MLModelMetadata.created_at.desc()).all()


@router.post("/train", response_model=MLTrainResponse)
def train(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MLTrainResponse:
    try:
        result = ml_service.train_model(db, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return MLTrainResponse(
        metadata=result.metadata,
        training_samples=result.training_samples,
        feature_names=result.feature_names,
    )


@router.post("/score", response_model=MLScoreResponse)
def score(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MLScoreResponse:
    try:
        metadata, _, _ = ml_service._load_active_model(db, settings)
        results = ml_service.score_all(db, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return MLScoreResponse(
        model_version=metadata.version,
        results=[MLScoreResultOut(**vars(r)) for r in results],
        anomalies_flagged=sum(1 for r in results if r.is_anomaly),
    )


@router.post("/score-and-alert", response_model=list[str])
def score_and_alert(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> list[str]:
    try:
        created = ml_service.score_and_create_anomaly_alerts(db, settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return [alert.id for alert in created]
