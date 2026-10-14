from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.detection_config import DetectionConfig
from app.schemas.detection_config import (
    DetectionConfigCreate,
    DetectionConfigRead,
    DetectionConfigUpdate,
)

router = APIRouter(prefix="/detection-configs", tags=["detection-configs"])


@router.get("", response_model=list[DetectionConfigRead])
def list_detection_configs(db: Session = Depends(get_db)) -> list[DetectionConfig]:
    return db.query(DetectionConfig).order_by(DetectionConfig.name).all()


@router.get("/{config_id}", response_model=DetectionConfigRead)
def get_detection_config(config_id: str, db: Session = Depends(get_db)) -> DetectionConfig:
    config = db.get(DetectionConfig, config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Detection config not found")
    return config


@router.post("", response_model=DetectionConfigRead, status_code=201)
def create_detection_config(
    payload: DetectionConfigCreate, db: Session = Depends(get_db)
) -> DetectionConfig:
    existing = db.query(DetectionConfig).filter(DetectionConfig.name == payload.name).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Detection config with this name exists")
    config = DetectionConfig(**payload.model_dump())
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


@router.patch("/{config_id}", response_model=DetectionConfigRead)
def update_detection_config(
    config_id: str, payload: DetectionConfigUpdate, db: Session = Depends(get_db)
) -> DetectionConfig:
    config = db.get(DetectionConfig, config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Detection config not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(config, field, value)

    db.commit()
    db.refresh(config)
    return config
