from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.api.dependencies import require_admin
from app.models.audit_record import AuditRecord
from app.models.detection_config import DetectionConfig
from app.models.user import User
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
    payload: DetectionConfigCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DetectionConfig:
    existing = db.query(DetectionConfig).filter(DetectionConfig.name == payload.name).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Detection config with this name exists")
    config = DetectionConfig(**payload.model_dump())
    db.add(config)
    db.flush()
    db.add(
        AuditRecord(
            actor=admin.username,
            action="detection_config_created",
            resource_type="detection_config",
            resource_id=config.id,
            details={"name": config.name, "rule_type": config.rule_type},
        )
    )
    db.commit()
    db.refresh(config)
    return config


@router.patch("/{config_id}", response_model=DetectionConfigRead)
def update_detection_config(
    config_id: str,
    payload: DetectionConfigUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DetectionConfig:
    config = db.get(DetectionConfig, config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Detection config not found")

    changes = payload.model_dump(exclude_unset=True)
    before = {field: getattr(config, field) for field in changes}
    for field, value in changes.items():
        setattr(config, field, value)

    if changes:
        db.add(
            AuditRecord(
                actor=admin.username,
                action="detection_config_updated",
                resource_type="detection_config",
                resource_id=config.id,
                details={
                    "before": before,
                    "after": changes,
                },
            )
        )
    db.commit()
    db.refresh(config)
    return config
