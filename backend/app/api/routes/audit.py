from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies import require_admin
from app.database import get_db
from app.models.audit_record import AuditRecord
from app.models.user import User
from app.schemas.audit import AuditRecordRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditRecordRead])
def list_audit_records(
    _admin: Annotated[User, Depends(require_admin)],
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditRecord]:
    return (
        db.query(AuditRecord)
        .order_by(AuditRecord.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
