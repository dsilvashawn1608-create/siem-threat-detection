from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_admin
from app.config import Settings, get_settings
from app.database import get_db
from app.models.audit_record import AuditRecord
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserRead
from app.services.auth_service import (
    TOKEN_LIFETIME_SECONDS,
    hash_password,
    issue_access_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not user.is_active or not verify_password(
        payload.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(
        access_token=issue_access_token(user.username, settings.auth_secret_key),
        expires_in=TOKEN_LIFETIME_SECONDS,
    )


@router.get("/me", response_model=UserRead)
def me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user


@router.get("/users", response_model=list[UserRead])
def list_users(
    _admin: Annotated[User, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> list[User]:
    return db.query(User).order_by(User.username).all()


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    _admin: Annotated[User, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> User:
    if db.query(User).filter(User.username == payload.username).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(
        AuditRecord(
            actor=_admin.username,
            action="user_created",
            resource_type="user",
            resource_id=user.id,
            details={"username": user.username, "role": user.role},
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}/deactivate", response_model=UserRead)
def deactivate_user(
    user_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cannot deactivate the current admin"
        )
    user.is_active = False
    db.add(
        AuditRecord(
            actor=admin.username,
            action="user_deactivated",
            resource_type="user",
            resource_id=user.id,
            details={"username": user.username},
        )
    )
    db.commit()
    db.refresh(user)
    return user
