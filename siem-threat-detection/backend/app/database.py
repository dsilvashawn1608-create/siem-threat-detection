"""SQLAlchemy 2.x engine/session layer. Dialect-agnostic across SQLite (dev)
and Postgres (prod-compatible) — the only dialect-specific branch is the
SQLite `check_same_thread` connect arg needed for FastAPI's threaded
request handling.
"""
from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _engine_kwargs(database_url: str) -> dict[str, Any]:
    if database_url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


def build_engine(database_url: str | None = None):
    url = database_url or get_settings().database_url
    return create_engine(url, **_engine_kwargs(url))


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
