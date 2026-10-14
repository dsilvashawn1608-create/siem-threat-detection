from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import database as database_module
from app.api.routes import alerts, detection_configs, health, incidents, ml, snort, splunk
from app.config import get_settings
from app.logging_config import configure_logging, get_logger
from app.scheduler import periodic_sync_loop
from app.services.correlation import ensure_default_detection_configs

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    # Import the module (not the name) so tests that monkeypatch
    # `database_module.SessionLocal` are respected here too — binding the
    # name at import time previously caused this to silently hit the real
    # DB during tests even when the test fixture swapped SessionLocal out.
    db = database_module.SessionLocal()
    try:
        ensure_default_detection_configs(db, settings)
    finally:
        db.close()

    sync_task: asyncio.Task | None = None
    stop_event = asyncio.Event()
    if settings.auto_sync_enabled:
        sync_task = asyncio.create_task(
            periodic_sync_loop(settings, database_module.SessionLocal, stop_event=stop_event)
        )
        logger.info("background_sync_started", extra={"interval": settings.sync_interval_seconds})

    yield

    if sync_task is not None:
        stop_event.set()
        sync_task.cancel()
        try:
            await sync_task
        except (asyncio.CancelledError, Exception):  # pragma: no cover
            pass


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix=settings.api_v1_prefix)
    app.include_router(splunk.router, prefix=settings.api_v1_prefix)
    app.include_router(snort.router, prefix=settings.api_v1_prefix)
    app.include_router(alerts.router, prefix=settings.api_v1_prefix)
    app.include_router(incidents.router, prefix=settings.api_v1_prefix)
    app.include_router(detection_configs.router, prefix=settings.api_v1_prefix)
    app.include_router(ml.router, prefix=settings.api_v1_prefix)

    return app


app = create_app()
