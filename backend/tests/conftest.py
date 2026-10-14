from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("SPLUNK_HEC_TOKEN", "test-token")

from app import database as database_module  # noqa: E402
from app.config import Settings, get_settings, reset_settings_cache  # noqa: E402


@pytest.fixture()
def test_engine():
    # In-memory SQLite + StaticPool so every connection (including the
    # ones FastAPI's threaded TestClient opens from other threads) shares
    # the SAME in-memory database rather than each getting a blank one.
    import app.models  # noqa: F401 - ensure all models are registered before create_all

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database_module.Base.metadata.create_all(engine)
    yield engine
    database_module.Base.metadata.drop_all(engine)


@pytest.fixture()
def db_session(test_engine):
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def test_settings(tmp_path) -> Settings:
    reset_settings_cache()
    settings = Settings(
        database_url="sqlite://",
        splunk_hec_token="test-token",
        auth_secret_key="test-secret-key-with-at-least-32-bytes",
        auth_admin_username="test-admin",
        auth_admin_password="test-admin-password",
        ml_model_dir=str(tmp_path / "models"),
        ml_min_training_samples=3,
        auto_correlate_enabled=True,
        correlation_default_threshold=3,
        correlation_default_window_seconds=300.0,
    )
    # get_settings() is called directly (not only via FastAPI's Depends)
    # in a few places — notably app.main's lifespan, which runs
    # ensure_default_detection_configs() before any route or dependency
    # override takes effect. Pre-seeding the module-level singleton (the
    # same global every `from app.config import get_settings` reference
    # reads from, regardless of which module bound the name) makes those
    # direct calls see this same test Settings instance instead of a
    # freshly-constructed one that's missing our overrides (e.g.
    # auto_correlate_enabled). The FastAPI dependency_overrides in the
    # `client` fixture additionally covers route-level Depends(get_settings).
    import app.config as config_module

    config_module._settings_singleton = settings
    yield settings
    reset_settings_cache()


@pytest.fixture()
def client(test_engine, test_settings, monkeypatch) -> Generator[TestClient, None, None]:
    from sqlalchemy.orm import sessionmaker

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    monkeypatch.setattr(database_module, "SessionLocal", TestingSessionLocal)

    import app.main as main_module

    def _get_settings_override() -> Settings:
        return test_settings

    main_module.app.dependency_overrides[get_settings] = _get_settings_override

    def _get_db_override():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    from app.database import get_db

    main_module.app.dependency_overrides[get_db] = _get_db_override

    with TestClient(main_module.app) as test_client:
        from app.services.auth_service import issue_access_token

        test_client.headers["Authorization"] = (
            f"Bearer {issue_access_token('test-admin', test_settings.auth_secret_key)}"
        )
        yield test_client

    main_module.app.dependency_overrides.clear()
