from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import database as database_module
from app.config import Settings, get_settings, reset_settings_cache


def test_lifespan_starts_and_stops_background_sync(test_engine, tmp_path, monkeypatch):
    """Covers the auto_sync_enabled branch in app.main's lifespan: the
    background periodic_sync_loop task is created on startup and
    cancelled cleanly on shutdown, rather than only being exercised
    indirectly through the `client` fixture (which keeps auto-sync off)."""
    reset_settings_cache()
    log_path = tmp_path / "alert"
    log_path.write_text("")

    settings = Settings(
        database_url="sqlite://",
        splunk_hec_token="",
        auto_sync_enabled=True,
        sync_interval_seconds=0.05,
        snort_alert_log_path=str(log_path),
        ml_model_dir=str(tmp_path / "models"),
    )

    import app.config as config_module

    config_module._settings_singleton = settings

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(database_module, "SessionLocal", TestingSessionLocal)

    import app.main as main_module

    main_module.app.dependency_overrides[get_settings] = lambda: settings

    # Entering/exiting the TestClient context runs the lifespan's startup
    # and shutdown halves — if the background task failed to start or
    # didn't cancel cleanly, this would hang or raise.
    with TestClient(main_module.app) as test_client:
        resp = test_client.get("/api/v1/health")
        assert resp.status_code == 200

    main_module.app.dependency_overrides.clear()
    reset_settings_cache()
