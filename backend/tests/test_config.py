from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from app.config import Settings, YamlSettingsSource, _load_yaml_defaults


def test_cors_origins_comma_separated_env_var(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://a.test,http://b.test")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    settings = Settings()
    assert settings.cors_origins == ["http://a.test", "http://b.test"]


def test_cors_origins_default_when_unset(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    settings = Settings(database_url="sqlite://")
    assert "http://localhost:5173" in settings.cors_origins


def test_production_requires_secrets_tls_and_nonlocal_cors():
    settings = Settings(
        _env_file=None,
        environment="production",
        auth_secret_key="s" * 64,
        auth_admin_username="admin",
        auth_admin_password="strong-production-password",
        splunk_verify_tls=True,
        cors_origins=["https://soc.example"],
        database_url="sqlite://",
    )
    assert settings.environment == "production"

    with pytest.raises(ValidationError, match="non-local origins"):
        Settings(
            _env_file=None,
            environment="production",
            auth_secret_key="s" * 64,
            auth_admin_username="admin",
            auth_admin_password="strong-production-password",
            splunk_verify_tls=True,
            cors_origins=["http://localhost:5173"],
            database_url="sqlite://",
        )


def test_yaml_defaults_use_literal_field_names(tmp_path):
    yaml_path = tmp_path / "settings.yaml"
    yaml_path.write_text(
        """
app:
  app_name: "From YAML"
splunk:
  splunk_hec_index: "custom_index_from_yaml"
"""
    )
    flat = _load_yaml_defaults(yaml_path)
    # Regression test for the Phase 1 bug: subkeys must NOT be prefixed
    # with their section name (e.g. must be "app_name", never
    # "app_app_name") or they silently match no Settings field.
    assert flat["app_name"] == "From YAML"
    assert flat["splunk_hec_index"] == "custom_index_from_yaml"
    assert "app_app_name" not in flat


def test_yaml_defaults_missing_file_returns_empty(tmp_path):
    assert _load_yaml_defaults(tmp_path / "does-not-exist.yaml") == {}


def test_env_var_overrides_yaml(tmp_path, monkeypatch):
    yaml_path = tmp_path / "settings.yaml"
    yaml_path.write_text("app:\n  app_name: from-yaml\n")
    monkeypatch.setattr("app.config.DEFAULT_YAML_PATH", yaml_path)
    monkeypatch.setenv("APP_NAME", "from-env")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    settings = Settings()
    assert settings.app_name == "from-env"


def test_yaml_defaults_accepts_top_level_scalar_keys(tmp_path):
    # Not every key needs to sit under a section — a bare top-level
    # scalar is taken as a literal field name too.
    yaml_path = tmp_path / "settings.yaml"
    yaml_path.write_text("debug: true\n")
    flat = _load_yaml_defaults(yaml_path)
    assert flat["debug"] is True


def test_yaml_settings_source_get_field_value_and_call(tmp_path, monkeypatch):
    yaml_path = tmp_path / "settings.yaml"
    yaml_path.write_text("app:\n  app_name: from-source-class\n")
    monkeypatch.setattr("app.config.DEFAULT_YAML_PATH", yaml_path)

    source = YamlSettingsSource(Settings)
    value, field_name, is_complex = source.get_field_value(None, "app_name")
    assert value == "from-source-class"
    assert field_name == "app_name"
    assert is_complex is False

    assert source()["app_name"] == "from-source-class"


def test_yaml_applies_when_no_env_override(tmp_path, monkeypatch):
    yaml_path = tmp_path / "settings.yaml"
    yaml_path.write_text("app:\n  app_name: from-yaml-only\n")
    monkeypatch.setattr("app.config.DEFAULT_YAML_PATH", yaml_path)
    monkeypatch.delenv("APP_NAME", raising=False)
    settings = Settings(_env_file=None, database_url="sqlite://")
    assert settings.app_name == "from-yaml-only"
