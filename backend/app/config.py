"""
Application configuration.

Settings are resolved in this precedence order (highest wins):
  1. Environment variables
  2. `.env` file
  3. `config/settings.yaml`
  4. Field defaults declared below

This order is implemented via `settings_customise_sources` below, using a
custom `YamlSettingsSource` inserted *below* env/dotenv priority.

NOTE on CORS_ORIGINS: pydantic-settings will, by default, attempt to JSON-decode
any `list[str]` field it reads from an environment variable. A plain comma
separated value like `CORS_ORIGINS=http://localhost:5173,http://localhost:3000`
is NOT valid JSON, so the default decoding raises a SettingsError before our
own validator ever runs. We annotate the field with `NoDecode` and split the
comma separated string ourselves in a `field_validator`. Covered by
`tests/test_config.py::test_cors_origins_comma_separated_env_var`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Type

import yaml
from pydantic import Field, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from typing_extensions import Annotated

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_YAML_PATH = BASE_DIR / "config" / "settings.yaml"


def _load_yaml_defaults(path: Path) -> dict[str, Any]:
    """Flattens config/settings.yaml's nested sections one level. Every
    subkey must be the literal Settings field name (e.g. `splunk_hec_url`,
    `app_name`) — sections are purely organizational, not a namespace
    prefix. (An earlier version prefixed subkeys with their section name,
    producing keys like `splunk_splunk_hec_url` that matched no real field
    and meant YAML values never actually applied — see /learnings.)
    """
    if not path.exists():
        return {}
    with path.open("r") as f:
        data = yaml.safe_load(f) or {}
    flat: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for subkey, subval in value.items():
                flat.setdefault(subkey, subval)
        else:
            flat[key] = value
    return flat


class YamlSettingsSource(PydanticBaseSettingsSource):
    """Reads config/settings.yaml. Lower priority than env vars and .env."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        data = _load_yaml_defaults(DEFAULT_YAML_PATH)
        return data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return _load_yaml_defaults(DEFAULT_YAML_PATH)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App ---
    app_name: str = "SIEM Threat Detection Platform"
    environment: str = Field(default="development")
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # --- Local API authentication ---
    auth_secret_key: str = ""
    auth_admin_username: str = ""
    auth_admin_password: str = ""

    # --- Optional Gemini analysis ---
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: float = Field(default=30.0, gt=0, le=120)

    # --- CORS ---
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if self.environment.lower() in {"production", "prod"}:
            if len(self.auth_secret_key) < 32:
                raise ValueError("AUTH_SECRET_KEY must contain at least 32 characters in production")
            if not self.auth_admin_username or len(self.auth_admin_password) < 12:
                raise ValueError(
                    "Production requires AUTH_ADMIN_USERNAME and an AUTH_ADMIN_PASSWORD "
                    "of at least 12 characters"
                )
            if not self.splunk_verify_tls:
                raise ValueError("SPLUNK_VERIFY_TLS must be true in production")
            if not self.cors_origins or "*" in self.cors_origins or any(
                origin.startswith(("http://localhost:", "http://127.0.0.1:"))
                for origin in self.cors_origins
            ):
                raise ValueError(
                    "Production CORS_ORIGINS must contain explicit non-local origins"
                )
        return self

    # --- Database ---
    database_url: str = "sqlite:///./siem.db"

    # --- Logging ---
    log_level: str = "INFO"
    log_json: bool = True

    # --- Splunk (Phase 2) ---
    splunk_hec_url: str = "https://localhost:8088"
    splunk_hec_token: str = ""
    splunk_hec_index: str = "siem_threat_detection"
    splunk_hec_source: str = "siem-backend"
    splunk_hec_sourcetype: str = "_json"
    splunk_api_url: str = "https://localhost:8089"
    splunk_username: str = "admin"
    splunk_password: str = ""
    splunk_verify_tls: bool = False
    splunk_request_timeout_seconds: float = 10.0
    splunk_search_poll_interval_seconds: float = 0.5
    splunk_search_max_poll_attempts: int = 20

    # --- Snort (Phase 3) ---
    snort_alert_log_path: str = "/data/snort/log/alert"
    snort_rules_path: str = "/data/snort/rules/local.rules"
    snort_log_stale_after_seconds: float = 300.0
    snort_forward_to_splunk: bool = False

    # --- Integration (Phase 4): background auto-sync ---
    auto_sync_enabled: bool = False
    sync_interval_seconds: float = 60.0
    sync_splunk_query: str = "search index=siem_threat_detection sourcetype=snort_alert_json"
    sync_splunk_earliest_time: str = "-5m"

    # --- Incident Engine (Phase 5) ---
    correlation_default_threshold: int = 3
    correlation_default_window_seconds: float = 300.0
    auto_correlate_enabled: bool = False

    # --- AI / anomaly detection (Phase 6) ---
    ml_model_dir: str = "/app/models"
    ml_model_name: str = "isolation-forest-alert-features"
    ml_contamination: float = 0.1
    ml_min_training_samples: int = 20
    ml_score_on_ingest_enabled: bool = False
    ml_anomaly_severity_threshold: float = -0.2

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlSettingsSource(settings_cls),
            file_secret_settings,
        )


_settings_singleton: Settings | None = None


def get_settings() -> Settings:
    global _settings_singleton
    if _settings_singleton is None:
        _settings_singleton = Settings()
    return _settings_singleton


def reset_settings_cache() -> None:
    global _settings_singleton
    _settings_singleton = None
