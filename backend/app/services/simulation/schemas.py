"""Schemas for the Gemini-planned lab simulation.

Gemini never produces alerts directly. It produces a *plan* -- a short list of
scenarios drawn from a fixed enum -- and this module is the trust boundary:
every value coming back from the model is coerced and clamped here, so a
hallucinated or prompt-injected response can at worst pick a different
allowed scenario or a smaller/larger-but-capped intensity.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

MAX_SCENARIOS = 5
MAX_TOTAL_ALERTS = 300
MAX_PROMPT_CHARS = 500
MAX_WINDOW_MINUTES = 240


class ScenarioType(str, Enum):
    PORT_SCAN = "port_scan"
    SSH_BRUTE_FORCE = "ssh_brute_force"
    FAILED_LOGIN_SPRAY = "failed_login_spray"
    WEB_SQL_INJECTION = "web_sql_injection"
    MALWARE_DOWNLOAD = "malware_download"
    C2_BEACONING = "c2_beaconing"
    LATERAL_MOVEMENT_SMB = "lateral_movement_smb"
    DNS_TUNNELING = "dns_tunneling"
    DATA_EXFILTRATION = "data_exfiltration"
    BENIGN_WEB_PROBE = "benign_web_probe"


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


class ScenarioPlan(BaseModel):
    """One scenario in a plan. Out-of-range numbers are clamped, not rejected."""

    type: ScenarioType
    intensity: int = 3
    attacker_count: int = 1
    target_count: int = 1
    duration_minutes: int = 15
    narrative: str = ""

    @field_validator("intensity", mode="before")
    @classmethod
    def _intensity(cls, v: Any) -> int:
        return _clamp_int(v, 1, 5, 3)

    @field_validator("attacker_count", mode="before")
    @classmethod
    def _attackers(cls, v: Any) -> int:
        return _clamp_int(v, 1, 5, 1)

    @field_validator("target_count", mode="before")
    @classmethod
    def _targets(cls, v: Any) -> int:
        return _clamp_int(v, 1, 5, 1)

    @field_validator("duration_minutes", mode="before")
    @classmethod
    def _duration(cls, v: Any) -> int:
        return _clamp_int(v, 1, MAX_WINDOW_MINUTES, 15)

    @field_validator("narrative", mode="before")
    @classmethod
    def _narrative(cls, v: Any) -> str:
        return str(v or "")[:300]


class SimulationPlan(BaseModel):
    title: str = "Lab simulation"
    campaign: bool = False
    scenarios: list[ScenarioPlan]
    planner: Literal["gemini", "fallback"] = "fallback"
    planner_note: str = ""

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, v: Any) -> str:
        return (str(v or "").strip() or "Lab simulation")[:120]

    @field_validator("scenarios", mode="before")
    @classmethod
    def _scenarios(cls, v: Any) -> list[Any]:
        """Drop entries with an unknown scenario type; cap the list length."""
        if not isinstance(v, list):
            return []
        allowed = {t.value for t in ScenarioType}
        kept = [
            item
            for item in v
            if (isinstance(item, ScenarioPlan))
            or (isinstance(item, dict) and item.get("type") in allowed)
        ]
        return kept[:MAX_SCENARIOS]


# Gemini's `responseSchema` (OpenAPI subset). Constraining the model to the
# enum means it cannot invent scenario types; the pydantic models above
# remain the real enforcement because schema adherence is best-effort.
GEMINI_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "title": {"type": "STRING"},
        "campaign": {"type": "BOOLEAN"},
        "scenarios": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "type": {"type": "STRING", "enum": [t.value for t in ScenarioType]},
                    "intensity": {"type": "INTEGER"},
                    "attacker_count": {"type": "INTEGER"},
                    "target_count": {"type": "INTEGER"},
                    "duration_minutes": {"type": "INTEGER"},
                    "narrative": {"type": "STRING"},
                },
                "required": ["type"],
            },
        },
    },
    "required": ["scenarios"],
}
