"""Gemini-planned, fully synthetic attack simulation for the SIEM lab."""

from .generator import SIM_EXTERNAL_ID_PREFIX, SIM_PREFIX, SyntheticAlert, generate_alerts
from .planner import GeminiPlanError, fallback_plan, plan_simulation
from .schemas import (
    MAX_PROMPT_CHARS,
    MAX_TOTAL_ALERTS,
    ScenarioPlan,
    ScenarioType,
    SimulationPlan,
)
from .service import (
    SimulationResult,
    build_simulation,
    catalog,
    is_simulated_external_id,
    run_simulation,
)

__all__ = [
    "GeminiPlanError", "MAX_PROMPT_CHARS", "MAX_TOTAL_ALERTS", "ScenarioPlan", "ScenarioType",
    "SIM_EXTERNAL_ID_PREFIX", "SIM_PREFIX", "SimulationPlan", "SimulationResult",
    "SyntheticAlert", "build_simulation", "catalog", "fallback_plan", "generate_alerts",
    "is_simulated_external_id", "plan_simulation", "run_simulation",
]
