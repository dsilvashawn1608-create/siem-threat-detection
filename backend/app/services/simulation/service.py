"""Orchestration: request -> plan -> alerts -> (optionally) ingest.

This module is the only public surface the API route needs:

    result = build_simulation(prompt, api_key=settings.gemini_api_key)   # preview
    summary = run_simulation(prompt, ingest_alert=..., api_key=...)      # persist

``ingest_alert`` is injected rather than imported so this package has no
dependency on the ORM or on alert_ingest.py's exact signature; the route
supplies a small adapter (see docs/SIMULATION.md).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from .generator import SIM_EXTERNAL_ID_PREFIX, SyntheticAlert, generate_alerts
from .planner import DEFAULT_MODEL, plan_simulation
from .scenarios import CATALOG
from .schemas import SimulationPlan


@dataclass
class SimulationResult:
    plan: SimulationPlan
    run_id: str
    seed: int
    window_start: datetime
    window_end: datetime
    alerts: list[SyntheticAlert]
    scenarios: list[dict[str, Any]]

    def summary(self) -> dict[str, Any]:
        severities = Counter(a.severity for a in self.alerts)
        sources = Counter(a.source for a in self.alerts)
        malicious = sum(1 for a in self.alerts if a.raw_data.get("malicious"))
        mitre = sorted({t for s in self.scenarios for t in s["mitre"]})
        return {
            "run_id": self.run_id,
            "seed": self.seed,
            "title": self.plan.title,
            "planner": self.plan.planner,
            "planner_note": self.plan.planner_note,
            "campaign": self.plan.campaign,
            "alert_count": len(self.alerts),
            "malicious_alerts": malicious,
            "benign_alerts": len(self.alerts) - malicious,
            "by_severity": dict(severities),
            "by_source": dict(sources),
            "mitre_techniques": mitre,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "scenarios": self.scenarios,
            "synthetic": True,
        }


def build_simulation(
    prompt: str,
    *,
    api_key: str | None,
    model: str = DEFAULT_MODEL,
    seed: int | None = None,
    now: datetime | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] | None = None,
) -> SimulationResult:
    """Plan and generate without persisting anything (the "preview" path)."""
    kwargs: dict[str, Any] = {"api_key": api_key, "model": model, "client": client}
    if sleep is not None:
        kwargs["sleep"] = sleep
    plan = plan_simulation(prompt, **kwargs)
    gen = generate_alerts(plan, seed=seed, now=now)
    return SimulationResult(
        plan=plan,
        run_id=gen.run_id,
        seed=gen.seed,
        window_start=gen.window_start,
        window_end=gen.window_end,
        alerts=gen.alerts,
        scenarios=gen.scenarios,
    )


def run_simulation(
    prompt: str,
    *,
    ingest_alert: Callable[[dict[str, Any]], Any],
    api_key: str | None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Plan, generate, and push every alert through ``ingest_alert``.

    ``ingest_alert`` gets one alert dict and returns truthy if a new row was
    created, falsy if it already existed (idempotent on external_id).
    """
    result = build_simulation(prompt, api_key=api_key, **kwargs)
    created = 0
    for alert in result.alerts:
        if ingest_alert(alert.to_dict()):
            created += 1
    summary = result.summary()
    summary["created"] = created
    summary["skipped_existing"] = len(result.alerts) - created
    return summary


def catalog() -> list[dict[str, Any]]:
    """Scenario list for a UI dropdown / GET /simulation/scenarios."""
    return [
        {
            "type": t.value,
            "label": d.label,
            "description": d.description,
            "source": d.source,
            "mitre": list(d.mitre),
            "malicious": d.malicious,
        }
        for t, d in CATALOG.items()
    ]


def is_simulated_external_id(external_id: str | None) -> bool:
    """True for alerts created by the simulator (use for the 'clear simulated data' filter)."""
    return bool(external_id) and external_id.startswith(SIM_EXTERNAL_ID_PREFIX)  # type: ignore[union-attr]
