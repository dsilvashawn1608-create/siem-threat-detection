from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy.orm import Session

from app.config import Settings
from app.models.alert import AlertSeverity, AlertSource
from app.models.audit_record import AuditRecord
from app.models.user import User
from app.schemas.ai_analysis import AISimulationResponse
from app.services.alert_ingest import create_alert
from app.services.correlation import run_correlation_once
from app.services.gemini_service import classify_simulation_prompt

SimulationScenario = Literal["port_scan", "failed_logins", "web_probe"]

SOURCE_IP = "192.0.2.55"
DESTINATION_IP = "198.51.100.25"

_SCENARIOS: dict[SimulationScenario, tuple[str, str, list[tuple[int, str]]]] = {
    "port_scan": (
        "simulated port-scan pattern",
        "reconnaissance",
        [(22, "TCP"), (80, "TCP"), (443, "TCP"), (445, "TCP")],
    ),
    "failed_logins": (
        "simulated repeated SSH authentication failures",
        "authentication",
        [(22, "TCP"), (22, "TCP"), (22, "TCP")],
    ),
    "web_probe": (
        "simulated benign web-probe pattern",
        "web_probe",
        [(80, "TCP"), (443, "TCP"), (8080, "TCP")],
    ),
}


def create_synthetic_simulation(
    db: Session,
    *,
    prompt: str,
    actor: User,
    settings: Settings,
) -> AISimulationResponse:
    scenario = classify_simulation_prompt(settings, prompt)
    simulation_id = str(uuid.uuid4())
    signature, category, targets = _SCENARIOS[scenario]
    now = datetime.now(timezone.utc)
    alerts = [
        create_alert(
            db,
            source=AlertSource.MANUAL,
            severity=AlertSeverity.MEDIUM,
            signature=f"[SIMULATION] {signature}",
            category=category,
            description=(
                "Synthetic SIEM demo event only. No packets, login attempts, "
                "or network requests were sent."
            ),
            source_ip=SOURCE_IP,
            source_port=41000 + index,
            dest_ip=DESTINATION_IP,
            dest_port=destination_port,
            protocol=protocol,
            raw_data={
                "synthetic": True,
                "simulation_id": simulation_id,
                "scenario": scenario,
            },
            external_id=f"simulation:{simulation_id}:{index}",
            event_time=now,
            commit=False,
        )
        for index, (destination_port, protocol) in enumerate(targets, start=1)
    ]
    db.add(
        AuditRecord(
            actor=actor.username,
            action="synthetic_simulation_created",
            resource_type="simulation",
            resource_id=simulation_id,
            details={
                "scenario": scenario,
                "synthetic": True,
                "alerts_created": len(alerts),
                "alert_ids": [alert.id for alert in alerts],
            },
        )
    )
    db.commit()

    incidents = run_correlation_once(db, settings, actor=actor.username)
    return AISimulationResponse(
        simulation_id=simulation_id,
        scenario=scenario,
        alert_ids=[alert.id for alert in alerts],
        alerts_created=len(alerts),
        incidents_created=len(incidents),
        message=(
            "Synthetic demo alerts were added to the SIEM. No real attack traffic "
            "was sent. "
            + (
                f"The configured correlation engine created {len(incidents)} incident(s)."
                if incidents
                else "Run correlation from the Incidents tab if you want to evaluate "
                "the current correlation settings."
            )
        ),
    )
