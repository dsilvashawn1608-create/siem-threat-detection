"""Background asyncio loop that periodically pulls new Splunk/Snort
alerts and runs the correlation engine, started/stopped from FastAPI's
lifespan context manager. `session_factory` is injectable so tests can
point it at a test DB rather than relying on import-time module
attributes (see /learnings: an earlier version bound `SessionLocal` at
import time, which silently broke monkeypatching in tests)."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_config import get_logger
from app.models.alert import AlertSource
from app.services.correlation import run_correlation_once
from app.services.snort_service import (
    build_external_id as snort_external_id,
    parse_alert_file,
    severity_from_priority,
)
from app.services.alert_ingest import get_or_create_alert
from app.services.splunk_service import SplunkService, SplunkServiceError, build_external_id
from app.models.alert import AlertSeverity

logger = get_logger(__name__)

SessionFactory = Callable[[], Session]


def sync_snort_once(db: Session, settings: Settings) -> dict:
    parsed_alerts, read_lines, skipped_unparseable = parse_alert_file(
        settings.snort_alert_log_path
    )
    created = 0
    skipped_duplicates = 0
    for parsed in parsed_alerts:
        _, was_created = get_or_create_alert(
            db,
            external_id=snort_external_id(parsed),
            source=AlertSource.SNORT,
            severity=severity_from_priority(parsed.priority),
            signature=parsed.message,
            category=parsed.classification,
            source_ip=parsed.source_ip,
            source_port=parsed.source_port,
            dest_ip=parsed.dest_ip,
            dest_port=parsed.dest_port,
            protocol=parsed.protocol,
            raw_data=parsed.model_dump(mode="json"),
            event_time=parsed.event_time,
        )
        created += int(was_created)
        skipped_duplicates += int(not was_created)
    db.commit()
    return {
        "read_lines": read_lines,
        "created": created,
        "skipped_duplicates": skipped_duplicates,
        "skipped_unparseable": skipped_unparseable,
    }


def sync_splunk_once(db: Session, settings: Settings) -> dict:
    service = SplunkService(settings)
    try:
        results = service.search(
            query=settings.sync_splunk_query,
            earliest_time=settings.sync_splunk_earliest_time,
        )
    except SplunkServiceError as exc:
        logger.error("scheduled_splunk_sync_failed", extra={"error": str(exc)})
        return {"fetched": 0, "created": 0, "skipped_duplicates": 0, "error": str(exc)}
    finally:
        service.close()

    created = 0
    skipped = 0
    for result in results:
        severity_raw = str(result.get("severity", "medium")).lower()
        try:
            severity = AlertSeverity(severity_raw)
        except ValueError:
            severity = AlertSeverity.MEDIUM
        _, was_created = get_or_create_alert(
            db,
            external_id=build_external_id(result),
            source=AlertSource.SPLUNK,
            severity=severity,
            signature=str(result.get("signature") or result.get("_raw", "splunk_event"))[:255],
            description=str(result.get("_raw", ""))[:2000] or None,
            source_ip=result.get("source_ip"),
            raw_data=result,
        )
        created += int(was_created)
        skipped += int(not was_created)
    db.commit()
    return {"fetched": len(results), "created": created, "skipped_duplicates": skipped}


def run_sync_once(
    settings: Settings,
    session_factory: SessionFactory,
    *,
    actor: str = "scheduler",
) -> dict:
    db = session_factory()
    try:
        result = {"snort": sync_snort_once(db, settings)}
        if settings.splunk_hec_token:
            result["splunk"] = sync_splunk_once(db, settings)
        if settings.auto_correlate_enabled:
            incidents = run_correlation_once(db, settings, actor=actor)
            result["incidents_created"] = len(incidents)
        logger.info("scheduled_sync_complete", extra={"result": result})
        return result
    finally:
        db.close()


async def periodic_sync_loop(
    settings: Settings,
    session_factory: SessionFactory,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    stop_event = stop_event or asyncio.Event()
    while not stop_event.is_set():
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, run_sync_once, settings, session_factory
            )
        except Exception:  # pragma: no cover - defensive; one bad cycle shouldn't kill the loop
            logger.exception("periodic_sync_cycle_failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=settings.sync_interval_seconds)
        except asyncio.TimeoutError:
            continue
