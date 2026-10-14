from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.api.dependencies import require_admin
from app.database import get_db
from app.models.alert import AlertSeverity, AlertSource
from app.schemas.splunk import (
    SplunkEventIn,
    SplunkSearchRequest,
    SplunkSearchResult,
    SplunkSyncResponse,
)
from app.services.alert_ingest import get_or_create_alert
from app.services.splunk_service import SplunkService, SplunkServiceError, build_external_id

router = APIRouter(prefix="/splunk", tags=["splunk"])


def get_splunk_service(settings: Settings = Depends(get_settings)) -> SplunkService:
    return SplunkService(settings)


@router.post("/events")
def send_event(
    payload: SplunkEventIn,
    _admin=Depends(require_admin),
    service: SplunkService = Depends(get_splunk_service),
) -> dict:
    try:
        result = service.send_event(
            event=payload.event,
            source_ip=payload.source_ip,
            severity=payload.severity,
            signature=payload.signature,
            event_time=payload.time,
        )
    except SplunkServiceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        service.close()
    return result


@router.post("/search", response_model=SplunkSearchResult)
def search(
    payload: SplunkSearchRequest,
    _admin=Depends(require_admin),
    service: SplunkService = Depends(get_splunk_service),
) -> SplunkSearchResult:
    try:
        results = service.search(
            query=payload.query,
            earliest_time=payload.earliest_time,
            latest_time=payload.latest_time,
        )
    except SplunkServiceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        service.close()
    return SplunkSearchResult(results=results, result_count=len(results))


@router.post("/sync", response_model=SplunkSyncResponse)
def sync(
    _admin=Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: SplunkService = Depends(get_splunk_service),
) -> SplunkSyncResponse:
    try:
        results = service.search(
            query=settings.sync_splunk_query,
            earliest_time=settings.sync_splunk_earliest_time,
        )
    except SplunkServiceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        service.close()

    created = 0
    skipped = 0
    for result in results:
        external_id = build_external_id(result)
        severity_raw = str(result.get("severity", "medium")).lower()
        try:
            severity = AlertSeverity(severity_raw)
        except ValueError:
            severity = AlertSeverity.MEDIUM

        alert, was_created = get_or_create_alert(
            db,
            external_id=external_id,
            source=AlertSource.SPLUNK,
            severity=severity,
            signature=str(result.get("signature") or result.get("_raw", "splunk_event"))[:255],
            description=str(result.get("_raw", ""))[:2000] or None,
            source_ip=result.get("source_ip"),
            raw_data=result,
        )
        if was_created:
            created += 1
        else:
            skipped += 1
    db.commit()

    return SplunkSyncResponse(
        fetched=len(results), created=created, skipped_duplicates=skipped
    )
