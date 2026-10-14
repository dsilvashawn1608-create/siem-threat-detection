from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models.alert import AlertSource
from app.schemas.snort import SnortSyncResponse
from app.services.alert_ingest import get_or_create_alert
from app.services.snort_service import (
    build_external_id,
    parse_alert_file,
    severity_from_priority,
)

router = APIRouter(prefix="/snort", tags=["snort"])


@router.post("/sync", response_model=SnortSyncResponse)
def sync(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SnortSyncResponse:
    parsed_alerts, read_lines, skipped_unparseable = parse_alert_file(
        settings.snort_alert_log_path
    )

    created = 0
    skipped_duplicates = 0
    for parsed in parsed_alerts:
        external_id = build_external_id(parsed)
        _, was_created = get_or_create_alert(
            db,
            external_id=external_id,
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
        if was_created:
            created += 1
        else:
            skipped_duplicates += 1
    db.commit()

    return SnortSyncResponse(
        read_lines=read_lines,
        parsed=len(parsed_alerts),
        created=created,
        skipped_duplicates=skipped_duplicates,
        skipped_unparseable=skipped_unparseable,
    )
