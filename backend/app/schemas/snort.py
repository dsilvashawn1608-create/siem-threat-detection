from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class SnortAlertParsed(BaseModel):
    """One parsed line (block) from Snort's `alert_fast` log format."""

    gid: int
    sid: int
    rev: int
    message: str
    classification: str | None = None
    priority: int | None = None
    protocol: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    event_time: datetime


class SnortSyncResponse(BaseModel):
    read_lines: int
    parsed: int
    created: int
    skipped_duplicates: int
    skipped_unparseable: int
