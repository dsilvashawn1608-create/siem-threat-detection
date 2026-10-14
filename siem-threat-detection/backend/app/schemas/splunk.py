from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class SplunkEventIn(BaseModel):
    """Payload accepted by POST /splunk/events — forwarded to HEC as-is,
    plus whatever metadata fields we attach (index/source/sourcetype)."""

    event: dict
    source_ip: str | None = None
    severity: str | None = None
    signature: str | None = None
    time: datetime | None = None


class SplunkSearchRequest(BaseModel):
    query: str
    earliest_time: str = "-15m"
    latest_time: str = "now"


class SplunkSearchResult(BaseModel):
    results: list[dict]
    result_count: int


class SplunkSyncResponse(BaseModel):
    fetched: int
    created: int
    skipped_duplicates: int
