"""Thin client around Splunk's HTTP Event Collector (ingest) and the
Splunk REST search-job API (query). Wrapped in a single `httpx.Client` so
tests can swap it out / mock it with `respx`."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import Settings
from app.logging_config import get_logger

logger = get_logger(__name__)


class SplunkServiceError(RuntimeError):
    pass


def _json_safe(value: Any) -> Any:
    """Recursively stringifies datetimes so dicts bound for a JSON column
    or an HTTP JSON body never choke the encoder."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


class SplunkService:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.Client(verify=settings.splunk_verify_tls)

    def close(self) -> None:
        self._client.close()

    # --- HEC ingest -----------------------------------------------------

    def send_event(
        self,
        event: dict,
        source_ip: str | None = None,
        severity: str | None = None,
        signature: str | None = None,
        event_time: datetime | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "event": _json_safe(event),
            "index": self.settings.splunk_hec_index,
            "source": self.settings.splunk_hec_source,
            "sourcetype": self.settings.splunk_hec_sourcetype,
        }
        if event_time is not None:
            payload["time"] = event_time.timestamp()
        if source_ip:
            payload.setdefault("event", {})
            if isinstance(payload["event"], dict):
                payload["event"].setdefault("source_ip", source_ip)
        if severity:
            if isinstance(payload["event"], dict):
                payload["event"].setdefault("severity", severity)
        if signature:
            if isinstance(payload["event"], dict):
                payload["event"].setdefault("signature", signature)

        url = f"{self.settings.splunk_hec_url}/services/collector/event"
        headers = {"Authorization": f"Splunk {self.settings.splunk_hec_token}"}
        try:
            resp = self._client.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.settings.splunk_request_timeout_seconds,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("splunk_hec_send_failed", extra={"error": str(exc)})
            raise SplunkServiceError(f"Failed to send event to Splunk HEC: {exc}") from exc
        return resp.json()

    # --- Search job API ---------------------------------------------------

    def search(
        self,
        query: str,
        earliest_time: str = "-15m",
        latest_time: str = "now",
    ) -> list[dict]:
        search_query = query if query.strip().startswith("search") else f"search {query}"
        job_id = self._create_search_job(search_query, earliest_time, latest_time)
        self._wait_for_job(job_id)
        return self._fetch_results(job_id)

    def _auth(self) -> tuple[str, str]:
        return (self.settings.splunk_username, self.settings.splunk_password)

    def _create_search_job(self, query: str, earliest_time: str, latest_time: str) -> str:
        url = f"{self.settings.splunk_api_url}/services/search/jobs"
        try:
            resp = self._client.post(
                url,
                data={
                    "search": query,
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "output_mode": "json",
                },
                auth=self._auth(),
                timeout=self.settings.splunk_request_timeout_seconds,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise SplunkServiceError(f"Failed to create Splunk search job: {exc}") from exc
        data = resp.json()
        sid = data.get("sid")
        if not sid:
            raise SplunkServiceError(f"Splunk search job response missing sid: {data}")
        return sid

    def _wait_for_job(self, job_id: str) -> None:
        url = f"{self.settings.splunk_api_url}/services/search/jobs/{job_id}"
        for _ in range(self.settings.splunk_search_max_poll_attempts):
            try:
                resp = self._client.get(
                    url,
                    params={"output_mode": "json"},
                    auth=self._auth(),
                    timeout=self.settings.splunk_request_timeout_seconds,
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                raise SplunkServiceError(f"Failed to poll Splunk search job: {exc}") from exc
            data = resp.json()
            entry = (data.get("entry") or [{}])[0]
            content = entry.get("content", {})
            if content.get("isDone"):
                return
            time.sleep(self.settings.splunk_search_poll_interval_seconds)
        raise SplunkServiceError(f"Splunk search job {job_id} did not complete in time")

    def _fetch_results(self, job_id: str) -> list[dict]:
        url = f"{self.settings.splunk_api_url}/services/search/jobs/{job_id}/results"
        try:
            resp = self._client.get(
                url,
                params={"output_mode": "json"},
                auth=self._auth(),
                timeout=self.settings.splunk_request_timeout_seconds,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise SplunkServiceError(f"Failed to fetch Splunk search results: {exc}") from exc
        data = resp.json()
        return data.get("results", [])


def build_external_id(result: dict) -> str | None:
    """Splunk results carry `_cd` (bucket:offset within an index) as a
    stable per-event identifier; fall back to `event_id` or `_serial` if a
    particular search doesn't surface `_cd`."""
    for key in ("_cd", "event_id", "_serial"):
        value = result.get(key)
        if value:
            return f"splunk:{value}"
    return None
