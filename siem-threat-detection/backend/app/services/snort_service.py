"""Parser for Snort 2.9's `alert_fast` text log format.

Snort 2.9.20 (the version Ubuntu 24.04's `apt` ships as the `snort`
package — there is no Snort 3 apt package) has no built-in JSON alert
output. `alert_fast` writes one alert as a 2-line block, e.g.:

    10/04-12:34:56.789012  [**] [1:1000001:1] ICMP Test Rule Triggered [**] \
[Classification: Potentially Bad Traffic] [Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.10

This module regex-parses that exact shape; verified against real output
from an installed `snort` binary run over a scapy-synthesized pcap
(see snort/pcaps/).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from app.logging_config import get_logger
from app.schemas.snort import SnortAlertParsed

logger = get_logger(__name__)

# 10/04-12:34:56.789012  [**] [1:1000001:1] MESSAGE [**] [Classification: X] [Priority: N] {PROTO} SRC_IP:SRC_PORT -> DST_IP:DST_PORT
#
# The address alternation tries IPv4 (digits/dots only) before the bare
# hex/colon fallback (IPv6, port not parsed) — IPv4's character class
# deliberately excludes ':' so the optional ":PORT" suffix isn't swallowed
# into the address itself (an all-inclusive "[0-9a-fA-F.:]+" class makes
# the IP match greedily consume "10.0.0.5:51234" whole, leaving no port).
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_IPV6_OR_OTHER = r"[0-9a-fA-F:]+"
_ADDR = rf"(?:{_IPV4}|{_IPV6_OR_OTHER})"

_ALERT_RE = re.compile(
    r"^(?P<date>\d{2}/\d{2})-(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.+?)\s+\[\*\*\]\s*"
    r"(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s*)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s*)?"
    r"(?:\{(?P<protocol>[A-Za-z0-9_]+)\}\s*)?"
    rf"(?P<src>{_ADDR})(?::(?P<src_port>\d+))?\s*->\s*"
    rf"(?P<dst>{_ADDR})(?::(?P<dst_port>\d+))?\s*$"
)


class SnortParseError(ValueError):
    pass


def parse_alert_line(line: str, year: int | None = None) -> SnortAlertParsed | None:
    """Parses a single logical alert line. Returns None for blank/unparseable
    lines rather than raising, so a caller can skip them and keep a count."""
    line = line.strip()
    if not line:
        return None
    match = _ALERT_RE.match(line)
    if not match:
        logger.warning("snort_unparseable_line", extra={"line": line[:300]})
        return None

    groups = match.groupdict()
    year = year or datetime.now(timezone.utc).year
    month, day = groups["date"].split("/")
    hh, mm, rest = groups["time"].split(":")
    ss, _, micro = rest.partition(".")
    try:
        event_time = datetime(
            year=year,
            month=int(month),
            day=int(day),
            hour=int(hh),
            minute=int(mm),
            second=int(ss),
            microsecond=int((micro + "000000")[:6]) if micro else 0,
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise SnortParseError(f"Invalid timestamp in Snort alert line: {line}") from exc

    return SnortAlertParsed(
        gid=int(groups["gid"]),
        sid=int(groups["sid"]),
        rev=int(groups["rev"]),
        message=groups["message"].strip(),
        classification=(groups.get("classification") or "").strip() or None,
        priority=int(groups["priority"]) if groups.get("priority") else None,
        protocol=groups.get("protocol"),
        source_ip=groups.get("src"),
        source_port=int(groups["src_port"]) if groups.get("src_port") else None,
        dest_ip=groups.get("dst"),
        dest_port=int(groups["dst_port"]) if groups.get("dst_port") else None,
        event_time=event_time,
    )


def parse_alert_file(path: str | Path) -> tuple[list[SnortAlertParsed], int, int]:
    """Returns (parsed_alerts, read_lines, skipped_unparseable)."""
    p = Path(path)
    if not p.exists():
        return [], 0, 0

    parsed: list[SnortAlertParsed] = []
    read_lines = 0
    skipped = 0
    # alert_fast writes one alert per logical line (no blank-line blocks in
    # the default format), so each non-empty line is one alert attempt.
    for raw_line in p.read_text(errors="replace").splitlines():
        if not raw_line.strip():
            continue
        read_lines += 1
        alert = parse_alert_line(raw_line)
        if alert is None:
            skipped += 1
        else:
            parsed.append(alert)
    return parsed, read_lines, skipped


def build_external_id(alert: SnortAlertParsed) -> str:
    return (
        f"snort:{alert.gid}:{alert.sid}:{alert.rev}:"
        f"{alert.event_time.isoformat()}:{alert.source_ip}:{alert.dest_ip}"
    )


def severity_from_priority(priority: int | None) -> str:
    """Snort priority 1 = highest. Maps onto our AlertSeverity scale."""
    if priority is None:
        return "medium"
    if priority <= 1:
        return "critical"
    if priority == 2:
        return "high"
    if priority == 3:
        return "medium"
    return "low"
