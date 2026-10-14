from __future__ import annotations

import pytest

from app.services.snort_service import (
    SnortParseError,
    build_external_id,
    parse_alert_file,
    parse_alert_line,
    severity_from_priority,
)

REAL_SNORT_ALERT_LINE = (
    "10/04-12:34:56.789012  [**] [1:1000001:1] ICMP Test Rule Triggered [**] "
    "[Classification: Potentially Bad Traffic] [Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.10"
)

REAL_SNORT_ALERT_WITH_PORTS = (
    "10/04-12:35:01.111111  [**] [1:1000002:2] TCP SYN scan detected [**] "
    "[Classification: Attempted Information Leak] [Priority: 2] {TCP} "
    "10.0.0.5:51234 -> 10.0.0.10:80"
)

LIVE_SNORT_ALERT_WITH_NUMERIC_PROTOCOL = (
    "10/12-12:09:43.799862  [**] [1:1000004:1] SMB Access Attempt [**] "
    "[Classification: Generic Protocol Command Decode] [Priority: 3] "
    "{PROTO:006} 172.18.0.6:61115 -> 172.18.0.3:445"
)


def test_parse_alert_line_icmp():
    parsed = parse_alert_line(REAL_SNORT_ALERT_LINE, year=2026)
    assert parsed is not None
    assert parsed.gid == 1
    assert parsed.sid == 1000001
    assert parsed.rev == 1
    assert parsed.message == "ICMP Test Rule Triggered"
    assert parsed.classification == "Potentially Bad Traffic"
    assert parsed.priority == 2
    assert parsed.protocol == "ICMP"
    assert parsed.source_ip == "10.0.0.5"
    assert parsed.dest_ip == "10.0.0.10"
    assert parsed.source_port is None
    assert parsed.event_time.month == 10
    assert parsed.event_time.day == 4


def test_parse_alert_line_with_ports():
    parsed = parse_alert_line(REAL_SNORT_ALERT_WITH_PORTS, year=2026)
    assert parsed is not None
    assert parsed.source_port == 51234
    assert parsed.dest_port == 80
    assert parsed.protocol == "TCP"

def test_parse_live_alert_line_with_numeric_protocol():
    parsed = parse_alert_line(LIVE_SNORT_ALERT_WITH_NUMERIC_PROTOCOL, year=2026)
    assert parsed is not None
    assert parsed.protocol == "PROTO:006"
    assert parsed.source_ip == "172.18.0.6"
    assert parsed.dest_ip == "172.18.0.3"
    assert parsed.source_port == 61115
    assert parsed.dest_port == 445


def test_parse_alert_line_blank_returns_none():
    assert parse_alert_line("") is None
    assert parse_alert_line("   ") is None


def test_parse_alert_line_unparseable_returns_none():
    assert parse_alert_line("this is not a snort alert line at all") is None


def test_parse_alert_file_counts(tmp_path):
    log_file = tmp_path / "alert"
    log_file.write_text(
        REAL_SNORT_ALERT_LINE + "\n" + "garbage unparseable line\n" + REAL_SNORT_ALERT_WITH_PORTS + "\n"
    )
    parsed, read_lines, skipped = parse_alert_file(log_file)
    assert read_lines == 3
    assert len(parsed) == 2
    assert skipped == 1


def test_parse_alert_line_invalid_timestamp_raises():
    # Matches the regex shape but month=13 is not a real month, so the
    # datetime() constructor raises ValueError, which is wrapped and
    # re-raised as SnortParseError rather than silently skipped.
    bad_line = (
        "13/45-99:99:99.000000  [**] [1:1:1] bogus timestamp [**] "
        "1.1.1.1 -> 2.2.2.2"
    )
    with pytest.raises(SnortParseError):
        parse_alert_line(bad_line, year=2026)


def test_parse_alert_file_skips_blank_lines(tmp_path):
    log_file = tmp_path / "alert"
    log_file.write_text(
        "\n\n" + REAL_SNORT_ALERT_LINE + "\n\n   \n" + REAL_SNORT_ALERT_WITH_PORTS + "\n"
    )
    parsed, read_lines, skipped = parse_alert_file(log_file)
    # Blank/whitespace-only lines are skipped before being counted as "read".
    assert read_lines == 2
    assert len(parsed) == 2
    assert skipped == 0


def test_parse_alert_file_missing_returns_empty(tmp_path):
    parsed, read_lines, skipped = parse_alert_file(tmp_path / "does-not-exist")
    assert parsed == []
    assert read_lines == 0
    assert skipped == 0


def test_build_external_id_is_stable_and_unique():
    a = parse_alert_line(REAL_SNORT_ALERT_LINE, year=2026)
    b = parse_alert_line(REAL_SNORT_ALERT_WITH_PORTS, year=2026)
    assert build_external_id(a) != build_external_id(b)
    assert build_external_id(a) == build_external_id(a)


def test_severity_from_priority_mapping():
    assert severity_from_priority(1) == "critical"
    assert severity_from_priority(2) == "high"
    assert severity_from_priority(3) == "medium"
    assert severity_from_priority(5) == "low"
    assert severity_from_priority(None) == "medium"
