"""Regression test using a real `alert_fast` log file captured by running
an actual installed Snort 2.9.20 binary (`snort -c snort.conf -r
pcaps/demo-lab-traffic.pcap -A fast`) against the project's demo pcap —
see snort/pcaps/generate_demo_pcap.py and snort/rules/local.rules. This
pins the parser to real Snort output rather than only hand-written
fixtures, since Snort's text format has enough quirks (variable spacing,
optional classification/priority/protocol blocks) that a hand-rolled
sample can accidentally be easier to parse than the real thing."""
from __future__ import annotations

from pathlib import Path

from app.services.snort_service import parse_alert_file

FIXTURE = Path(__file__).parent / "fixtures" / "real_snort_alert.log"


def test_parses_every_line_of_real_snort_output():
    parsed, read_lines, skipped = parse_alert_file(FIXTURE)
    assert read_lines == 6
    assert skipped == 0
    assert len(parsed) == 6


def test_real_output_field_values_match_known_rules():
    parsed, _, _ = parse_alert_file(FIXTURE)
    by_sid = {p.sid: p for p in parsed}

    assert by_sid[1000001].protocol == "ICMP"
    assert by_sid[1000001].source_port is None

    assert by_sid[1000002].dest_port == 22
    assert by_sid[1000002].source_port == 51012

    assert by_sid[1000006].classification == "A Network Trojan was detected"
    assert by_sid[1000006].priority == 1
    assert by_sid[1000006].dest_port == 4444
