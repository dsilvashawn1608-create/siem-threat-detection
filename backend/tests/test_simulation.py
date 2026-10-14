"""Tests for the Gemini-planned lab simulation (app.services.simulation).

Self-contained: no database, no real network (Gemini is mocked with respx).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone

import httpx
import pytest
import respx

from app.services.simulation import (
    MAX_PROMPT_CHARS,
    MAX_TOTAL_ALERTS,
    SIM_EXTERNAL_ID_PREFIX,
    SIM_PREFIX,
    ScenarioPlan,
    ScenarioType,
    SimulationPlan,
    build_simulation,
    catalog,
    fallback_plan,
    generate_alerts,
    is_simulated_external_id,
    plan_simulation,
    run_simulation,
)
from app.services.simulation.__main__ import main as cli_main
from app.services.simulation.generator import LAB_NET
from app.services.simulation.planner import GEMINI_URL

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
URL = GEMINI_URL.format(model="gemini-2.5-flash")
KEY = "AIza-test-key-should-never-leak"
DOC_NETS = [ipaddress.ip_network(n) for n in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24")]


def sp(t: ScenarioType, **kw) -> ScenarioPlan:
    return ScenarioPlan(type=t, **kw)


def plan_of(*scenarios: ScenarioPlan, campaign: bool = False) -> SimulationPlan:
    return SimulationPlan(scenarios=list(scenarios), campaign=campaign)


def gemini_body(obj) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": json.dumps(obj)}]}}]}


def no_sleep(_s: float) -> None:
    return None


# ------------------------------------------------------------------ schemas


def test_scenario_numbers_are_clamped_not_rejected():
    s = ScenarioPlan(
        type="port_scan", intensity=99, attacker_count=-3, target_count="x",
        duration_minutes=100000, narrative="n" * 1000,
    )
    assert s.intensity == 5
    assert s.attacker_count == 1
    assert s.target_count == 1
    assert s.duration_minutes == 240
    assert len(s.narrative) == 300


def test_plan_drops_unknown_types_and_caps_length():
    items = [{"type": "port_scan"}, {"type": "rm -rf /"}, {"type": "nope"}] + [
        {"type": "ssh_brute_force"} for _ in range(10)
    ]
    plan = SimulationPlan(scenarios=items)
    assert len(plan.scenarios) == 5
    assert all(s.type in set(ScenarioType) for s in plan.scenarios)


def test_plan_title_defaults_when_blank():
    assert SimulationPlan(scenarios=[], title="   ").title == "Lab simulation"


# ------------------------------------------------------------------ generator


def test_generation_is_deterministic_for_a_seed():
    plan = plan_of(sp(ScenarioType.PORT_SCAN), sp(ScenarioType.SSH_BRUTE_FORCE, intensity=5))
    a = generate_alerts(plan, seed=7, now=NOW)
    b = generate_alerts(plan, seed=7, now=NOW)
    c = generate_alerts(plan, seed=8, now=NOW)
    assert [x.to_dict() for x in a.alerts] == [x.to_dict() for x in b.alerts]
    assert [x.source_ip for x in a.alerts] != [x.source_ip for x in c.alerts]


def test_only_reserved_or_lab_addresses_are_used():
    plan = plan_of(*[sp(t, attacker_count=3, target_count=3) for t in list(ScenarioType)[:5]])
    plan2 = plan_of(*[sp(t, attacker_count=3, target_count=3) for t in list(ScenarioType)[5:]])
    for p in (plan, plan2):
        for alert in generate_alerts(p, seed=1, now=NOW).alerts:
            for ip in (alert.source_ip, alert.dest_ip):
                addr = ipaddress.ip_address(ip)
                assert addr in LAB_NET or any(addr in n for n in DOC_NETS), ip


def test_alerts_are_labelled_synthetic_and_json_safe():
    res = generate_alerts(plan_of(*[sp(t) for t in ScenarioType][:5]), seed=3, now=NOW)
    assert res.alerts
    for a in res.alerts:
        assert a.signature.startswith(SIM_PREFIX)
        assert a.external_id.startswith(SIM_EXTERNAL_ID_PREFIX + res.run_id)
        assert a.raw_data["synthetic"] is True
        assert a.raw_data["simulation_run_id"] == res.run_id
        json.dumps(a.raw_data)  # raises if a datetime/other object sneaks in
        assert isinstance(a.event_time, datetime)


def test_external_ids_unique_and_time_ordered():
    res = generate_alerts(plan_of(sp(ScenarioType.PORT_SCAN), sp(ScenarioType.C2_BEACONING)),
                          seed=5, now=NOW)
    ids = [a.external_id for a in res.alerts]
    assert len(ids) == len(set(ids))
    times = [a.event_time for a in res.alerts]
    assert times == sorted(times)
    assert ids == sorted(ids)


def test_total_alert_cap_is_enforced():
    big = plan_of(*[sp(t, intensity=5, attacker_count=5) for t in [
        ScenarioType.PORT_SCAN, ScenarioType.SSH_BRUTE_FORCE, ScenarioType.DNS_TUNNELING,
        ScenarioType.C2_BEACONING, ScenarioType.DATA_EXFILTRATION]])
    res = generate_alerts(big, seed=9, now=NOW)
    assert len(res.alerts) <= MAX_TOTAL_ALERTS
    # every scenario still shows up after scaling down
    assert {a.raw_data["scenario"] for a in res.alerts} == {s.type.value for s in big.scenarios}


def test_ssh_brute_force_ends_with_a_success_only_at_high_intensity():
    hi = generate_alerts(plan_of(sp(ScenarioType.SSH_BRUTE_FORCE, intensity=5)), seed=1, now=NOW)
    wins = [a for a in hi.alerts if a.raw_data.get("auth_result") == "success"]
    assert len(wins) == 1
    assert wins[0].severity == "critical"
    assert hi.alerts[-1] is wins[0]
    lo = generate_alerts(plan_of(sp(ScenarioType.SSH_BRUTE_FORCE, intensity=3)), seed=1, now=NOW)
    assert not any(a.raw_data.get("auth_result") == "success" for a in lo.alerts)


def test_port_scan_sweeps_ports_in_ascending_order():
    res = generate_alerts(plan_of(sp(ScenarioType.PORT_SCAN, intensity=5)), seed=2, now=NOW)
    ports = [a.dest_port for a in res.alerts]
    assert ports == sorted(ports)
    assert len(set(ports)) >= 10


def test_events_fall_inside_reported_window():
    plan = plan_of(sp(ScenarioType.C2_BEACONING, duration_minutes=30),
                   sp(ScenarioType.PORT_SCAN, duration_minutes=10))
    res = generate_alerts(plan, seed=4, now=NOW)
    assert res.window_end == NOW
    for a in res.alerts:
        assert res.window_start <= a.event_time <= res.window_end


def test_beacons_are_roughly_periodic():
    res = generate_alerts(plan_of(sp(ScenarioType.C2_BEACONING, intensity=3, duration_minutes=60)),
                          seed=6, now=NOW)
    t = [a.event_time.timestamp() for a in res.alerts]
    step = 60 * 60 / len(t)
    gaps = [b - a for a, b in zip(t, t[1:])]
    assert all(0.6 * step <= g <= 1.4 * step for g in gaps)


def test_campaign_stages_are_sequential_and_share_actors():
    kill = [ScenarioType.PORT_SCAN, ScenarioType.SSH_BRUTE_FORCE, ScenarioType.MALWARE_DOWNLOAD,
            ScenarioType.C2_BEACONING, ScenarioType.DATA_EXFILTRATION]
    res = generate_alerts(plan_of(*[sp(t, duration_minutes=10) for t in kill], campaign=True),
                          seed=11, now=NOW)
    by = {t.value: [a for a in res.alerts if a.raw_data["scenario"] == t.value] for t in kill}

    # stages happen in order
    for first, second in zip(kill, kill[1:]):
        assert max(a.event_time for a in by[first.value]) <= min(
            a.event_time for a in by[second.value]
        )
    # one external attacker across the inbound stages
    assert {a.source_ip for a in by["port_scan"]} == {a.source_ip for a in by["ssh_brute_force"]}
    # the scanned/brute-forced victim is the host that later beacons and exfiltrates
    victim = by["port_scan"][0].dest_ip
    assert {a.source_ip for a in by["c2_beaconing"]} == {victim}
    assert {a.source_ip for a in by["data_exfiltration"]} == {victim}
    # beacons and exfil go to the same external server
    assert {a.dest_ip for a in by["c2_beaconing"]} == {a.dest_ip for a in by["data_exfiltration"]}


def test_without_campaign_each_scenario_gets_its_own_attacker():
    res = generate_alerts(plan_of(sp(ScenarioType.PORT_SCAN), sp(ScenarioType.SSH_BRUTE_FORCE)),
                          seed=12, now=NOW)
    scan = {a.source_ip for a in res.alerts if a.raw_data["scenario"] == "port_scan"}
    ssh = {a.source_ip for a in res.alerts if a.raw_data["scenario"] == "ssh_brute_force"}
    assert scan and ssh and scan.isdisjoint(ssh)


def test_benign_scenario_is_flagged_not_malicious():
    res = generate_alerts(plan_of(sp(ScenarioType.BENIGN_WEB_PROBE)), seed=1, now=NOW)
    assert res.alerts and all(a.raw_data["malicious"] is False for a in res.alerts)
    assert all(a.severity == "low" for a in res.alerts)


def test_empty_plan_generates_nothing():
    res = generate_alerts(SimulationPlan(scenarios=[]), seed=1, now=NOW)
    assert res.alerts == [] and res.scenarios == []


# ------------------------------------------------------------------ fallback planner


def test_fallback_maps_keywords_and_intensity():
    plan = fallback_plan("heavy ransomware attack")
    assert {s.type for s in plan.scenarios} == {
        ScenarioType.SSH_BRUTE_FORCE, ScenarioType.LATERAL_MOVEMENT_SMB,
        ScenarioType.DATA_EXFILTRATION,
    }
    assert plan.campaign is True
    assert all(s.intensity == 5 for s in plan.scenarios)
    assert plan.planner == "fallback"


def test_fallback_keywords_match_whole_words_for_short_tokens():
    plan = fallback_plan("adaptive deception research")  # contains the letters "apt"
    assert plan.campaign is False
    assert "default demo mix" in plan.planner_note


def test_fallback_is_deterministic():
    assert fallback_plan("dns tunnel and c2 beacon").model_dump() == fallback_plan(
        "dns tunnel and c2 beacon").model_dump()


def test_empty_prompt_uses_default_mix():
    plan = plan_simulation("   ", api_key=KEY)
    assert plan.planner == "fallback" and plan.scenarios


def test_no_api_key_uses_fallback_with_note():
    plan = plan_simulation("ssh brute force", api_key=None)
    assert plan.planner == "fallback"
    assert "GEMINI_API_KEY" in plan.planner_note


# ------------------------------------------------------------------ Gemini planner


@respx.mock
def test_gemini_plan_success_validates_clamps_and_filters():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=gemini_body({
        "title": "APT demo", "campaign": True,
        "scenarios": [
            {"type": "port_scan", "intensity": 99},
            {"type": "format_disk", "intensity": 3},  # not in the enum -> dropped
            {"type": "c2_beaconing", "duration_minutes": 9999},
        ],
    })))
    plan = plan_simulation("x" * 2000, api_key=KEY, sleep=no_sleep)
    assert plan.planner == "gemini" and plan.campaign is True
    assert [s.type for s in plan.scenarios] == [ScenarioType.PORT_SCAN, ScenarioType.C2_BEACONING]
    assert plan.scenarios[0].intensity == 5
    assert plan.scenarios[1].duration_minutes == 240

    req = route.calls.last.request
    assert req.headers["x-goog-api-key"] == KEY
    assert KEY not in str(req.url)  # key travels in a header, never the URL
    body = json.loads(req.content)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "responseSchema" in body["generationConfig"]
    assert len(body["contents"][0]["parts"][0]["text"]) == MAX_PROMPT_CHARS  # truncated


@respx.mock
def test_gemini_invalid_json_falls_back():
    respx.post(URL).mock(return_value=httpx.Response(
        200, json={"candidates": [{"content": {"parts": [{"text": "not json {"}]}}]}))
    plan = plan_simulation("port scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback" and "invalid JSON" in plan.planner_note
    assert {s.type for s in plan.scenarios} == {ScenarioType.PORT_SCAN}


@respx.mock
def test_gemini_with_no_valid_scenarios_falls_back():
    respx.post(URL).mock(return_value=httpx.Response(200, json=gemini_body(
        {"scenarios": [{"type": "ignore previous instructions"}]})))
    plan = plan_simulation("ssh brute force", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback" and "no valid scenarios" in plan.planner_note


@respx.mock
def test_gemini_rate_limit_is_retried_once():
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(429),
        httpx.Response(200, json=gemini_body({"scenarios": [{"type": "port_scan"}]})),
    ])
    plan = plan_simulation("scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "gemini" and route.call_count == 2


@respx.mock
def test_gemini_persistent_server_error_falls_back():
    route = respx.post(URL).mock(return_value=httpx.Response(503))
    plan = plan_simulation("dns tunneling", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback" and route.call_count == 2
    assert "HTTP 503" in plan.planner_note


@respx.mock
def test_gemini_auth_error_message_never_contains_the_key():
    respx.post(URL).mock(return_value=httpx.Response(403, json={"error": {"message": KEY}}))
    plan = plan_simulation("scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback"
    assert "GEMINI_API_KEY" in plan.planner_note
    assert KEY not in plan.planner_note


@respx.mock
def test_gemini_network_error_note_has_type_only():
    respx.post(URL).mock(side_effect=httpx.ConnectError(f"boom {KEY}"))
    plan = plan_simulation("scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback"
    assert "ConnectError" in plan.planner_note and KEY not in plan.planner_note


@respx.mock
def test_gemini_blocked_prompt_falls_back():
    respx.post(URL).mock(return_value=httpx.Response(
        200, json={"promptFeedback": {"blockReason": "SAFETY"}}))
    plan = plan_simulation("scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback" and "SAFETY" in plan.planner_note


@respx.mock
def test_gemini_empty_candidates_and_wrong_shape_fall_back():
    respx.post(URL).mock(side_effect=[
        httpx.Response(200, json={"candidates": []}),
        httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "[1,2]"}]}}]}),
        httpx.Response(200, text="<html>nope</html>"),
    ])
    for _ in range(3):
        assert plan_simulation("scan", api_key=KEY, sleep=no_sleep).planner == "fallback"


# ------------------------------------------------------------------ service / adapter


def test_run_simulation_is_idempotent_through_an_ingest_callback():
    seen: set[str] = set()

    def ingest(alert: dict) -> bool:
        if alert["external_id"] in seen:
            return False
        seen.add(alert["external_id"])
        return True

    kwargs = dict(ingest_alert=ingest, api_key=None, seed=21, now=NOW)
    first = run_simulation("ssh brute force", **kwargs)
    second = run_simulation("ssh brute force", **kwargs)
    assert first["created"] == first["alert_count"] > 0
    assert first["skipped_existing"] == 0
    assert second["created"] == 0 and second["skipped_existing"] == second["alert_count"]


def test_summary_is_consistent():
    res = build_simulation("full attack kill chain with some noise", api_key=None, seed=3, now=NOW)
    s = res.summary()
    assert s["synthetic"] is True
    assert s["alert_count"] == len(res.alerts) == sum(x["alerts"] for x in s["scenarios"])
    assert s["malicious_alerts"] + s["benign_alerts"] == s["alert_count"]
    assert sum(s["by_severity"].values()) == s["alert_count"]
    assert "T1046" in s["mitre_techniques"]
    json.dumps(s)  # the whole summary must be JSON-serialisable for the API response


def test_catalog_lists_every_scenario_type():
    assert {c["type"] for c in catalog()} == {t.value for t in ScenarioType}


def test_is_simulated_external_id():
    assert is_simulated_external_id("sim:0000002a:0001")
    assert not is_simulated_external_id("snort:abc")
    assert not is_simulated_external_id(None)


# ------------------------------------------------------------------ CLI


def test_cli_text_and_json_output(capsys):
    assert cli_main(["ssh brute force", "--offline", "--seed", "1", "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert "[fallback]" in out and "[SIMULATED]" in out

    assert cli_main(["dns tunnel", "--offline", "--seed", "1", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["synthetic"] is True and data["alert_count"] > 0


# ------------------------------------------------------------------ edge cases


def test_scale_counts_shrinks_to_budget_and_never_drops_a_scenario():
    from app.services.simulation.generator import _scale_counts

    assert _scale_counts([3, 4], 10) == [3, 4]  # already fits: unchanged
    shrunk = _scale_counts([1000, 1, 1, 1, 1], 5)
    assert sum(shrunk) == 5 and min(shrunk) >= 1
    # budget smaller than one-per-scenario: floor of 1 each wins, no infinite loop
    assert _scale_counts([50, 50, 50, 50, 50], 3) == [1, 1, 1, 1, 1]


def test_offsets_handles_zero_events():
    import random

    from app.services.simulation.generator import _offsets

    assert _offsets("uniform", 0, 60.0, random.Random(1)) == []


def test_narrative_is_carried_into_raw_data():
    res = generate_alerts(
        plan_of(sp(ScenarioType.PORT_SCAN, narrative="attacker maps the DMZ")), seed=1, now=NOW)
    assert all(a.raw_data["narrative"] == "attacker maps the DMZ" for a in res.alerts)


def test_fallback_understands_quiet_and_distributed_wording():
    plan = fallback_plan("quiet distributed botnet port scan")
    scan = plan.scenarios[0]
    assert scan.type == ScenarioType.PORT_SCAN
    assert scan.intensity == 2
    assert scan.attacker_count == 3


def test_plan_scenarios_must_be_a_list():
    assert SimulationPlan(scenarios="oops").scenarios == []  # type: ignore[arg-type]


@respx.mock
def test_gemini_plan_that_fails_validation_falls_back():
    respx.post(URL).mock(return_value=httpx.Response(200, json=gemini_body(
        {"campaign": "maybe", "scenarios": [{"type": "port_scan"}]})))
    plan = plan_simulation("port scan", api_key=KEY, sleep=no_sleep)
    assert plan.planner == "fallback" and "failed validation" in plan.planner_note


@respx.mock
def test_build_simulation_passes_sleep_through_to_the_retry_loop():
    respx.post(URL).mock(side_effect=[
        httpx.Response(429),
        httpx.Response(200, json=gemini_body({"scenarios": [{"type": "dns_tunneling"}]})),
    ])
    delays: list[float] = []
    res = build_simulation("dns", api_key=KEY, seed=1, now=NOW, sleep=delays.append)
    assert res.plan.planner == "gemini" and delays == [1.5]
