"""Turn a validated SimulationPlan into synthetic, timestamped alerts.

Everything here is deterministic given (plan, seed, now): the same seed gives
the same alerts, which is what makes the tests exact and lets a demo be
replayed. Nothing in this module touches the network or the database.

Safety properties (all covered by tests):
* Only reserved documentation address ranges are ever used for non-lab IPs
  (RFC 5737 TEST-NET-1/2/3) and example.net for domains, so no real hosts are
  implicated.
* Every signature is prefixed "[SIMULATED]" and every raw_data carries
  ``synthetic: true`` and the run id.
* The total alert count is hard-capped (MAX_TOTAL_ALERTS).
* raw_data is JSON-safe (no datetime objects) -- the Alert.raw_data JSON
  column cannot serialize them (see learnings: Phase 3).
"""

from __future__ import annotations

import ipaddress
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .scenarios import (
    BURST,
    CATALOG,
    INBOUND,
    LAB_HOSTS,
    OUTBOUND,
    PERIODIC,
    USERNAMES,
    ScenarioDef,
)
from .schemas import MAX_TOTAL_ALERTS, ScenarioPlan, SimulationPlan

SIM_PREFIX = "[SIMULATED] "
SIM_EXTERNAL_ID_PREFIX = "sim:"

# RFC 5737 documentation ranges: guaranteed never to be real, routable hosts.
_ATTACKER_NETS = (
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
)
_SERVER_NET = ipaddress.ip_network("192.0.2.0/24")  # TEST-NET-1
LAB_NET = ipaddress.ip_network("10.20.0.0/16")

UTC = timezone.utc


@dataclass
class SyntheticAlert:
    external_id: str
    source: str
    signature: str
    severity: str
    source_ip: str
    source_port: int | None
    dest_ip: str
    dest_port: int | None
    protocol: str
    event_time: datetime
    description: str
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Plain dict for the ingest adapter. event_time stays a datetime."""
        return {
            "external_id": self.external_id,
            "source": self.source,
            "signature": self.signature,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "event_time": self.event_time,
            "description": self.description,
            "raw_data": self.raw_data,
        }


@dataclass
class GenerationResult:
    run_id: str
    seed: int
    window_start: datetime
    window_end: datetime
    alerts: list[SyntheticAlert]
    scenarios: list[dict[str, Any]]


# --------------------------------------------------------------------------- hosts


class _HostAllocator:
    """Hands out attacker/victim/server addresses.

    In campaign mode the same actors are reused across every stage, so the
    correlation engine (which groups by source_ip) sees one coherent story:
    the external attacker hits a victim, and that victim later beacons out.
    Outside campaign mode each scenario gets fresh, distinct actors.
    """

    def __init__(self, rng: random.Random, campaign: bool) -> None:
        self._rng = rng
        self._campaign = campaign
        self._attackers = self._external(_ATTACKER_NETS)
        self._servers = self._external((_SERVER_NET,))
        self._attacker_cursor = 0
        self._server_cursor = 0
        self._shared_hosts = self._shuffled_hosts()
        self._shared_attackers: list[str] | None = None
        self._shared_servers: list[str] | None = None

    def _external(self, nets: tuple[ipaddress.IPv4Network, ...]) -> list[str]:
        ips = [str(h) for net in nets for h in net.hosts()]
        self._rng.shuffle(ips)
        return ips

    def _shuffled_hosts(self) -> list[tuple[str, str]]:
        hosts = list(LAB_HOSTS)
        self._rng.shuffle(hosts)
        return hosts

    def _host_order(self) -> list[tuple[str, str]]:
        return self._shared_hosts if self._campaign else self._shuffled_hosts()

    def attackers(self, n: int) -> list[str]:
        if self._campaign:
            if self._shared_attackers is None:
                self._shared_attackers = self._attackers[:5]
            return self._shared_attackers[:n]
        picked = self._attackers[self._attacker_cursor : self._attacker_cursor + n]
        self._attacker_cursor += n
        return picked

    def servers(self, n: int) -> list[str]:
        if self._campaign:
            if self._shared_servers is None:
                self._shared_servers = self._servers[:5]
            return self._shared_servers[:n]
        picked = self._servers[self._server_cursor : self._server_cursor + n]
        self._server_cursor += n
        return picked

    def internal(self, n: int) -> list[tuple[str, str]]:
        return self._host_order()[:n]

    def internal_excluding(
        self, n: int, exclude: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        return [h for h in self._host_order() if h not in exclude][:n]


# --------------------------------------------------------------------------- helpers


def _scale_counts(counts: list[int], budget: int) -> list[int]:
    """Shrink per-scenario counts proportionally so their sum fits the budget."""
    total = sum(counts)
    if total <= budget:
        return counts
    factor = budget / total
    scaled = [max(1, int(c * factor)) for c in counts]
    while sum(scaled) > budget:
        biggest = max(range(len(scaled)), key=lambda i: scaled[i])
        if scaled[biggest] <= 1:
            break
        scaled[biggest] -= 1
    return scaled


def _offsets(timing: str, n: int, duration_s: float, rng: random.Random) -> list[float]:
    """Seconds-from-window-start for n events, sorted ascending."""
    if n <= 0:
        return []
    if timing == PERIODIC:
        step = duration_s / n
        return [
            min(duration_s, max(0.0, step * (k + 0.5) + rng.uniform(-0.1, 0.1) * step))
            for k in range(n)
        ]
    span = duration_s * 0.25 if timing == BURST else duration_s
    return sorted(rng.uniform(0, span) for _ in range(n))


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _sweep_ports(defn: ScenarioDef, rng: random.Random) -> list[int]:
    extra = rng.sample(range(1, 10000), 30)
    return sorted(set(defn.dest_ports) | set(extra))


_SQLI_URIS = (
    "/products?id=1' OR '1'='1",
    "/search?q=' UNION SELECT NULL,NULL--",
    "/login?user=admin'--",
    "/items?cat=1; SELECT SLEEP(5)--",
)
_MALWARE_FILES = ("update.exe", "svc.ps1", "payload.bin", "installer.msi")


def _details(
    defn: ScenarioDef,
    rng: random.Random,
    *,
    index: int,
    total: int,
    src_name: str | None,
    dst_name: str | None,
    duration_s: float,
) -> dict[str, Any]:
    """Scenario-specific fields stored in raw_data (never used for logic)."""
    kind = defn.type.value
    extra: dict[str, Any] = {}
    if kind in ("ssh_brute_force", "failed_login_spray"):
        extra = {"username": rng.choice(USERNAMES), "auth_result": "failed"}
    elif kind == "web_sql_injection":
        extra = {"uri": rng.choice(_SQLI_URIS), "method": "GET"}
    elif kind == "malware_download":
        fname = rng.choice(_MALWARE_FILES)
        extra = {"filename": fname, "bytes": rng.randint(20_000, 4_000_000)}
    elif kind == "c2_beaconing":
        extra = {
            "beacon_interval_s": round(duration_s / max(total, 1), 1),
            "bytes_out": rng.randint(200, 900),
            "tls_sni": f"cdn-{rng.getrandbits(32):08x}.example.net",
        }
    elif kind == "dns_tunneling":
        label = f"{rng.getrandbits(96):024x}{rng.getrandbits(96):024x}"
        extra = {
            "query": f"{label}.tunnel.example.net",
            "query_length": len(label) + len(".tunnel.example.net"),
            "record_type": "TXT",
        }
    elif kind == "lateral_movement_smb":
        extra = {"share": rng.choice(("ADMIN$", "C$", "IPC$")), "account": "svc-backup"}
    elif kind == "data_exfiltration":
        extra = {"bytes_out": rng.randint(5_000_000, 80_000_000)}
    elif kind == "port_scan":
        extra = {"tcp_flags": "S"}
    elif kind == "benign_web_probe":
        extra = {"user_agent": "ExampleBot/1.0", "uri": rng.choice(("/robots.txt", "/health"))}
    if src_name:
        extra["src_host"] = src_name
    if dst_name:
        extra["dest_host"] = dst_name
    return extra


# --------------------------------------------------------------------------- main


def generate_alerts(
    plan: SimulationPlan,
    *,
    seed: int | None = None,
    now: datetime | None = None,
) -> GenerationResult:
    seed = secrets.randbits(32) if seed is None else int(seed) & 0xFFFFFFFF
    rng = random.Random(seed)
    now = (now or datetime.now(UTC)).astimezone(UTC)
    run_id = f"{seed:08x}"
    hosts = _HostAllocator(rng, plan.campaign)

    scenarios = plan.scenarios
    if not scenarios:
        return GenerationResult(run_id, seed, now, now, [], [])

    # --- windows: sequential (campaign) or all ending now (concurrent) --------
    windows: list[tuple[datetime, datetime]] = []
    if plan.campaign:
        cursor = now - timedelta(minutes=sum(s.duration_minutes for s in scenarios))
        for s in scenarios:
            end = cursor + timedelta(minutes=s.duration_minutes)
            windows.append((cursor, end))
            cursor = end
    else:
        windows = [(now - timedelta(minutes=s.duration_minutes), now) for s in scenarios]

    # --- counts, with a hard total cap ---------------------------------------
    defs = [CATALOG[s.type] for s in scenarios]
    n_actors = [max(1, s.attacker_count) for s in scenarios]
    body_counts = [d.base_count * s.intensity * a for d, s, a in zip(defs, scenarios, n_actors)]
    has_finale = [
        bool(d.finale_signature) and s.intensity >= d.finale_min_intensity
        for d, s in zip(defs, scenarios)
    ]
    body_counts = _scale_counts(body_counts, MAX_TOTAL_ALERTS - sum(has_finale))

    raw: list[tuple[datetime, int, SyntheticAlert]] = []  # (time, scenario idx, alert)

    for si, (s, d) in enumerate(zip(scenarios, defs)):
        start, end = windows[si]
        duration_s = (end - start).total_seconds()
        count = body_counts[si]
        actors = n_actors[si]

        sources, dests = _resolve_endpoints(hosts, s, d, actors)
        sweep = _sweep_ports(d, rng) if d.port_mode == "sweep" else None
        offsets = _offsets(d.timing, count, duration_s, rng)
        mal = d.malicious

        for i, off in enumerate(offsets):
            src_ip, src_name = sources[i % len(sources)]
            dst_ip, dst_name = dests[rng.randrange(len(dests))]
            dport = sweep[i % len(sweep)] if sweep else rng.choice(d.dest_ports)
            when = start + timedelta(seconds=off)
            details = _details(
                d, rng, index=i, total=count, src_name=src_name, dst_name=dst_name,
                duration_s=duration_s,
            )
            sig = rng.choice(d.signatures)
            raw.append(
                (
                    when,
                    si,
                    _make_alert(
                        d, s, run_id, sig, d.severity, src_ip, dst_ip, dport, when, details,
                        _ephemeral_port(rng), malicious=mal,
                    ),
                )
            )

        if has_finale[si]:
            src_ip, src_name = sources[0]
            dst_ip, dst_name = dests[0]
            when = end - timedelta(seconds=rng.uniform(1, 10))
            details = _details(
                d, rng, index=count, total=count, src_name=src_name, dst_name=dst_name,
                duration_s=duration_s,
            )
            if d.type.value == "ssh_brute_force":
                details["auth_result"] = "success"
            details["finale"] = True
            raw.append(
                (
                    when,
                    si,
                    _make_alert(
                        d, s, run_id, d.finale_signature or "", d.finale_severity,
                        src_ip, dst_ip, d.dest_ports[0], when, details,
                        _ephemeral_port(rng), malicious=mal,
                    ),
                )
            )

    raw.sort(key=lambda t: t[0])
    alerts: list[SyntheticAlert] = []
    per_scenario_counts = [0] * len(scenarios)
    for n, (_, si, alert) in enumerate(raw):
        alert.external_id = f"{SIM_EXTERNAL_ID_PREFIX}{run_id}:{n:04d}"
        alerts.append(alert)
        per_scenario_counts[si] += 1

    summary = [
        {
            "type": s.type.value,
            "label": d.label,
            "source": d.source,
            "alerts": per_scenario_counts[i],
            "mitre": list(d.mitre),
            "malicious": d.malicious,
            "window_start": windows[i][0].isoformat(),
            "window_end": windows[i][1].isoformat(),
            "narrative": s.narrative,
        }
        for i, (s, d) in enumerate(zip(scenarios, defs))
    ]
    return GenerationResult(
        run_id=run_id,
        seed=seed,
        window_start=min(w[0] for w in windows),
        window_end=max(w[1] for w in windows),
        alerts=alerts,
        scenarios=summary,
    )


def _resolve_endpoints(
    hosts: _HostAllocator, s: ScenarioPlan, d: ScenarioDef, actors: int
) -> tuple[list[tuple[str, str | None]], list[tuple[str, str | None]]]:
    """Return (sources, destinations) as (ip, hostname-or-None) pairs."""
    n_dst = max(1, s.target_count)
    if d.direction == INBOUND:
        srcs = [(ip, None) for ip in hosts.attackers(actors)]
        dsts = [(ip, name) for name, ip in hosts.internal(n_dst)]
    elif d.direction == OUTBOUND:
        compromised = hosts.internal(actors)
        srcs = [(ip, name) for name, ip in compromised]
        dsts = [(ip, None) for ip in hosts.servers(n_dst)]
    else:  # INTERNAL
        compromised = hosts.internal(actors)
        srcs = [(ip, name) for name, ip in compromised]
        others = hosts.internal_excluding(n_dst, compromised) or hosts.internal(n_dst)
        dsts = [(ip, name) for name, ip in others]
    return srcs, dsts


def _make_alert(
    d: ScenarioDef,
    s: ScenarioPlan,
    run_id: str,
    signature: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    dport: int,
    when: datetime,
    details: dict[str, Any],
    sport: int,
    *,
    malicious: bool,
) -> SyntheticAlert:
    raw_data: dict[str, Any] = {
        "synthetic": True,
        "simulation_run_id": run_id,
        "scenario": d.type.value,
        "scenario_label": d.label,
        "mitre": list(d.mitre),
        "malicious": malicious,
        "event_time": when.isoformat(),  # string, not datetime: JSON column safe
        **details,
    }
    if s.narrative:
        raw_data["narrative"] = s.narrative
    return SyntheticAlert(
        external_id="",  # assigned after global time-sort
        source=d.source,
        signature=f"{SIM_PREFIX}{signature}",
        severity=severity,
        source_ip=src_ip,
        source_port=sport,
        dest_ip=dst_ip,
        dest_port=dport,
        protocol=d.protocol,
        event_time=when,
        description=f"{d.label}: {signature}",
        raw_data=raw_data,
    )
