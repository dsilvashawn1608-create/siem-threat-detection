"""Scenario catalog: what each simulated attack looks like to the SIEM.

Each ScenarioDef is declarative. generator.py turns it into timestamped alerts.
Signatures are deliberately generic ("Possible TCP SYN port scan") rather than
copies of real vendor rule names/IDs, and every generated alert is prefixed
"[SIMULATED]" so nothing synthetic can be mistaken for a real detection.

MITRE ATT&CK technique IDs are attached so the dashboard can show what each
scenario exercises.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schemas import ScenarioType

# direction: who is the alert's source_ip?
#   inbound  -> external attacker -> internal target
#   outbound -> compromised internal host -> external server
#   internal -> compromised internal host -> another internal host
INBOUND = "inbound"
OUTBOUND = "outbound"
INTERNAL = "internal"

# timing: how events are spread over the scenario window
UNIFORM = "uniform"
PERIODIC = "periodic"  # regular interval with jitter (beaconing)
BURST = "burst"  # packed into the first ~25% of the window (scans, sprays)


@dataclass(frozen=True)
class ScenarioDef:
    type: ScenarioType
    label: str
    source: str  # "SNORT" (network) or "SPLUNK" (log/event)
    direction: str
    timing: str
    base_count: int  # alerts at intensity 1, per attacker
    signatures: tuple[str, ...]
    severity: str  # low | medium | high | critical
    protocol: str
    dest_ports: tuple[int, ...]
    mitre: tuple[str, ...]
    malicious: bool = True
    port_mode: str = "fixed"  # fixed | sweep
    finale_signature: str | None = None
    finale_severity: str = "critical"
    finale_min_intensity: int = 4
    description: str = ""


CATALOG: dict[ScenarioType, ScenarioDef] = {
    ScenarioType.PORT_SCAN: ScenarioDef(
        type=ScenarioType.PORT_SCAN,
        label="Port scan",
        source="SNORT",
        direction=INBOUND,
        timing=BURST,
        base_count=6,
        signatures=("Possible TCP SYN port scan", "Sequential port probe from single host"),
        severity="medium",
        protocol="TCP",
        dest_ports=(21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080),
        mitre=("T1046",),
        port_mode="sweep",
        description="Reconnaissance sweep across many destination ports.",
    ),
    ScenarioType.SSH_BRUTE_FORCE: ScenarioDef(
        type=ScenarioType.SSH_BRUTE_FORCE,
        label="SSH brute force",
        source="SPLUNK",
        direction=INBOUND,
        timing=BURST,
        base_count=8,
        signatures=("Repeated failed SSH authentication",),
        severity="high",
        protocol="TCP",
        dest_ports=(22,),
        mitre=("T1110.001",),
        finale_signature="Successful SSH login after repeated failures",
        finale_severity="critical",
        description="Many failed SSH logins; at high intensity one eventually succeeds.",
    ),
    ScenarioType.FAILED_LOGIN_SPRAY: ScenarioDef(
        type=ScenarioType.FAILED_LOGIN_SPRAY,
        label="Password spray",
        source="SPLUNK",
        direction=INBOUND,
        timing=UNIFORM,
        base_count=6,
        signatures=("Failed logins across many accounts from one source",),
        severity="medium",
        protocol="TCP",
        dest_ports=(443, 3389, 445),
        mitre=("T1110.003",),
        description="Low-and-slow failed logins across many usernames.",
    ),
    ScenarioType.WEB_SQL_INJECTION: ScenarioDef(
        type=ScenarioType.WEB_SQL_INJECTION,
        label="Web SQL injection",
        source="SNORT",
        direction=INBOUND,
        timing=UNIFORM,
        base_count=4,
        signatures=(
            "Possible SQL injection attempt in HTTP request",
            "SQL keyword in HTTP query string",
        ),
        severity="high",
        protocol="TCP",
        dest_ports=(80, 443, 8080),
        mitre=("T1190",),
        description="Injection attempts against a public-facing web application.",
    ),
    ScenarioType.MALWARE_DOWNLOAD: ScenarioDef(
        type=ScenarioType.MALWARE_DOWNLOAD,
        label="Malware download",
        source="SNORT",
        direction=OUTBOUND,
        timing=UNIFORM,
        base_count=2,
        signatures=(
            "Executable download from untrusted host",
            "Suspicious script fetched over HTTP",
        ),
        severity="high",
        protocol="TCP",
        dest_ports=(80, 443, 8080),
        mitre=("T1105",),
        description="Internal host pulls a tool/payload from an external server.",
    ),
    ScenarioType.C2_BEACONING: ScenarioDef(
        type=ScenarioType.C2_BEACONING,
        label="C2 beaconing",
        source="SNORT",
        direction=OUTBOUND,
        timing=PERIODIC,
        base_count=6,
        signatures=("Periodic outbound HTTPS beacon to rare destination",),
        severity="high",
        protocol="TCP",
        dest_ports=(443, 8443),
        mitre=("T1071.001",),
        description="Regular, low-volume check-ins to a command-and-control server.",
    ),
    ScenarioType.LATERAL_MOVEMENT_SMB: ScenarioDef(
        type=ScenarioType.LATERAL_MOVEMENT_SMB,
        label="Lateral movement (SMB)",
        source="SPLUNK",
        direction=INTERNAL,
        timing=UNIFORM,
        base_count=4,
        signatures=(
            "Admin share access from workstation to multiple hosts",
            "Remote service creation over SMB",
        ),
        severity="high",
        protocol="TCP",
        dest_ports=(445, 135),
        mitre=("T1021.002",),
        description="A compromised host reaching into other internal hosts.",
    ),
    ScenarioType.DNS_TUNNELING: ScenarioDef(
        type=ScenarioType.DNS_TUNNELING,
        label="DNS tunneling",
        source="SNORT",
        direction=OUTBOUND,
        timing=PERIODIC,
        base_count=8,
        signatures=("Unusually long / high-entropy DNS queries to one domain",),
        severity="medium",
        protocol="UDP",
        dest_ports=(53,),
        mitre=("T1071.004",),
        description="Data smuggled in DNS queries to an attacker-controlled domain.",
    ),
    ScenarioType.DATA_EXFILTRATION: ScenarioDef(
        type=ScenarioType.DATA_EXFILTRATION,
        label="Data exfiltration",
        source="SPLUNK",
        direction=OUTBOUND,
        timing=UNIFORM,
        base_count=3,
        signatures=("Large outbound transfer to external host",),
        severity="high",
        protocol="TCP",
        dest_ports=(443, 21, 22),
        mitre=("T1041",),
        finale_signature="Cumulative outbound volume exceeds baseline",
        finale_severity="critical",
        finale_min_intensity=3,
        description="Bulk data leaving the network to an external endpoint.",
    ),
    ScenarioType.BENIGN_WEB_PROBE: ScenarioDef(
        type=ScenarioType.BENIGN_WEB_PROBE,
        label="Benign web probe",
        source="SNORT",
        direction=INBOUND,
        timing=UNIFORM,
        base_count=3,
        signatures=("Web crawler requesting robots.txt", "Health-check style HTTP request"),
        severity="low",
        protocol="TCP",
        dest_ports=(80, 443),
        mitre=(),
        malicious=False,
        description="Harmless noise, useful for testing false-positive handling.",
    ),
}

# Plausible usernames for log-style scenarios (stored in raw_data only).
USERNAMES = (
    "root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "pi",
    "ftpuser", "support", "jenkins", "deploy", "backup", "guest", "user",
)

# Internal lab hosts: (hostname, ip last two octets under 10.20.0.0/16).
LAB_HOSTS = (
    ("web01", "10.20.1.10"),
    ("web02", "10.20.1.11"),
    ("db01", "10.20.2.20"),
    ("app01", "10.20.2.30"),
    ("file01", "10.20.3.40"),
    ("ws-fin-07", "10.20.4.107"),
    ("ws-dev-12", "10.20.4.112"),
    ("jump01", "10.20.5.5"),
)

# Example campaigns, usable as presets and as the keyword fallback's building blocks.
KILL_CHAIN: tuple[ScenarioType, ...] = (
    ScenarioType.PORT_SCAN,
    ScenarioType.SSH_BRUTE_FORCE,
    ScenarioType.MALWARE_DOWNLOAD,
    ScenarioType.C2_BEACONING,
    ScenarioType.DATA_EXFILTRATION,
)
