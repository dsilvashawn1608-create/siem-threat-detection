"""Try the simulator without the rest of the app.

    cd backend
    python -m app.services.simulation "ransomware attack, heavy"            # offline
    GEMINI_API_KEY=... python -m app.services.simulation "slow APT intrusion"  # Gemini
    python -m app.services.simulation "ssh brute force" --json --seed 7
"""

import argparse
import json
import os
import sys

from .service import build_simulation


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.services.simulation")
    ap.add_argument("prompt", help="natural-language request")
    ap.add_argument("--offline", action="store_true", help="skip Gemini, use keyword planner")
    ap.add_argument("--seed", type=int, default=None, help="reproducible output")
    ap.add_argument("--json", action="store_true", help="print the full summary as JSON")
    ap.add_argument("--limit", type=int, default=12, help="alerts to print (default 12)")
    args = ap.parse_args(argv)

    key = None if args.offline else os.environ.get("GEMINI_API_KEY")
    result = build_simulation(args.prompt, api_key=key, seed=args.seed)
    summary = result.summary()
    if args.json:
        json.dump(summary, sys.stdout, indent=2)
        print()
        return 0

    print(f"{summary['title']}  [{summary['planner']}]  run={summary['run_id']}")
    if summary["planner_note"]:
        print(f"  note: {summary['planner_note']}")
    print(f"  {summary['alert_count']} synthetic alerts  "
          f"({summary['malicious_alerts']} malicious / {summary['benign_alerts']} benign)  "
          f"MITRE: {', '.join(summary['mitre_techniques']) or '-'}")
    for s in summary["scenarios"]:
        print(f"  - {s['label']:<24} {s['alerts']:>3} alerts  {s['source']}")
    print()
    for a in result.alerts[: args.limit]:
        print(f"{a.event_time:%H:%M:%S} {a.severity:<8} {a.source_ip:>15}:{a.source_port} -> "
              f"{a.dest_ip}:{a.dest_port}  {a.signature}")
    if len(result.alerts) > args.limit:
        print(f"... {len(result.alerts) - args.limit} more")
    return 0


if __name__ == "__main__":  # pragma: no cover (entry-point guard)
    raise SystemExit(main())
