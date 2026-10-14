#!/bin/bash
# Entrypoint for the snort container.
#
# Two modes, chosen by SNORT_MODE (default: pcap):
#   pcap  - replays demo-lab-traffic.pcap on a loop against local.rules,
#           writing alert_fast output to /data/snort/log/alert. This is
#           what docker-compose uses by default so the whole stack
#           produces alerts without any real attack traffic or a
#           privileged network interface.
#   live  - runs snort live against $SNORT_INTERFACE (requires
#           NET_ADMIN/NET_RAW capability and a real interface attached
#           to the compose network).
set -euo pipefail

MODE="${SNORT_MODE:-pcap}"
LOG_DIR="${SNORT_LOG_DIR:-/data/snort/log}"
mkdir -p "$LOG_DIR"

if [ "$MODE" = "live" ]; then
    IFACE="${SNORT_INTERFACE:-eth0}"
    echo "Starting snort in LIVE mode on interface $IFACE"
    exec snort -c /etc/snort/snort.conf -i "$IFACE" -l "$LOG_DIR" -A fast -N
fi

echo "Starting snort in PCAP REPLAY mode (SNORT_MODE=pcap)"
PCAP="${SNORT_DEMO_PCAP:-/data/snort/pcaps/demo-lab-traffic.pcap}"

if [ ! -f "$PCAP" ]; then
    echo "Demo pcap not found at $PCAP — copying the bundled default."
    mkdir -p "$(dirname "$PCAP")"
    cp /opt/snort-demo/demo-lab-traffic.pcap "$PCAP"
fi

INTERVAL="${SNORT_REPLAY_INTERVAL_SECONDS:-120}"
echo "Replaying $PCAP every ${INTERVAL}s, appending alert_fast output to $LOG_DIR/alert"
while true; do
    snort -c /etc/snort/snort.conf -r "$PCAP" -l "$LOG_DIR" -A fast -N || true
    sleep "$INTERVAL"
done
