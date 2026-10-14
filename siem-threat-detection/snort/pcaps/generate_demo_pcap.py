#!/usr/bin/env python3
"""Generates snort/pcaps/demo-lab-traffic.pcap — synthetic traffic crafted
to trigger every rule in snort/rules/local.rules at least once, so the
Snort integration (and the SIEM backend's parser) can be exercised
end-to-end without a live network.

Run from snort/pcaps/: python3 generate_demo_pcap.py
"""
from __future__ import annotations

from scapy.all import ICMP, IP, TCP, UDP, Raw, wrpcap

packets = []

ATTACKER = "10.0.0.5"
VICTIM = "10.0.0.10"


def tcp_syn(src, dst, dport, sport=51000):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


# --- SID 1000001: ICMP Test Rule ---
packets.append(IP(src=ATTACKER, dst=VICTIM) / ICMP())

# --- SID 1000002: SSH brute force pattern (3+ SYNs to :22 within 60s) ---
for i in range(4):
    packets.append(tcp_syn(ATTACKER, VICTIM, 22, sport=51010 + i))

# --- SID 1000003: TCP SYN scan on :80 ---
packets.append(tcp_syn(ATTACKER, VICTIM, 80, sport=51234))

# --- SID 1000004: SMB access attempt on :445 ---
packets.append(tcp_syn(ATTACKER, VICTIM, 445, sport=51300))

# --- SID 1000005: Suspicious DNS query volume (UDP/53) ---
packets.append(IP(src=ATTACKER, dst=VICTIM) / UDP(sport=51400, dport=53) / Raw(load=b"\x00" * 12))

# --- SID 1000006: Possible C2 beacon port (:4444) ---
packets.append(tcp_syn(ATTACKER, VICTIM, 4444, sport=51500))

wrpcap("demo-lab-traffic.pcap", packets)
print(f"Wrote {len(packets)} packets to demo-lab-traffic.pcap")
