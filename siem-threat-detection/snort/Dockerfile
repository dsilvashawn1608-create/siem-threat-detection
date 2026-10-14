# Snort 2.9.20 (Ubuntu's apt package — there is no Snort 3 apt package on
# Ubuntu 24.04; see backend/app/services/snort_service.py for why that
# matters for the alert format). Runs against a pcap by default so the
# whole stack works without a privileged/live network interface in
# docker-compose; point SNORT_INTERFACE at a real NIC for live capture.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends snort \
    && rm -rf /var/lib/apt/lists/*

# Our lab config/rules replace the stock ones; classification.config and
# reference.config stay as installed by the apt package (snort.conf
# includes them from /etc/snort/).
COPY snort.conf /etc/snort/snort.conf
COPY rules/ /etc/snort/rules/
COPY pcaps/demo-lab-traffic.pcap /opt/snort-demo/demo-lab-traffic.pcap
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /var/log/snort /data/snort/log /data/snort/pcaps

VOLUME ["/data/snort"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
