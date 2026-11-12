# ICAP server: c-icap with the virus_scan service and the clamd engine (spec §7). Owner: THR-4.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends c-icap libc-icap-mod-virus-scan tzdata \
 && rm -rf /var/lib/apt/lists/*

# The packaged c-icap.conf carries the arch-specific ModulesDir/ServicesDir
# (/usr/lib/<triplet>/c_icap), so it is kept and our settings are included at its end.
COPY c-icap.local.conf virus_scan.conf clamd_mod.conf /etc/c-icap/
RUN printf '\n# NT140 lab settings (spec §7)\nInclude c-icap.local.conf\n' >> /etc/c-icap/c-icap.conf
COPY templates/VIRUS_FOUND /usr/share/c_icap/templates/virus_scan/en/VIRUS_FOUND
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1344
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
