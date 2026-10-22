# Lab client: client-staff (MANAGED=1) and client-guest (MANAGED=0) (spec §9). Owner: TLS-2.
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl openssl ca-certificates python3 dnsutils iproute2 iputils-ping netcat-openbsd tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
