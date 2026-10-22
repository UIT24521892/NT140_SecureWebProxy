# Squid 6 forward proxy with SslBump support (spec §2.1, §15).
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# squid-openssl: the plain `squid` package is built without SslBump (CLAUDE.md §3).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      squid-openssl apache2-utils gettext-base ca-certificates curl tzdata \
 && rm -rf /var/lib/apt/lists/*

# Keep the fully documented default config for directive lookups (spec §15),
# and drop the distro drop-in so conf.d only holds our ordered files.
RUN mkdir -p /usr/share/doc/nt140 \
 && cp /etc/squid/squid.conf /usr/share/doc/nt140/squid.conf.documented \
 && rm -f /etc/squid/conf.d/*

COPY conf/squid.conf /etc/squid/squid.conf
COPY conf/conf.d/ /etc/squid/conf.d/
COPY templates/ /etc/squid/templates/
COPY errors/ /etc/squid/errors-lab/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 3128
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
