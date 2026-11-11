#!/usr/bin/env python3
"""Capture Squid traffic and temporary TLS secrets with reliable cleanup (TLS-6)."""
from __future__ import annotations

import argparse
from datetime import datetime
import re
import signal
import sys
import time

from tls_support import ROOT, compose, current_mode, probe, switch_mode


def keylog_config(content: str) -> None:
    compose("exec", "-T", "squid", "bash", "-c",
            "cat > /etc/squid/tls-keylog.conf; squid -k parse >&2 && squid -k reconfigure", stdin=content)
    time.sleep(0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("seconds", nargs="?", type=int, default=30)
    parser.add_argument("--demo", choices=["http", "splice", "bump", "icap"])
    parser.add_argument("--upstream-tls12", action="store_true",
                        help="temporarily use TLS 1.2 upstream for Squid 6 key-log diagnostics")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.name) or not 1 <= args.seconds <= 3600:
        parser.error("name: 1..64 letters/digits/_/-; seconds: 1..3600")
    directory = ROOT / "captures"
    directory.mkdir(exist_ok=True)
    pcap = directory / (args.name + ".pcap")
    if pcap.exists():
        parser.error(f"capture exists: {pcap}; use a different name")
    if args.demo == "icap" and "icap" not in compose("ps", "--status", "running", "--services").stdout.split():
        raise RuntimeError("THR-4 prerequisite missing: no running ICAP service")
    mode = current_mode()
    original = compose("exec", "-T", "squid", "cat", "/etc/squid/tls-keylog.conf").stdout
    offset = int(compose("exec", "-T", "squid", "bash", "-c",
                         "if [ -f /var/log/squid/tls_keys.log ]; then wc -c < /var/log/squid/tls_keys.log; else echo 0; fi").stdout)
    started = False
    try:
        keylog_config("tls_key_log stdio:/var/log/squid/tls_keys.log\n")
        if args.demo in ("splice", "bump"):
            switch_mode("splice" if args.demo == "splice" else "selective")
        if args.upstream_tls12:
            content = compose("exec", "-T", "squid", "cat", "/etc/squid/conf.d/20-sslbump-common.inc").stdout
            original_option = "tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt"
            if original_option not in content:
                raise RuntimeError("cannot apply TLS 1.2 debug option to the installed TLS template")
            content = content.replace(original_option, original_option + " options=NO_TLSv1_3")
            compose("exec", "-T", "squid", "bash", "-c",
                    "cat > /etc/squid/conf.d/20-sslbump-common.inc; squid -k parse >&2 && squid -k reconfigure", stdin=content)
            time.sleep(0.5)
        compose("--profile", "capture", "up", "-d", "--no-deps", "--force-recreate", "sniffer", timeout=300)
        compose("exec", "-T", "-d", "sniffer", "sh", "-c",
                'umask 077; echo $$ > "/tmp/nt140-$1.pid"; exec tcpdump -U -n -i any -w "/captures/$1.pcap"',
                "sh", args.name)
        started = True
        for _ in range(30):
            if pcap.exists() and pcap.stat().st_size >= 24:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("tcpdump did not create the capture")
        if args.demo:
            scheme = "http" if args.demo in ("http", "icap") else "https"
            url = ("http://downloads.lab.test/files/clean.pdf" if args.demo == "icap"
                   else f"{scheme}://allowed.lab.test/capture/{args.name}/")
            result = probe("alice", url, "capture-" + args.name, keylog=f"/captures/{args.name}.client.keys")
            if result["outcome"] != "ALLOW":
                raise RuntimeError(f"capture demo failed: {result['outcome']}")
        print(f"Capturing {args.seconds}s: {pcap}", flush=True)
        time.sleep(args.seconds)
    finally:
        try:
            if started:
                compose("exec", "-T", "sniffer", "sh", "-c",
                        'kill -INT "$(cat "/tmp/nt140-$1.pid")"', "sh", args.name, check=False)
                time.sleep(0.5)
                decoded = compose("exec", "-T", "sniffer", "tcpdump", "-nn", "-r", f"/captures/{args.name}.pcap", check=False)
                (directory / (args.name + ".txt")).write_text(decoded.stdout + decoded.stderr, encoding="utf-8")
        finally:
            try:
                # Reconfigure closes/flushed buffered key logs before exporting them.
                keylog_config(original)
                keys = compose("exec", "-T", "squid", "bash", "-c",
                               'if [ -f /var/log/squid/tls_keys.log ]; then tail -c "+$1" /var/log/squid/tls_keys.log; fi',
                               "bash", str(offset + 1)).stdout
                if keys:
                    (directory / (args.name + ".squid.keys")).write_text(keys, encoding="ascii")
            finally:
                switch_mode(mode)
    (directory / (args.name + ".md")).write_text(
        f"# Capture {args.name}\n\nCreated: {datetime.now().isoformat()}\n\n"
        f"Demo: {args.demo or 'manual'}; duration: {args.seconds}s; original mode restored: {mode}; temporary upstream TLS 1.2: {args.upstream_tls12}.\n"
        "\nPCAP and real tcpdump summary are adjacent. TLS secrets are in *.keys when available.\n",
        encoding="utf-8")
    print(pcap)
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"capture: {error}", file=sys.stderr)
        sys.exit(1)
