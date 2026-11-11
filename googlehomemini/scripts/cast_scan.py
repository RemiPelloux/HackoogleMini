#!/usr/bin/env python3
"""Discover Cast/Google devices on the LAN and dump their eureka_info.

Usage:
  scripts/cast_scan.py            # mDNS discovery + eureka dump
  scripts/cast_scan.py 192.168.1.12   # probe a specific host
  scripts/cast_scan.py --json     # machine-readable, saved to evidence/

eureka_info is a plain HTTP endpoint the Cast firmware serves unauthenticated on :8008.
It leaks firmware build, Cast protocol revision, setup state, public key, UDN.
"""
import json
import sys
import time
import urllib.request

import zeroconf


def eureka(host, timeout=6):
    url = f"http://{host}:8008/setup/eureka_info?options=detail"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return {"_error": f"{type(e).__name__}: {e}"}


def mdns_discover(timeout=8):
    found = {}

    class Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=4000)
            if not info:
                return
            addrs = [a for a in info.parsed_addresses()]
            txt = {
                k.decode(): v.decode("utf-8", "replace")
                for k, v in (info.properties or {}).items()
            }
            found[name] = {
                "service": type_,
                "addresses": addrs,
                "port": info.port,
                "server": info.server,
                "txt": txt,
            }

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = zeroconf.Zeroconf()
    try:
        zeroconf.ServiceBrowser(zc, "_googlecast._tcp.local.", Listener())
        time.sleep(timeout)
    finally:
        zc.close()
    return found


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = {"mdns": {}, "probes": {}}

    if args:
        hosts = args
    else:
        print("[*] mDNS discovery (8s)...", file=sys.stderr)
        out["mdns"] = mdns_discover()
        hosts = sorted({ip for s in out["mdns"].values() for ip in s["addresses"]})
        print(f"[*] found {len(hosts)} cast host(s): {hosts}", file=sys.stderr)

    for h in hosts:
        out["probes"][h] = eureka(h)

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
