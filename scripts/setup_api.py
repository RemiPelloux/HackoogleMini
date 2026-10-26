#!/usr/bin/env python3
"""Enumerate the local setup API of an unprovisioned Home device (GET only).

Run this while attached to the device's setup AP. Read-only by design: it never
POSTs, so it cannot change device state. The point is to find out exactly what the
setup server exposes before we consider provisioning (which destroys the BLE setup
surface and may trigger a firmware update).

Usage: scripts/setup_api.py --host 192.168.255.249 [--port 8443] [--out file.json]
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

# Endpoints used by the Cast/Home setup server. Mostly undocumented; this list is
# assembled from the eureka setup protocol plus obvious neighbours.
ENDPOINTS = [
    "/setup/eureka_info",
    "/setup/eureka_info?options=detail",
    "/setup/eureka_info?options=detail&params=setup_state,device_info",
    "/eureka_info",
    "/setup/scan_results",
    "/setup/scan_wifi",
    "/setup/supported_timezones",
    "/setup/get_app_device_id",
    "/setup/get_offer",
    "/setup/offer",
    "/setup/network_settings",
    "/setup/check_connectivity",
    "/setup/test_internet_connectivity",
    "/setup/system_time",
    "/setup/bluetooth_status",
    "/setup/get_bluetooth_info",
    "/setup/device_info",
    "/setup/capabilities",
    "/setup/setup_state",
    "/setup/icon.png",
    "/setup/devices",
    "/setup/connected_devices",
    "/setup/get_debug_info",
    "/setup/debug_info",
    "/setup/log",
    "/setup/version",
    "/setup/about",
]


def fetch(base, path, timeout=8):
    req = urllib.request.Request(base + path, method="GET")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # device uses a self-signed certificate
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(65536)
            return {"status": r.status, "len": len(body), "body": body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "len": 0, "body": b""}
    except Exception as e:  # noqa: BLE001
        return {"status": None, "error": f"{type(e).__name__}: {e}", "len": 0,
                "body": b""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--out")
    args = ap.parse_args()

    scheme = "https" if args.port == 8443 else "http"
    base = f"{scheme}://{args.host}:{args.port}"
    print(f"# probing {base} (GET only)")

    report = {"base": base, "endpoints": {}}
    for path in ENDPOINTS:
        r = fetch(base, path)
        entry = {"status": r["status"], "len": r["len"]}
        if r.get("error"):
            entry["error"] = r["error"]
        body = r["body"]
        if body:
            if body[:1] in (b"{", b"["):
                try:
                    entry["json"] = json.loads(body)
                except json.JSONDecodeError:
                    entry["text"] = body[:400].decode("utf-8", "replace")
            elif body[:4] == b"\x89PNG":
                entry["kind"] = "png"
            else:
                entry["text"] = body[:400].decode("utf-8", "replace")
        report["endpoints"][path] = entry

        status = r["status"] if r["status"] is not None else "ERR"
        extra = ""
        if "json" in entry:
            keys = list(entry["json"])[:12] if isinstance(entry["json"], dict) else "list"
            extra = f" keys={keys}"
        elif entry.get("kind"):
            extra = f" {entry['kind']}"
        elif entry.get("text"):
            extra = f" {entry['text'][:90]!r}"
        elif entry.get("error"):
            extra = f" {entry['error']}"
        print(f"  {status:>4}  {entry['len']:>6}B  {path}{extra}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n# saved {args.out}")


if __name__ == "__main__":
    main()
