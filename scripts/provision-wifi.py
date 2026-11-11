#!/usr/bin/env python3
"""Provision an unprovisioned Home device onto our own Wi-Fi via its setup API.

This is the step that changes the device's state: it leaves setup/AP mode, joins a
real network, and (importantly) starts talking to Google -- which is exactly the
traffic we want to observe. It also destroys the BLE setup surface, so run
`scripts/ble_dump.py` first if you have not.

Reversing it: hold the device's factory-reset control for ~15 s and it returns to
setup mode.

The POST /setup/connect_wifi payload is the one the Google Home app sends; the
wpa_auth / wpa_cipher values come from the device's own /setup/scan_results.

Usage:
  scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345
  scripts/provision-wifi.py --ssid Livebox-C5C0 --pass '...' --bssid 58:1d:d8:5a:c5:c8
  scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345 --keep   # stay attached
"""
import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def sh(*a, timeout=60):
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def current_wifi():
    for line in sh("nmcli", "-t", "-f", "NAME,TYPE", "con", "show", "--active").splitlines():
        name, _, typ = line.partition(":")
        if typ == "802-11-wireless":
            return name
    return None


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE  # self-signed device certificate
    return c


def api(base, path, payload=None, timeout=20):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx()) as r:
            body = r.read()
            return r.status, (json.loads(body) if body[:1] in (b"{", b"[") else body)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400]
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def join_setup_ap():
    nm = sh("nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi", "list")
    ssid = None
    for line in nm.splitlines():
        s, _, sec = line.rpartition(":")
        if s.lower().startswith(("googlehome", "chromecast", "nest")) and sec in ("", "--"):
            ssid = s
            break
    if not ssid:
        print("!! no open Google setup AP visible; is the Mini unprovisioned?",
              file=sys.stderr)
        return None
    print(f"[*] setup AP: '{ssid}'", file=sys.stderr)
    prof = "gh-prov"
    sh("nmcli", "con", "delete", prof)
    sh("nmcli", "con", "add", "type", "wifi", "con-name", prof, "ssid", ssid,
       "autoconnect", "no")
    sh("nmcli", "con", "modify", prof, "802-11-wireless.hidden", "yes",
       "ipv4.method", "auto", "ipv6.method", "ignore")
    if "successfully activated" not in sh("nmcli", "con", "up", prof, timeout=80):
        print("!! could not join the setup AP", file=sys.stderr)
        return None
    for _ in range(20):
        if sh("ip", "-4", "-o", "addr", "show", "scope", "global").strip():
            break
        time.sleep(1)
    gw = sh("ip", "route").split("via ")[1].split()[0] if "via " in sh("ip", "route") else None
    print(f"[*] attached, gateway={gw}", file=sys.stderr)
    return gw, prof


def restore(prev, prof):
    sh("nmcli", "con", "down", prof)
    sh("nmcli", "con", "delete", prof)
    if prev:
        sh("nmcli", "con", "up", prev, timeout=90)
        print(f"[*] restored {prev}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--pass", dest="password", required=True)
    ap.add_argument("--bssid")
    ap.add_argument("--host")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    prev = current_wifi()
    prof = None
    try:
        host = args.host
        if not host:
            got = join_setup_ap()
            if not got:
                return 2
            host, prof = got
        base = f"https://{host}:8443"

        st, results = api(base, "/setup/scan_results")
        if not isinstance(results, list):
            print(f"!! scan_results failed ({st}): {results}", file=sys.stderr)
            return 3

        # match the device's own view of the target network
        target = None
        for net in results:
            if net.get("ssid") == args.ssid:
                if args.bssid and net.get("bssid", "").lower() != args.bssid.lower():
                    continue
                target = net
                break
        if target is None:
            seen = sorted({n.get("ssid", "?") for n in results})
            print(f"!! '{args.ssid}' not in the device's scan. It sees: {seen}",
                  file=sys.stderr)
            return 4
        print(f"[*] target: {target['ssid']} {target['bssid']} "
              f"freq={target.get('frequency')} wpa_auth={target.get('wpa_auth')} "
              f"wpa_cipher={target.get('wpa_cipher')}", file=sys.stderr)

        # PSK must be RSA-PKCS1v1.5-encrypted with the device's public key
        st_ei, ei = api(base, "/setup/eureka_info")
        if not isinstance(ei, dict):
            print(f"!! could not fetch eureka_info: {ei}", file=sys.stderr)
            return 5
        pub_b64 = ei.get("device_info", {}).get("public_key") or ei.get("public_key")
        if not pub_b64:
            print("!! no public_key in eureka_info — falling back to plaintext 'password'",
                  file=sys.stderr)
            enc_passwd = None
        else:
            try:
                from Cryptodome.PublicKey import RSA
                from Cryptodome.Cipher import PKCS1_v1_5
                key = RSA.import_key(base64.b64decode(pub_b64))
                cipher = PKCS1_v1_5.new(key)
                enc_passwd = base64.b64encode(
                    cipher.encrypt(args.password.encode())).decode()
                print(f"[*] PSK encrypted with device public key (PKCS1v15)", file=sys.stderr)
            except ImportError:
                print("!! pycryptodome not installed — falling back to plaintext 'password'\n"
                      "   pip install pycryptodome", file=sys.stderr)
                enc_passwd = None

        payload = {
            "ssid": target["ssid"],
            "wpa_auth": target.get("wpa_auth", 7),
            "wpa_cipher": target.get("wpa_cipher", 4),
            "bssid": target["bssid"],
        }
        if enc_passwd:
            payload["enc_passwd"] = enc_passwd
        else:
            payload["password"] = args.password
        st, body = api(base, "/setup/connect_wifi", payload, timeout=40)
        print(f"[*] POST /setup/connect_wifi -> {st} {body!s:.200}", file=sys.stderr)

        print("[*] polling setup state ...", file=sys.stderr)
        state = None
        for i in range(30):
            time.sleep(2)
            st, info = api(base, "/setup/eureka_info?options=detail")
            if not isinstance(info, dict):
                print(f"    [{i}] device stopped answering (it is switching networks)")
                break
            state = (info.get("setup_state"), info.get("connected"),
                     info.get("wpa_configured"), info.get("ssid"))
            print(f"    [{i}] setup_state={state[0]} connected={state[1]} "
                  f"wpa_configured={state[2]} ssid={state[3]!r}")
            if info.get("connected") or info.get("wpa_configured"):
                break
        if args.out:
            with open(args.out, "w") as f:
                json.dump({"target": target, "final_state": state,
                           "connect_response": str(body)}, f, indent=2)
        print("\n[*] if wpa_configured=true, the device is on the network now. "
              "Watch the DNS log on the lab AP.", file=sys.stderr)
        return 0
    finally:
        if prof and not args.keep:
            restore(prev, prof)


if __name__ == "__main__":
    sys.exit(main())
