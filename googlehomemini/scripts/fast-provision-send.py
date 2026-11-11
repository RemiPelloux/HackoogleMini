#!/usr/bin/env python3
"""Send connect_wifi to the Mini using pre-computed payload.
Assumes caller has already configured the network interface to reach 192.168.255.249.

Pre-computed payload uses:
  - public_key from evidence (known, no need to fetch from device)
  - Livebox-C5C0 parameters from last scan (ssid, bssid, wpa_auth, wpa_cipher)
  - PSK: &PI_0123456789=

Usage:
  python3 fast-provision-send.py [--host 192.168.255.249]
"""
import json, ssl, sys, urllib.request

# Pre-computed from device public key (RSA-PKCS1v1.5 of "&PI_0123456789=")
PAYLOAD = {
    "ssid": "Livebox-C5C0",
    "wpa_auth": 4,
    "wpa_cipher": 4,
    "bssid": "58:1d:d8:5a:c5:c8",
    "enc_passwd": "GokQ1oZ6ktxPSlT5QZfv58M3/hqIHV2uzCakIzrA0C/ZB7AlU+wQCpHshXWLjBNlcV6lX67nPqx8BcnoLtEzHzHaHnSCKLe4Z4uax2xjzWCiK9zGqEBJlO/0xcTylfEbqD5pTvOO8GOEGUjtk8a2x4BMxXt+yxsAg7I0CsKVade+pfW2xH2G7HCBaZnDNixoinLDEABpxyou6ixRBsONQ1cmh/nk+rwRAjG4EJ9Wo081c4E5HfC/dyDeBYKaFXT4ebW2QutD4RFh+uJxuTDZq/cyDyLXa5Oc4kvvOA8wOXpB238ccouTvIiCuLU4Cpoh/BAHbnFTTQ29Ksb7jRTPYQ=="
}

host = sys.argv[1] if len(sys.argv) > 1 else "192.168.255.249"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

body = json.dumps(PAYLOAD).encode()
req = urllib.request.Request(
    f"https://{host}:8443/setup/connect_wifi",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST"
)

print(f"[*] POST /setup/connect_wifi → {host}", flush=True)
try:
    r = urllib.request.urlopen(req, timeout=8, context=ctx)
    print(f"[+] {r.status} '{r.read()}'", flush=True)
except urllib.error.URLError as e:
    print(f"[!] {e}", flush=True)
    sys.exit(1)
