#!/usr/bin/env python3
"""Dump the full Google Home BLE setup surface (0xfea0) to JSON, robustly.

Hard-won details baked in:
  * the Mini advertises a ROTATING random BLE address -> resolve by name every run;
  * BlueZ often reports `Connected: yes` on a stale handle and then every
    ReadValue returns an empty array -> verify with a canary read (device name,
    which is always 14 bytes) and force reconnect until the canary passes;
  * values larger than the ATT MTU need offset reads (ReadValue {offset}).

Usage: scripts/ble_dump.py [--out FILE]
"""
import asyncio
import gzip
import json
import subprocess
import sys
import time

NAME_PREFIXES = ("googlehome", "nest-", "chromecast")
CANARY_UUID = "00002a00-0000-1000-8000-00805f9b34fb"
CANARY_MIN = 8


def sh(*cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def disconnect_google_homes():
    """A connected device stops advertising, so we cannot rediscover its rotating
    address while an old link is still up. Drop any GoogleHome* link first."""
    out = sh("bluetoothctl", "devices", timeout=15).stdout
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        _kw, addr, name = parts
        if not name.lower().startswith(NAME_PREFIXES):
            continue
        info = sh("bluetoothctl", "info", addr, timeout=15).stdout
        if "Connected: yes" in info:
            print(f"[*] disconnecting stale link to {name} @ {addr}", file=sys.stderr)
            sh("bluetoothctl", "disconnect", addr, timeout=20)
            time.sleep(2)


def resolve_address(timeout=15.0):
    """Find the Mini's current (rotating) BLE address by advertised name/service."""
    from bleak import BleakScanner

    async def go():
        return await BleakScanner.discover(timeout=timeout, return_adv=True)

    found = {}
    for addr, (dev, adv) in asyncio.run(go()).items():
        nm = dev.name or adv.local_name or ""
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if nm.lower().startswith(NAME_PREFIXES) or any("fea0" in u for u in uuids):
            found[addr] = (nm, adv.rssi)

    if not found:
        return None, None
    addr, (name, _rssi) = max(found.items(), key=lambda kv: kv[1][1])
    return addr, name


def prop(path, name):
    r = sh("busctl", "--system", "get-property", "org.bluez", path,
           "org.bluez.GattCharacteristic1", name)
    if r.returncode != 0:
        return None
    v = r.stdout.strip()
    return v[3:-1] if v.startswith('s "') else v


def read_value(path, offset=0):
    """One ATT read at `offset`.

    busctl prints the `ay` as `ay <count> <count byte values in DECIMAL>`.
    (Decimal, not hex -- parsing it as hex silently corrupts every value.)
    """
    r = sh("busctl", "--system", "call", "org.bluez", path,
           "org.bluez.GattCharacteristic1", "ReadValue", "a{sv}", "1",
           "offset", "q", str(offset), timeout=12)
    if r.returncode != 0:
        return None, r.stderr.strip()
    parts = r.stdout.strip().split()
    if len(parts) < 2 or parts[0] != "ay":
        return b"", None
    n = int(parts[1])
    try:
        return bytes(int(p, 10) for p in parts[2:2 + n]), None
    except ValueError:
        return b"", None


def long_read(path, limit=1 << 20):
    out, off, errs = b"", 0, []
    while off < limit:
        chunk, err = read_value(path, off)
        if chunk is None:
            errs.append(err)
            break
        if not chunk:
            break
        out += chunk
        off = len(out)
        if len(chunk) < 20:      # short tail read == end of value
            break
    return out, errs


def char_paths(addr):
    dev = f"/org/bluez/hci0/dev_{addr.replace(':', '_')}"
    tree = sh("busctl", "--system", "tree", "org.bluez").stdout
    return sorted({ln.strip(" │├─└") for ln in tree.splitlines()
                   if dev in ln and "/char" in ln}), dev


def link_ok(addr):
    paths, _ = char_paths(addr)
    for p in paths:
        if prop(p, "UUID") == CANARY_UUID:
            data, _ = read_value(p, 0)
            return data is not None and len(data) >= CANARY_MIN
    return False


def bring_up(addr, attempts=3):
    for i in range(attempts):
        sh("bluetoothctl", "disconnect", addr, timeout=20)
        time.sleep(2)
        sh("bluetoothctl", "connect", addr, timeout=40)
        time.sleep(3)
        if link_ok(addr):
            print(f"[*] link verified on attempt {i + 1}", file=sys.stderr)
            return True
        print(f"[!] stale link after attempt {i + 1}, retrying", file=sys.stderr)
    return False


def main():
    out_file = None
    if "--out" in sys.argv:
        out_file = sys.argv[sys.argv.index("--out") + 1]

    addr, name = resolve_address()
    if not addr:
        disconnect_google_homes()
        addr, name = resolve_address()
    if not addr:
        print("!! no Google Home advertiser in range", file=sys.stderr)
        sys.exit(2)
    print(f"[*] target {name} @ {addr}", file=sys.stderr)

    if not bring_up(addr):
        print("!! could not establish a usable GATT link", file=sys.stderr)
        sys.exit(3)

    paths, dev = char_paths(addr)
    result = {"address": addr, "advertised_name": name, "collected": time.strftime(
        "%Y-%m-%dT%H:%M:%S"), "characteristics": {}}

    for p in paths:
        uuid = prop(p, "UUID")
        flags = prop(p, "Flags") or ""
        entry = {"handle_ref": p.rsplit("/", 1)[-1], "uuid": uuid, "flags": flags}
        if uuid and "read" in flags:
            data, errs = long_read(p)
            entry["len"] = len(data)
            entry["hex"] = data.hex()
            if errs:
                entry["read_errors"] = errs
            if data[:2] == b"\x1f\x8b":
                try:
                    entry["gunzip"] = gzip.decompress(data).decode("utf-8", "replace")
                except Exception as e:  # noqa: BLE001
                    entry["gunzip_error"] = str(e)
        result["characteristics"][uuid or p] = entry
        print(f"[{uuid}] {entry.get('len', '-')}B {flags}", file=sys.stderr)
        time.sleep(0.1)

    blob = json.dumps(result, indent=2)
    if out_file:
        with open(out_file, "w") as fh:
            fh.write(blob)
        print(f"[*] wrote {out_file} ({len(blob)}B)", file=sys.stderr)
    else:
        print(blob)


if __name__ == "__main__":
    main()
