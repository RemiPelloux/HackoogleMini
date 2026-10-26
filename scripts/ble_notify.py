#!/usr/bin/env python3
"""Collect Google Home BLE setup values that exceed the 512-byte ATT read limit.

Why this exists
---------------
`197c6160`, `1a7c6160` and `1b7c6160` are gzipped payloads larger than the 512-byte
ATT long-read ceiling. A plain read returns a truncated gzip stream
(`Compressed file ended before the end-of-stream marker was reached`). The
notify-capable characteristics are the escape hatch: the device streams the full
value as GATT notifications.

Implementation notes
--------------------
BlueZ is used directly over D-Bus instead of bleak, because bleak's BlueZ backend
fails with `BleakDeviceNotFoundError` while bluetoothctl is still mid-discovery for
this device (the object comes and goes from the object tree as it connects). The
connection itself is still driven through bluetoothctl, which handles the retry /
stale-link cases well.

A connected BLE device stops advertising, and this Mini rotates its
resolvable-private address, so any stale link must be dropped before discovery.

Writes are opt-in (`--trigger`) because the setup protocol is only partly
reconstructed: an unknown command may reset the device into setup mode (harmless
while unprovisioned, disruptive otherwise).

Usage
-----
  scripts/ble_notify.py                            # subscribe, listen 20s
  scripts/ble_notify.py --seconds 40
  scripts/ble_notify.py --trigger 1a6c6160:00      # OPT-IN write before listening
  scripts/ble_notify.py --read-after               # re-read the chars after listening
"""
import argparse
import asyncio
import gzip
import json
import re
import subprocess
import sys
import time

from dbus_next import BusType, Variant
from dbus_next.aio import MessageBus

BLUEZ = "org.bluez"
NAME_PREFIXES = ("googlehome", "nest-", "chromecast")
GOOGLE_SVC = "fea0"
NOTIFY_SHORTS = ["0c7c6160", "157c6160", "197c6160", "1a7c6160", "1b7c6160"]


def sh(*args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def google_addresses():
    out = []
    for line in sh("bluetoothctl", "devices").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[2].lower().startswith(NAME_PREFIXES):
            out.append(parts[1])
    return out


def drop_live_links():
    """Disconnect Google-ish devices BlueZ still holds a link to.

    A connected device stops advertising, so a stale link makes every later scan
    look like the device vanished. BlueZ also reports Connected: yes on dead handles.
    """
    dropped = False
    for addr in google_addresses():
        info = sh("bluetoothctl", "info", addr)
        if "Connected: yes" in info:
            print(f"[*] dropping live link {addr}", file=sys.stderr)
            sh("bluetoothctl", "disconnect", addr, timeout=25)
            dropped = True
    return dropped


def discover(timeout=25):
    """Return (address, name) of a Google advertiser, or (None, None).

    `bluetoothctl --timeout N scan on` prints ANSI-coloured lines like
    `[NEW] Device 73:5F:A9:7F:67:36 GoogleHome4983`; parse that shape directly and
    fall back to BlueZ's cached device list, which keeps the name across scans.
    """
    out = sh("bluetoothctl", "--timeout", str(timeout), "scan", "on",
             timeout=timeout + 15)
    for raw in out.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw).strip()
        m = re.match(r"\[(?:NEW|CHG)\]\s+Device\s+([0-9A-Fa-f:]{17})\s*(.*)$", line)
        if not m:
            continue
        addr, name = m.group(1), (m.group(2) or "").strip()
        if name.lower().startswith(NAME_PREFIXES):
            return addr, name
    # fall back to the BlueZ cache: a device seen once keeps its name
    cached = google_addresses()
    if cached:
        return cached[0], "(cached)"
    return None, None


async def find_chars(bus, address):
    """Map short uuid -> object path for the connected device's characteristics.

    ObjectManager lives on `/`, not on the device path (BlueZ exposes the whole tree
    from the root), so introspecting the device path yields no ObjectManager.
    """
    dev_path = "/org/bluez/hci0/dev_" + address.replace(":", "_")
    root = await bus.introspect(BLUEZ, "/")
    om = bus.get_proxy_object(BLUEZ, "/", root).get_interface(
        "org.freedesktop.DBus.ObjectManager")
    managed = await om.call_get_managed_objects()
    chars = {}
    base = dev_path + "/"
    for path, ifaces in managed.items():
        if not path.startswith(base):
            continue
        ch = ifaces.get("org.bluez.GattCharacteristic1")
        if not ch:
            continue
        chars[ch["UUID"].value.lower()] = path
    return chars


async def read_offsets(bus, path, limit=8192):
    """ATT long read, walking the offset until a short chunk or an error."""
    intro = await bus.introspect(BLUEZ, path)
    obj = bus.get_proxy_object(BLUEZ, path, intro)
    iface = obj.get_interface("org.bluez.GattCharacteristic1")
    buf = bytearray()
    while len(buf) < limit:
        try:
            chunk = await iface.call_read_value({"offset": Variant("q", len(buf))})
            data = bytes(chunk)
        except Exception:  # noqa: BLE001
            break
        if not data:
            break
        buf.extend(data)
        if len(data) < 20:
            break
    return bytes(buf)


async def collect(args):
    if drop_live_links():
        await asyncio.sleep(8)

    address = name = None
    for _ in range(3):
        address, name = discover()
        if address:
            break
        await asyncio.sleep(5)
    if not address:
        print("!! no Google Home advertiser in range.\n"
              "   The Mini stops advertising while connected, and can also go quiet\n"
              "   after repeated connection attempts. Unplug/replug it, wait ~20s,\n"
              "   then retry.", file=sys.stderr)
        return 2
    print(f"[*] {name} @ {address}", file=sys.stderr)

    print("[*] connecting via bluetoothctl ...", file=sys.stderr)
    sh("bluetoothctl", "connect", address, timeout=45)
    await asyncio.sleep(4)

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        chars = await find_chars(bus, address)
    except Exception as e:  # noqa: BLE001
        print(f"!! cannot reach {address} on D-Bus: {e}", file=sys.stderr)
        return 3
    print(f"[*] {len(chars)} characteristics", file=sys.stderr)

    want = {s: p for u, p in chars.items() if u.startswith(tuple(NOTIFY_SHORTS))
            for s in NOTIFY_SHORTS if u.startswith(s)}
    if not want:
        print("!! none of the expected characteristics are present", file=sys.stderr)
        return 4

    # canary: device name must be readable and non-trivial, else the link is stale
    name_path = chars.get("00002a00-0000-1000-8000-00805f9b34fb")
    if name_path:
        canary = await read_offsets(bus, name_path, 64)
        if len(canary) < 8:
            print(f"!! canary read returned {len(canary)}B; link is stale. "
                  "Power-cycle the Mini and retry.", file=sys.stderr)
            return 5
        print(f"[*] canary ok: {canary.decode(errors='replace')}", file=sys.stderr)

    result = {"collected": time.strftime("%Y-%m-%dT%H:%M:%S"),
              "address": address, "advertised_name": name, "streams": {}}

    bufs = {p: bytearray() for p in want.values()}

    for short, path in want.items():
        intro = await bus.introspect(BLUEZ, path)
        obj = bus.get_proxy_object(BLUEZ, path, intro)
        props = obj.get_interface("org.freedesktop.DBus.Properties")

        def make_handler(p):
            # dbus-next validates the handler's arity against the signal
            # signature (s a{sv} as), so the path must come from the closure.
            def on_change(_iface, changed, _invalidated):
                v = changed.get("Value")
                if v is not None:
                    bufs[p].extend(bytes(v.value))
            return on_change

        try:
            props.on_properties_changed(make_handler(path))
        except AttributeError:
            print("[-] no PropertiesChanged signal on", short, file=sys.stderr)
        try:
            gatt = obj.get_interface("org.bluez.GattCharacteristic1")
            await gatt.call_start_notify()
            print(f"[+] notify on {short}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[-] notify failed {short}: {e}", file=sys.stderr)

    if args.trigger:
        short, _, hx = args.trigger.partition(":")
        path = next((p for u, p in chars.items() if u.startswith(short.lower())), None)
        if path is None:
            print(f"!! no characteristic matching {short}", file=sys.stderr)
        else:
            payload = bytes.fromhex(hx)
            intro = await bus.introspect(BLUEZ, path)
            obj = bus.get_proxy_object(BLUEZ, path, intro)
            gatt = obj.get_interface("org.bluez.GattCharacteristic1")
            await gatt.call_write_value(payload, {})
            print(f"[*] trigger wrote {payload.hex()} to {short}", file=sys.stderr)

    print(f"[*] listening {args.seconds:.0f}s ...", file=sys.stderr)
    await asyncio.sleep(args.seconds)

    for short, path in want.items():
        data = bytes(bufs[path])
        if not data:
            continue
        entry = {"len": len(data), "hex": data.hex()}
        if data[:2] == b"\x1f\x8b":
            try:
                entry["gunzip"] = gzip.decompress(data).decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                entry["gunzip_error"] = str(e)
        result["streams"][short] = entry
        print(f"[=] {short} {len(data)}B", file=sys.stderr)
        print("    " + entry.get("gunzip", entry.get("gunzip_error", ""))[:400],
              file=sys.stderr)

    if args.read_after:
        for short in NOTIFY_SHORTS:
            path = next((p for u, p in chars.items() if u.startswith(short)), None)
            if path:
                data = await read_offsets(bus, path)
                if data:
                    result["streams"].setdefault(short, {}).update(
                        {"read_after_len": len(data)})

    print(json.dumps(result, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--trigger", help="<short-uuid>:<hex> write before listening")
    ap.add_argument("--read-after", action="store_true")
    sys.exit(asyncio.run(collect(ap.parse_args())))


if __name__ == "__main__":
    main()
