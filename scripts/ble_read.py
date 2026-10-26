#!/usr/bin/env python3
"""Dump every readable characteristic of a Google Home BLE setup service.

The 0xfea0 service is Google's "Setup" service. On an unprovisioned Home Mini it
is fully readable/writable over an unencrypted link, which is how the Google Home
app provisions the device. This script records exactly what the device will hand
out, so we can identify model / firmware and reconstruct the setup protocol.

Usage: scripts/ble_read.py <ADDRESS> [--write uuid:hex --write uuid:hex]
"""
import asyncio
import json
import sys

from bleak import BleakClient

# Characteristic short IDs seen on the Home Mini setup service (base 0x????6160-fab2-11e4-9fbb-0002a5d5c51b)
NAMED = {
    "00002a00-0000-1000-8000-00805f9b34fb": "device_name",
    "00002a01-0000-1000-8000-00805f9b34fb": "appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "ppcp",
    "00002a05-0000-1000-8000-00805f9b34fb": "service_changed",
}


def hexdump(b: bytes) -> str:
    return b.hex()


async def main():
    addr = sys.argv[1]
    writes = []
    argv = sys.argv[2:]
    for i, a in enumerate(argv):
        if a == "--write":
            writes.append(argv[i + 1])

    out = {"address": addr, "readable": {}, "errors": {}, "writes": []}

    async with BleakClient(addr, timeout=30) as client:
        chars = []
        for svc in client.services:
            for ch in svc.characteristics:
                chars.append((str(svc.uuid), ch))

        for svc_uuid, ch in chars:
            props = list(ch.properties)
            if "read" not in props:
                continue
            key = NAMED.get(str(ch.uuid).lower(), str(ch.uuid))
            try:
                val = await client.read_gatt_char(ch)
                entry = {"service": svc_uuid, "handle": ch.handle, "hex": hexdump(val)}
                try:
                    txt = val.decode("utf-8")
                    if txt.isprintable():
                        entry["ascii"] = txt
                except Exception:  # noqa: BLE001
                    pass
                out["readable"][key] = entry
                print(f"[read] {key:42s} {entry['hex']}"
                      + (f"  '{entry['ascii']}'" if "ascii" in entry else ""))
            except Exception as e:  # noqa: BLE001
                out["errors"][key] = f"{type(e).__name__}: {e}"
                print(f"[fail] {key:42s} {type(e).__name__}: {e}")

        for w in writes:
            uuid, _, hx = w.partition(":")
            target = next((c for _, c in chars if str(c.uuid).startswith(uuid.lower())),
                          None)
            if target is None:
                print(f"[skip] no char {uuid}")
                continue
            try:
                await client.write_gatt_char(target, bytes.fromhex(hx), response=True)
                out["writes"].append({"uuid": uuid, "hex": hx, "ok": True})
                print(f"[write] {uuid} <- {hx} OK")
            except Exception as e:  # noqa: BLE001
                out["writes"].append({"uuid": uuid, "hex": hx, "ok": False, "err": str(e)})
                print(f"[write] {uuid} <- {hx} {type(e).__name__}: {e}")

    print("\n----- JSON -----")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
