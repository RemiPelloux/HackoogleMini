#!/usr/bin/env python3
"""Scan BLE for Google Home / Nest devices and optionally enumerate GATT.

An unprovisioned Google Home Mini advertises its setup name ("GoogleHomeXXXX")
and the Google service UUID 0xfea0. Enumerating its GATT tree shows which setup
and control characteristics the device exposes pre- and post-provisioning.

Usage:
  scripts/ble_scan.py                  # scan 20s, list Google-ish devices
  scripts/ble_scan.py --all            # list every advertiser
  scripts/ble_scan.py --gatt <ADDR>    # connect and dump services/characteristics
"""
import asyncio
import json
import sys

from bleak import BleakClient, BleakScanner

GOOGLE_NAMES = ("googlehome", "google home", "nest", "chromecast", "googlecast")
GOOGLE_UUIDS = ("fea0", "fe9f", "fef3")


def is_googley(dev, adv):
    name = (dev.name or adv.local_name or "").lower()
    if any(g in name for g in GOOGLE_NAMES):
        return True
    for u in list(adv.service_uuids or []):
        if any(g in u.lower() for g in GOOGLE_UUIDS):
            return True
    return False


async def scan(show_all=False, timeout=20.0):
    rows = []

    def cb(dev, adv):
        if not show_all and not is_googley(dev, adv):
            return
        rows.append(
            {
                "address": dev.address,
                "name": dev.name,
                "local_name": adv.local_name,
                "rssi": adv.rssi,
                "service_uuids": list(adv.service_uuids or []),
                "manufacturer_data": {
                    str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
                },
                "service_data": {k: v.hex() for k, v in (adv.service_data or {}).items()},
                "tx_power": adv.tx_power,
            }
        )

    async with BleakScanner(detection_callback=cb):
        await asyncio.sleep(timeout)
    return rows


async def gatt(address, timeout=20.0):
    async with BleakClient(address, timeout=timeout) as client:
        out = {"address": address, "connected": client.is_connected, "services": []}
        for svc in client.services:
            entry = {
                "uuid": str(svc.uuid),
                "handle": svc.handle,
                "description": svc.description,
                "characteristics": [],
            }
            for ch in svc.characteristics:
                entry["characteristics"].append(
                    {
                        "uuid": str(ch.uuid),
                        "handle": ch.handle,
                        "properties": list(ch.properties),
                        "description": ch.description,
                    }
                )
            out["services"].append(entry)
        return out


async def main():
    argv = sys.argv[1:]
    if "--gatt" in argv:
        addr = argv[argv.index("--gatt") + 1]
        print(json.dumps(await gatt(addr), indent=2))
        return
    rows = await scan(show_all="--all" in argv)
    seen, uniq = set(), []
    for r in sorted(rows, key=lambda x: -x["rssi"]):
        if r["address"] in seen:
            continue
        seen.add(r["address"])
        uniq.append(r)
    print(json.dumps(uniq, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
