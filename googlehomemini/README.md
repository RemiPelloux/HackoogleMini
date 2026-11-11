# googlehomemini

Reverse-engineering workspace for replacing the Google Assistant agent on a **Google
Home Mini** with a local LLM that can call arbitrary **MCP** servers.

Read in this order:

1. **`notes/ondevice-plan.md`** — can this device run our code, what to replace, and
   what the device already speaks. **The strategic answer is here.**
2. **`notes/findings.md`** — what was actually observed, with evidence links.
3. **`notes/architecture.md`** — what "replace the agent" means and the realistic
   options, with the latency budget.
4. **`notes/firmware-plan.md`** — how to get firmware and what to analyse in it.

## Status

| Area | State |
| --- | --- |
| Device discovered | ✅ `GoogleHome4983`, BLE + **open setup AP**, unprovisioned |
| Device identity | ✅ **`product_name: mushroom`, `model_name: Google Home Mini`** — gen 1 H0A confirmed (`findings.md` E1) |
| BLE setup service dumped | ✅ 38 characteristics, read without pairing |
| Setup API mapped | ✅ `eureka_info`, `scan_results`, `scan_wifi`, `get_app_device_id`, `offer` (E2) |
| Large BLE payloads | ✅ resolved — no longer needed, the setup AP returns full data (U1) |
| Exact model name | ✅ `product_name: mushroom` ⇒ Marvell Armada 1500 Mini Plus (U2) |
| LAN / Cast reachability | ❌ device has no IP yet (`wpa_configured: false`) |
| USB / UART / JTAG | ❌ none available on H0A — NAND access only (U5, F9) |
| Firmware obtained | ❌ not yet — **the blocking prerequisite** |
| Firmware pipeline | ✅ verified end-to-end on a synthetic image |
| NAND dump decoder | ✅ `scripts/nand-decode.py`, selftest green |
| REA + Ghidra | ✅ healthy (Ghidra 12.1.2 headless; IDA + JADX also available) |

**The short version:** boot is verified and there is no UART, so Google's images
cannot be patched in place. The only route into this hardware is a NAND dump plus the
published YAFFS2 `cache`-partition exploit; the alternative is a drop-in PCB. See
`notes/ondevice-plan.md`.

## Quick start

```bash
scripts/make-venv.sh                 # once: python venv for the recon scripts
scripts/recon.sh                     # LAN cast + BLE Google devices -> evidence/

scripts/join-setup-ap.sh --api       # join the open setup AP + enumerate the API
scripts/provision-wifi.py --ssid <ssid> --pass <psk>   # move it onto your network
scripts/lab-ap.sh up                 # own its gateway (needs hostapd/dnsmasq, sudo)

scripts/ble_dump.py                  # full BLE setup-service dump
scripts/decode_gatt.py evidence/<dump>.json    # inflate payloads (incl. truncated)

scripts/cast_play.py --list                    # what Cast devices exist
scripts/cast_play.py --play http://host/tts.wav   # play audio on the Mini

scripts/nand-decode.py selftest                # prove the NAND tooling works
scripts/nand-decode.py layout target/<dump>.bin # geometry of a real dump

scripts/fw-analyze.sh target/<image>.bin       # once you have firmware
scripts/ghidra-headless.sh target/<region> 0x8000
```

`. scripts/rea-env.sh` first if you want to call `rea` directly.

## Scripts

| Script | Purpose |
| --- | --- |
| `scripts/recon.sh` | one-shot LAN + BLE recon, writes `evidence/` |
| `scripts/join-setup-ap.sh` | join the Mini's **open setup AP**, dump `eureka_info`, enumerate the API, always restore Wi-Fi |
| `scripts/setup_api.py` | read-only GET enumeration of the setup API surface |
| `scripts/provision-wifi.py` | POST `/setup/connect_wifi` to move the device onto a real network (destroys the setup surface) |
| `scripts/lab-ap.sh` | lab AP + DHCP + DNS logging + NAT + pcap so the Mini's traffic is observable |
| `scripts/nand-decode.py` | NAND dump geometry/swap detection, partition extraction, string hunts (`layout`/`scan`/`extract`/`find`/`selftest`) |
| `scripts/cast_scan.py` | mDNS discovery + `eureka_info` dump for Cast devices |
| `scripts/ble_scan.py` | BLE advertiser scan, optional GATT enumeration |
| `scripts/ble_read.py` | read all readable characteristics (bleak) |
| `scripts/ble_dump.py` | **robust** full `0xfea0` dump: resolves the rotating address, canary-checks the link, offset-aware long reads |
| `scripts/ble_notify.py` | BlueZ/D-Bus notify collector; `Operation is not supported` proves a char is read-only |
| `scripts/decode_gatt.py` | decode a GATT dump: gzip, and **partial inflate of the 512-byte-truncated payloads** |
| `scripts/cast_play.py` | list Cast devices / play an audio URL on one |
| `scripts/fw-analyze.sh` | REA firmware pipeline (identify → regions → extract → analyze → decompile) |
| `scripts/ghidra-headless.sh` | Ghidra headless on one ELF or raw ARM region, decompiles all functions |
| `scripts/ev.sh` | run any `rea` command, save JSON into `evidence/` |

## Seven traps already solved (do not re-learn them)

1. The Mini advertises a **rotating random BLE address**; resolve by name each run.
2. BlueZ reports `Connected: yes` on a **stale handle** and then returns empty reads.
   Always canary-check (device name = 14 bytes) before trusting a dump.
3. `busctl` prints `ay` arrays in **decimal**, not hex. Parsing as hex corrupts values.
4. Three setup payloads are **hard-capped at 512 bytes**, notify is unsupported on
   them, and offset reads past 512 return 0 bytes — so `scripts/decode_gatt.py`
   partial-inflates the prefix instead.
5. A connected device stops advertising, and the Mini can stay silent for minutes
   after repeated failed attaches. **Power-cycle it** rather than assuming it vanished.
6. **There is no UART and no JTAG on gen 1 H0A** (pads are BGA) and micro-USB is
   power-only. Do not spend a day hunting a serial console — board access means NAND.
7. **The 512-byte BLE cap is a dead end worth abandoning early.** The device's own
   open setup AP returns the full `device_info` over HTTPS with no app, no account and
   no BLE crypto. If a payload looks truncated, ask whether a second interface has
   the whole thing before building a decoder.

## Collection order matters

The BLE setup surface only exists while the device is **unprovisioned**. Finish
evidence collection before setting the Mini up in the Google Home app — afterwards
most of `notes/findings.md` is no longer reproducible.

## Layout

```
target/    artefacts under investigation (never modified, not in git)
evidence/  REA/firmware/recon output, one file per command
notes/     findings, architecture, firmware plan
scripts/   recon + analysis tooling
work/      scratch: extracted regions, Ghidra projects, pseudocode (not in git)
```
