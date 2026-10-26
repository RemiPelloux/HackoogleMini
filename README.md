# googlehomemini

Reverse-engineering workspace for replacing the Google Assistant agent on a **Google
Home Mini** with a local LLM that can call arbitrary **MCP** servers.

Read in this order:

1. **`notes/findings.md`** — what was actually observed, with evidence links.
2. **`notes/architecture.md`** — what "replace the agent" means and the three
   realistic options. **Start here if you just want it working.**
3. **`notes/firmware-plan.md`** — how to get firmware and what to do with it.

## Status

| Area | State |
| --- | --- |
| Device discovered | ✅ `GoogleHome4983`, BLE only, unprovisioned |
| Device identity | ✅ build `3.75.468362`, capability set, attestation key + cert prefix (`findings.md` E1) |
| BLE setup service dumped | ✅ 38 characteristics, read without pairing |
| Large payloads | ⚠️ hard-capped at 512 B; 1–1.4 KB/char recovered by partial inflate (U1) |
| Exact model name | ❌ truncated away; gen 1 vs gen 2 still inferred (U2) |
| LAN / Cast reachability | ❌ device has no IP yet |
| USB access | ❌ power-only port, nothing enumerates |
| Firmware obtained | ❌ not yet |
| Firmware pipeline | ✅ verified end-to-end on a synthetic image |
| REA + Ghidra | ✅ healthy (Ghidra 12.1.2 headless; IDA + JADX also available) |

## Quick start

```bash
scripts/make-venv.sh                 # once: python venv for the recon scripts
scripts/recon.sh                     # LAN cast + BLE Google devices -> evidence/

scripts/ble_dump.py                  # full BLE setup-service dump
scripts/decode_gatt.py evidence/<dump>.json    # inflate payloads (incl. truncated)

scripts/cast_play.py --list                    # what Cast devices exist
scripts/cast_play.py --play http://host/tts.wav   # play audio on the Mini

scripts/fw-analyze.sh target/<image>.bin       # once you have firmware
scripts/ghidra-headless.sh target/<region> 0x8000
```

`. scripts/rea-env.sh` first if you want to call `rea` directly.

## Scripts

| Script | Purpose |
| --- | --- |
| `scripts/recon.sh` | one-shot LAN + BLE recon, writes `evidence/` |
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

## Five traps already solved (do not re-learn them)

1. The Mini advertises a **rotating random BLE address**; resolve by name each run.
2. BlueZ reports `Connected: yes` on a **stale handle** and then returns empty reads.
   Always canary-check (device name = 14 bytes) before trusting a dump.
3. `busctl` prints `ay` arrays in **decimal**, not hex. Parsing as hex corrupts values.
4. Three setup payloads are **hard-capped at 512 bytes**, notify is unsupported on
   them, and offset reads past 512 return 0 bytes — so `scripts/decode_gatt.py`
   partial-inflates the prefix instead.
5. A connected device stops advertising, and the Mini can stay silent for minutes
   after repeated failed attaches. **Power-cycle it** rather than assuming it vanished.

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
