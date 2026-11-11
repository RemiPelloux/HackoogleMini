# REA investigation: googlehomemini

Created 2026-10-26. This folder is one reverse-engineering investigation run with REA
(Reverse Engineer Anything, `rea` CLI + `rea` MCP server, skill `reverse-engineer-anything`).

## Layout

| Path              | Contents                                                              |
| ----------------- | --------------------------------------------------------------------- |
| `target/`         | The artifacts under investigation (binaries, APKs, ASARs, firmware…)  |
| `evidence/`       | Raw REA JSON output, one file per command (`<step>-<command>.json`)   |
| `notes/findings.md` | Conclusions, each linked to the evidence file that supports it      |
| `reconstruction/` | Our own implementation of the feature, if one is requested            |
| `scripts/`        | Helper scripts for this investigation                                 |

## How to work here

- Use the `reverse-engineer-anything` skill and the `rea` MCP tools; fall back to the
  `rea` CLI (`source scripts/rea-env.sh` first) when MCP is unavailable.
- Always pass absolute paths to REA (`$PWD/target/...`). Never modify files in `target/`.
- Save every CLI result with `--json` into `evidence/` and cite it in `notes/findings.md`.
  Keep unknowns and REA's stated limitations next to each conclusion.
- Native providers: **Ghidra** is the default (headless, always available).
  **IDA Free** is optional and attached: the user must open the original binary in IDA
  (`ida`), wait for analysis, then press Ctrl+Alt+M to start the MCP plugin on
  127.0.0.1:13337; then use `--provider ida` / `provider_id: "ida"`.
- `reconstruction/` is clean-room output: write it from `notes/findings.md`, never by
  copying decompiled code.

## Project notes (googlehomemini)

Goal: replace the Google Assistant agent on a Google Home Mini with a local LLM that
speaks MCP. Read `README.md`, then `notes/findings.md`, then `notes/architecture.md`.

- Device: BLE `GoogleHome4983`, **unprovisioned**, no IP, no USB data path.
- The BLE setup surface (service `0xfea0`) only exists while unprovisioned.
  **Do not let the device be provisioned** until BLE evidence collection is finished;
  it is not reproducible afterwards.
- Two-provider ambiguity: native targets need an explicit `--provider`. Use
  `--provider ghidra` unless the user has IDA attached over MCP.
- Raw/headerless ARM regions (most of a firmware image) need
  `--target-format raw-binary --architecture arm --entry-point 0x<base>`.
- `scripts/ev.sh` wraps `rea ... --json` into `evidence/`; prefer it over ad-hoc calls.
- Recon quirks already solved — do not reintroduce:
  - the Mini's BLE address **rotates**; resolve by name (`GoogleHome*`, service
    `0xfea0`) each run, never hard-code a MAC;
  - BlueZ may report `Connected: yes` on a stale handle and then return empty reads;
    canary-check the device-name characteristic (14 bytes) before trusting a dump;
  - `busctl` prints `ay` byte arrays in **decimal**; parsing as hex corrupts values.
- The Gen-1 Mini micro-USB is power-only: absence from `lsusb` is expected, not a bug.
- Open unknowns are tracked as U1–U5 in `notes/findings.md`; U2 (exact model) and U4
  (verified boot) gate the whole on-device track.
