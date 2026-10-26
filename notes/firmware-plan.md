# Firmware: how to get it, and what to do with it

Nothing has been downloaded yet. This is the acquisition plan plus the analysis
pipeline that is already wired up and verified.

## Why this is the critical path

Everything about "replace the Google agent on the device" reduces to one question:
**does the boot chain accept an unsigned image?** Answer it before writing any code.

| Sub-question | What it decides |
| --- | --- |
| SoC / bootloader (u-boot?) | whether there is a documented-ish ROM/recovery path |
| Verified boot (signed kernel/rootfs?) | whether custom firmware is possible at all |
| Update mechanism + signature check | whether a crafted OTA can be accepted |
| Filesystem layout | where `cast_shell`, the audio pipeline, and network config live |

## Acquisition routes, best first

1. **Exact model first.** `findings.md` U2: the model string is in the truncated
   BLE blobs (after power cycle + notify fix) OR in `eureka_info` once on LAN.
   Do not download firmware until the model is confirmed — wrong image wastes days.
2. **OTA capture via controlled AP.** Set up `hostapd` on the Pi, run `tshark`,
   provision the Mini, let it fetch its OTA update. The URL path reveals the model
   and build ID; the payload is the firmware zip. Cast OTA format: the payload is a
   `update.zip` containing a `payload.bin` (full-disk image, Brotli/LZMA compressed)
   plus `payload_properties.txt` (SHA256, size). Use `delta_generator` from AOSP
   `update_engine` or `ota_from_target_files` to extract partitions.
   **Do this only after BLE evidence collection is complete** (provisioning destroys
   the BLE setup surface, irreversibly).
3. **Full flash dump via NandBug.** No UART or JTAG pads exist on the gen 1 H0A
   board (confirmed by courk.cc research). The only hardware path without desoldering
   is a NAND interposer. NandBug (ICE40 FPGA + FT2232H) reads the 256 MB Toshiba
   NAND in < 1 min without removing the chip. Build files:
   Hardware: https://github.com/courk/NandBug-Hardware
   Software: https://github.com/courk/NandBug-Software
   This also gives you the `cache` partition needed for the YAFFS2 exploit
   (see `findings.md` Piste 2). Take the full dump before any write.
4. **Google's public CDN.** Cast firmware URLs are in the form
   `https://clients2.google.com/service/update2/crx?x=id%3D<model-id>%26v%3D<ver>%26uc`.
   The model ID comes from `eureka_info` or the OTA URL captured in step 2.
   Some images are publicly reachable without an auth token.

Treat every image as untrusted input: `scripts/fw-analyze.sh` only ever reads the
file and writes to `evidence/` and `work/`. Never execute extracted code.

## Pipeline (already verified end-to-end on a synthetic image)

```bash
scripts/fw-analyze.sh target/<image>.bin
```

| Step | Command | Output |
| --- | --- | --- |
| 1 | `file`, `sha256sum`, entropy, `binwalk`, marker strings | `evidence/fw-*/01-host-ident.txt` |
| 2 | `rea inspect-firmware-regions` | `evidence/fw-*/02-regions.json` |
| 3 | `rea extract-firmware <img> <outdir>` | `work/fw-*/extracted/` |
| 4 | `rea analyze --provider ghidra` per ELF | `evidence/fw-*/04-analyze-N.json` |
| 5 | `rea decompile-all --provider ghidra` | `work/fw-*/pseudo/` |

For **raw, headerless ARM regions** (which is most of an embedded image), REA needs
the CPU family and a load address:

```bash
rea analyze target/region.bin \
  --target-format raw-binary --architecture arm --entry-point 0x8000 \
  --provider ghidra --json
```

And for a project you can open in the GUI:

```bash
scripts/ghidra-headless.sh target/region.bin 0x8000
# -> work/ghidra-region.bin/  (open with /opt/ghidra/ghidraRun)
```

`scripts/ghidra-headless.sh` defaults raw imports to `ARM:LE:32:v7`
(Cortex-A7) and decompiles every function into `evidence/<ts>-ghidra-*.txt`.

## What to look for once you have an image

Search strings and xrefs for, in this order:

1. **Boot / update trust** — `verified`, `signature`, `rsa`, `sha256`, `otp`, `efuse`,
   `bootloader`, `u-boot`, `mtd`, `secure_boot`, `dm-verity`.
2. **The Assistant/cloud leg** — endpoints and namespaces: `assistant`, `embeddedassistant`,
   `oauth`, `www.google.com`, `cast`, `libcast`, `cast_shell`, `eureka`.
3. **Audio pipeline** — `alsa`, `pulse`, `tinyalsa`, `hotword`, `speex`, `opus`.
4. **Network/provisioning** — `wpa_supplicant`, `eureka_info`, `setup`, `mdns`.

`rea search_strings` / `rea xrefs` / `rea analyze-function` are the right tools once
a binary is open; do not grep hundreds of MB by hand.

## OTA payload format and RSA verification

The OTA payload is **RSA-verified** by the postbootloader (mtd4/5). Capturing the
OTA zip via a controlled AP gives you a legitimate firmware image for *analysis*,
but you cannot flash a modified version back without bypassing the signature check
first. The YAFFS2 exploit path (findings.md Piste 2) is the bypass — the `cache`
partition (mtd8) is outside the verified boot chain and writable.

Old endpoint (expired): `https://ota.team-eureka.com/ota/update.php?version=<build>.<rev>&serial=<SHA1_serial>`
Reference repo: https://github.com/team-eureka/ChromeCast-OTA

OTA zip structure:
- `payload.bin` — full-disk image (LZMA or Brotli compressed)
- `payload_properties.txt` — SHA256 hash and size
- Extract partitions with: `python3 update_payload/update_payload.py extract --payload payload.bin --output_dir work/fw-<ts>/`
  (AOSP `update_engine` scripts, or the `chromiumos-update-payload-tools` PyPI package)

## Safety

- Keep `target/` read-only and out of git (see `.gitignore`); these are Google
  binaries, do not redistribute them.
- A failed flash on this class of device usually bricks it with no recovery unless
  you already have a hardware dump via NandBug. **Take the full NAND dump before
  any write attempt.** The `factory_store` partition (mtd10) contains the device's
  unique TLS certificate and private key — losing it is permanent.
