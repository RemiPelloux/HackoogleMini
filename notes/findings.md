# googlehomemini — findings

Investigation into replacing the Google Assistant agent on a Google Home Mini with a
local LLM that can call arbitrary MCP servers.

## Question

1. What exactly is the device, and what interfaces can we reach it on?
2. Where does the Google Assistant agent actually run, and what would "replace it"
   mean at the firmware level?
3. Can the device be reflashed, or must it be repurposed as an I/O endpoint?

## Target

| Field | Value |
| --- | --- |
| Artifact | no firmware image yet — see `notes/firmware-plan.md` |
| Device | Google Home Mini, BLE name `GoogleHome4983` |
| Build | **`cast_build_revision` 3.75.468362** (from the device, E1) |
| BLE addr | rotating resolvable-private address — observed `4D:64:D0:63:0A:E2`, `73:5F:A9:7F:67:36`, `51:50:10:FA:5E:47` |
| Hardware MAC | `44:07:0B:D…` (truncated by the 512-byte cap, see U1) |
| Hotspot BSSID | `FA:8F:CA:35:5C:46` — matches the advertised service data |
| LAN addr | none — device is not on Wi-Fi |
| Country | `FR`, UI locale French |
| Evidence | `evidence/20261026-*` |

## Findings

### F1. The device is unprovisioned and not on any network

`evidence/20261026-103338-nmap-cast.txt` — a sweep of `192.168.1.0/24` for
`:8008`/`:8009` returns exactly one host, `192.168.1.12`.
`evidence/20261026-103338-cast-scan.json` — that host identifies itself via
`/setup/eureka_info` as `65" Neo QLED`, model `QN80D`, build `721674079`,
`release_track: stable-channel`. That is the TV, **not** the Mini.

From the other side, `127c6160` (OTA status) returns
`{"auto_reboot":true,"current_operation":"UPDATE_STATUS_IDLE","last_checked_time":"0",
"new_size":"0","new_version":"0.0.0.0","ready_to_apply":false}` — version
`0.0.0.0` and a zero size mean no update was ever fetched, i.e. never provisioned.

### F2. There is no USB data path

`lsusb` and `/sys/bus/usb/devices` show only the integrated Chicony camera and root
hubs; no Google VID (`18d1`) device enumerates, before or after replugging. The
micro-USB port on this generation is power-only, so USB is not an analysis or
flashing interface. **Confirming this needs a teardown** (UART pads), not `lsusb`.

### F3. The BLE setup service is fully readable without pairing

`evidence/20261026-103458-gatt-dump.json` — GATT tree: 3 services, `0x1800` (GAP),
`0x1801` (GATT), `0xfea0` (Google) with 34 characteristics.
`evidence/20261026-104934-ble-setup-dump.json` + `evidence/20261026-111855-gatt-decoded.txt`
— reads succeed with **no bonding, no encryption, no authentication**.

### E1. Device identity and capabilities (recovered from the setup payloads)

Decoded with `scripts/decode_gatt.py`, which partially inflates the truncated gzip
streams (see U1). This is the substantive result of the BLE phase:

```json
"build_info": {"cast_build_revision": "3.75.468362"},
"device_info": {
  "capabilities": {
    "assistant_supported": true,
    "ble_supported": true, "bluetooth_supported": true,
    "bluetooth_audio_sink_supported": true, "bluetooth_audio_source_supported": true,
    "cloudcast_supported": true, "cloud_groups_supported": true,
    "hotspot_supported": true, "https_setup_supported": true,
    "setup_supported": true, "set_network_supported": true,
    "reboot_supported": true, "multizone_supported": true,
    "multiuser_supported": true, "preview_channel_supported": true,
    "secure_setup_enforcement_supported": false,
    "opencast_supported": false, "display_supported": false,
    "fdr_supported": false, "audio_hdr_supported": false
  },
  "cloud_device_id": "009CCF5F2B42B8E54BD50F2BB713692D",
  "factory_country_code": "FR",
  "hotspot_bssid": "FA:8F:CA:35:5C:46",
  "mac_address": "44:07:0B:D…",
  "public_key": "MIIBCgKCAQEA/tVvUlRi7rnbNlG8ZK5kjVr0NWlWvD0sAw1kVN3g0spCxbl4xflBKL92/9NlMiRQqwmYseSFBiCAYqiJMss36i1gJn/dxCRLNx3MlhHypj7FwOUeUVtxCVdbG4lGcKJqKybDnGJmsWodVWFO0bTb41hkwrAp4Pg3UuXjZczKLE5ZE4OomEF6rid8tdsRIKSjLympjwo79lLRqalKpg6sYQ73MKi3fk/pw+u5ey3z10CDYq1Dgd3IfcdS8nW9EcrFNUZ2t8itJe4PIXbC5uAuqoieL1Me6Fsp5uouGz67talX0tqsCeMh6VFUktaY56jImkNeg3xHTdo8OCZNEHZVYwIDAQAB"
},
"sign": {"certificate": "-----BEGIN CERTIFICATE-----\nMIIDzzCCAregAwIBAgIGTDM5SVJVMA0GCSqGSIb3DQEBCwUAMIGKMQswCQYDVQQG\nEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll\ndzETMBEGA1UECgwKR29vZ2…"}
```

Read this carefully, because three lines decide the project:

- **`assistant_supported: true`** — the Assistant client is present on this device,
  as expected. This is the component to reason about.
- **`secure_setup_enforcement_supported: false`** — setup is *not* enforced over an
  authenticated channel, consistent with F3 (open GATT reads, and no bonding). So the
  provisioning path is not a trust boundary here.
- **`https_setup_supported: true`** — there is a local HTTPS setup API in addition to
  BLE. This is the route to the *full* (untruncated) device info, see U1.

`public_key` is a complete RSA-2048 SubjectPublicKeyInfo, and `sign.certificate` is a
Google-issued X.509 chain (serial `TDM59IRU`-ish, issuer `C=US, ST=California,
L=Mountain View, O=Goog…`). Together these are the device attestation material — the
same material a firmware signature check would rely on.

Cross-check on the advertise data: the service data observed in
`evidence/20261026-103338-ble-scan.json` is `03fa8fca355c466f2020209e43`, i.e.
`0x03` then `FA:8F:CA:35:5C:46` — byte-for-byte the `hotspot_bssid` above. The
advertisement leaks the setup hotspot identity, not a random token.

### E2. The device exposes your Wi-Fi environment to any passing BLE scanner

`157c6160` is a *complete*, readable Wi-Fi scan list — no pairing, no popup, no
consent, on a device that is merely powered on:

`AcquaProtectionWifi`, `EAPNEU_WIFI`, `KFC_LIV`, `Livebox-6890`, `Livebox-94D0`,
`Livebox-C5C0`, `WIFI_KFC` — with BSSIDs, frequencies, RSSI, `wpa_auth` and
`wpa_cipher` for each, including per-AP `ap_list` entries for multi-BSSID radios.

That is a real privacy observation, not just a recon convenience: an unprovisioned
Home Mini broadcasts the neighbourhood's SSID inventory to anyone in radio range.

### F4. The advertised address rotates, and BlueZ lies about connection state

Three operational traps, all hit and solved (baked into `scripts/ble_dump.py` and
`scripts/ble_notify.py`):

- The Mini advertises a **resolvable-private BLE address** that rotates (three
  different addresses observed in one session). Hard-coding a MAC fails within
  minutes. Resolve by name (`GoogleHome*`) or service `0xfea0` on every run.
- BlueZ reports `Connected: yes` on a **stale handle**, after which every read
  returns empty rather than an error. A canary read (device-name characteristic,
  always 14 bytes) is required to prove the link.
- A connected device **stops advertising**, and the device can also go quiet for
  minutes after repeated failed attaches. Disconnect stale `GoogleHome*` links, and
  if it stays silent, power-cycle the Mini.

### F5. `busctl` prints `ay` byte arrays in decimal, not hex

`scripts/ble_dump.py` originally parsed `busctl` output as hex and silently produced
corrupt values (gzip that would not decompress). `busctl` emits
`ay <count> <count decimal byte values>`. This made the first long-read attempt look
successful while returning nonsense.

### F6. The Assistant agent is not on the device

Nothing observed contradicts the standard Cast architecture: the Mini runs a Cast
receiver plus a streaming audio client; wake-word detection is on-device, but
**speech-to-text, the agent logic and text-to-speech all run in Google's cloud** over
TLS. There is no on-device LLM, and ~256 MB of RAM leaves no room for one. "Put an
LLM inside" therefore means *redirect or replace the audio pipeline*, not *install a
model* — see `notes/architecture.md`.

## Unknowns and limitations

- **U1 — the three large payloads are hard-capped at 512 bytes. Partly resolved.**
  `197c6160` (device_info), `1a7c6160` (public_key + certificate) and `1b7c6160`
  (supported_locales) return exactly 512 bytes. Established experimentally:
  - ATT offset reads past 512 return **0 bytes** (not an ATT error), so the
    attribute really is 512 bytes long — this is a firmware cap, not an ATT limit;
  - `StartNotify` on those three returns **`Operation is not supported`** — they are
    read-only, so there is no notification escape hatch
    (`evidence/20261026-112044-ble-notify-probe.log`, reproducible);
  - writing an offset to the paired `xx6c` characteristic does **not** advance the
    window; each read restarts at the gzip header.
  - `scripts/decode_gatt.py` recovers 1–1.4 KB of JSON from each 512-byte prefix by
    partial inflation, which is how E1 was obtained. The remaining tail (full MAC,
    complete certificate PEM) needs the **HTTPS setup API**
    (`https_setup_supported: true`, hotspot `FA:8F:CA:35:5C:46`, port 8443), which
    requires the hotspot PSK that Google's flow hands over during the BLE handshake.
- **U2 — exact model still unnamed.** The build revision (3.75.468362) and the
  capability set are known, but no `model_name`/`product_name` string survived the
  512-byte cap, so gen 1 (`H0A`) vs gen 2 (`H1A`) is still inferred, not proven. It
  matters: it selects the SoC and therefore the Ghidra processor and load addresses.
- **U3 — no firmware image yet.** Nothing from this device has been analysed.
  `scripts/fw-analyze.sh` and `scripts/ghidra-headless.sh` are verified end-to-end on
  a synthetic image only.
- **U4 — verified boot / updater signing unassessed.** This is the decision point for
  the whole on-device track.
- **U5 — no USB, no UART yet.** Board-level access needs physical teardown.
- The two non-gzip blobs (`22216033…` 65 B, `2dab7a51…` 16 B) are high-entropy and
  undecoded — most likely handshake nonce/key material.
- Collection is stateful: **the setup service disappears once the device is
  provisioned.** Finish BLE evidence work before touching the Google Home app.

## Reconstruction plan

Two tracks, with very different risk:

- **Track A (days, no firmware risk):** keep the Mini as a Cast *speaker* and move
  the whole agent off-device — wake word, STT, LLM, MCP client, TTS on a home box.
  See `notes/architecture.md`; `scripts/cast_play.py` proves the speaker half works
  (validated against the TV on the LAN).
- **Track B (weeks, this REA investigation):** finish the setup-protocol
  reconstruction (U1), pin the model (U2), obtain firmware (U3), then decide on
  verified boot (U4) with `scripts/fw-analyze.sh` + Ghidra.

Track B's first deliverable is a decision, not code: *can this device run unsigned
code, yes or no.*

---

## Research findings (from internet research, 2026-10-26)

### F7. Build `3.75.468362` — YAFFS2 kernel exploit likely still applicable

The `cast_build_revision` `3.75.468362` was released in **2021**, corresponding to a
Linux 3.8.13 kernel build. The upstream YAFFS2 fix dates to **2014**; the Gen-1 H0A
kernel used in builds up to and including 2021 was never rebased past ~2019 and is
**confirmed vulnerable** by courk.cc's research on the same build lineage.

If the device has never been provisioned (confirmed: `new_version` = `0.0.0.0`), it
has never auto-updated over Wi-Fi — so the kernel running today is likely the
factory-flashed version, which is squarely in the vulnerable window.

**Action:** confirm with `build_info.cast_build_revision` from `eureka_info` once on
LAN (or trust the BLE value); if it matches a ≤ 2021 build, proceed to NandBug.

### F8. Gen 2 SoC correction — Synaptics AS370, not Amlogic

Earlier notes said gen 2 (H2C, "Nest Mini") uses Amlogic S905D. **Incorrect.**
iFixit teardown and WikiDevi confirm: gen 2 H2C uses **Synaptics AS370** (AudioSmart).
Amlogic chips (S905D, A113X, A113D) are in the **Nest Hub** product line, not the
Nest Mini. Consequences:

- CVE-2023-48424 / CVE-2023-48426 (eMMC fault injection → U-Boot shell, earned
  $68 000 at HardPwn USA 2023) affect **Amlogic Chromecast/Nest Hub** devices — they
  do **not** apply to either gen 1 H0A or gen 2 H2C (Synaptics) Nest Mini.
- The haxx.in EL3 BootROM exploit is Amlogic-specific, also irrelevant.

### F9. No UART or JTAG pads on gen 1 H0A (confirmed by courk)

Courk specifically probed the gen 1 H0A board and found no accessible serial/debug
test points — all debug interfaces are BGA, not exposed. UART pinouts on XDA/Reddit
are for the **Nest Hub**, a different device. For H0A:
- micro-USB is power-only (F2).
- The only non-destructive hardware path is NAND physical access via NandBug or a
  NAND flash clip/programmer.

### F10. H0A partition map (from courk.cc research)

| mtd | Name | Notes |
| --- | --- | --- |
| mtd0 | block0 | BootROM DDR/ECC config |
| mtd1 | prebootloader | Low-level SoC init |
| mtd2/3 | tz / tz-b | A/B TrustZone |
| mtd4/5 | postbootloader | 640 KB; RSA/SHA256-verifies kernel. **Google released the source.** |
| mtd6 | kernel | Linux 3.8.13 (verified by postbootloader) |
| mtd7 | rootfs | SquashFS + dm-verity |
| **mtd8** | **cache** | **YAFFS2, rw — NOT in the verified boot chain. Exploit target.** |
| mtd9 | recovery | Factory reset |
| mtd10 | factory\_store | YAFFS2 ro; device TLS certs, serial, keys |
| mtd11 | fts | Key-value store |

`cache` (mtd8) and `factory_store` (mtd10) are outside the verified boot chain.

### F11. CVE-2023-48419 — account-linking chain (CVSS 10.0, patched for firmware ≥ 2.58)

Matt Kunze (2022, patched April 2021):
1. 802.11 deauth → device loses Wi-Fi → enters setup mode
2. `GET http://<ip>:8008/setup/eureka_info` (no auth) → returns `cloud_device_id`,
   `public_key`, `signed.certificate`
3. Attach attacker's Google account using those fields via the cloud API
4. Remote access: routines, mic activation, arbitrary commands

Fixed April 2021. CVE-2023-48419 (CVSS 10.0) covers firmware < 2.58; patched via
March 2024 OTA. `3.75.468362` is from 2021 and may be **below `2.58`** — check the
`build_version` integer from `eureka_info` post-provisioning. If the unit is on old
firmware and provisioned, this chain may still work for initial access.
Source: https://downrightnifty.me/blog/2022/12/26/hacking-google-home.html

### F12. BLE privacy observation — Wi-Fi environment disclosure

`157c6160` returns the full Wi-Fi scan list with zero authentication from any BLE
device in range: SSIDs (`AcquaProtectionWifi`, `KFC_LIV`, `Livebox-6890`, etc.),
BSSIDs, RSSI, WPA cipher and auth type. An unprovisioned Home Mini in a public space
broadcasts its neighbourhood's SSID inventory. Logged as a privacy observation, not
just a recon convenience (E2).

---

## Open pistes (next steps, ordered by effort)

### Piste 1 — Identify the model precisely (U2) — first priority

- **Via OTA URL (best):** see firmware-plan.md Piste 3 (controlled AP).
- **Via `eureka_info` (easiest, needs provisioning):**
  ```bash
  curl -s "http://<mini-ip>:8008/setup/eureka_info?options=detail" | python3 -m json.tool
  ```
  Returns `cast_build_revision`, `build_version`, `hardware_version`, `model_name`.
  This resolves U2 and confirms whether the kernel is in the YAFFS2 exploit window.

### Piste 2 — YAFFS2 kernel exploit via NandBug (H0A only, confirmed code execution)

The only published secure-boot bypass on this exact device class. Source: courk.cc.

**Attack surface:** `cache` partition (mtd8) — YAFFS2, writable, outside verified boot.
**Bug:** object-confusion in `yaffs2_scan_chunk` in Linux 3.8.13. Fixed upstream in
2014; the H0A kernel (all known builds ≤ 2021) never received the patch.

**Full chain:**
1. Build NandBug hardware: ICE40HX1K-TQ144 FPGA + FT2232H interposer soldered to the
   NAND (TC58NVG1S3HBAI6). Reads 256 MB in < 1 min.
   Hardware: https://github.com/courk/NandBug-Hardware
   Software: https://github.com/courk/NandBug-Software
2. Dump the NAND. BCH ECC: poly `0x8003`, strength 48, OOB 90 B/page; nibble-swap
   first 2080 bytes of each page before computing BCH, swap result back.
3. Write poisoned YAFFS2 image to mtd8: crafted chunk with same `obj_id` but
   mismatched `chunk_id` causes type confusion → `file_size` field becomes
   `children.next` pointer → overwrite `dev->tagger.read_chunk_tags_fn`.
4. Spray fake `yaffs_obj` structures + shellcode via `blob-base64` entries in
   `wpa_supplicant.conf` (kernel lowmem is NX-free; one-to-one v→p map,
   addresses ~`0xc0000000–0xddd00000`).
5. Boot: `init.rc` mounts `cache`; trigger fires → `call_usermodehelper_fns`:
   - `mount -o remount,rw,exec /factory_setting`
   - Execute your payload ELF from `factory_setting`
6. Root shell. **5–10 % success per boot** (heap spray). Power-cycle on failure.

Unbrick tool built on this research: https://github.com/juniperchow/unbrick-google-home-mini

### Piste 3 — JADX + Frida on Google Home APK (BLE trigger commands, U1 tail, U2)

The `0xfea0` write-characteristic command format is undocumented. Two paths:

**JADX static (days, no device):**
Search decompiled APK for `fea0`, `7c6160`, `fe40` — they appear literally in the BLE
manager class. The surrounding method reveals the exact trigger byte sequence and any
encryption/MAC on the command side.

**Frida dynamic (hours, needs Android phone with Google Home app):**
```bash
frida -U -n "com.google.android.apps.chromecast.app" -l frida-ble-hook.js
# hook android.bluetooth.BluetoothGatt.writeCharacteristic
```
Captures all writes to the setup service in plaintext. Run while the app provisions
any Cast device. Reference: Pen Test Partners BLE+Frida guide.

The HTTPS setup API (`https_setup_supported: true`, hotspot `FA:8F:CA:35:5C:46`,
port 8443) would give the full untruncated `197c/1a7c/1b7c` payloads, but it needs
the hotspot PSK from the BLE handshake — same target.

### Piste 4 — NAND CS# fault injection (glitch into U-Boot shell)

DirectDefense/oddsolutions on the Pixel Tablet Dock (AML A113D) showed that a brief
high pulse on NAND CS# at the right boot window drops U-Boot to an interactive shell,
bypassing Secure Boot. They state it "seems to affect multiple other Nest devices."
Gen 1 H0A uses Marvell, so exact timing differs, but the technique class is
architecture-independent. Tools reference:
https://github.com/oddsolutions/korlan-secure-boot-bypass

### Piste 5 — Postbootloader source audit (U4 assessment)

Google released the H0A `postbootloader` source (~640 KB binary at mtd4/5). Audit it
for the same class of parser bugs as the Nest Hub U-Boot stack overflow
(fredericb.info, 2022): stack buffer overflows in FAT/partition/USB block parsers.
The Nest Hub bug was fixed upstream in 2011, reintroduced 2018, fixed by Google in
December 2021 — the Mini's postbootloader may be on a similarly stale upstream. If
the postbootloader parses USB blocks, a Raspberry Pi Pico delivering an oversized
block at boot is the attack delivery mechanism.

### Piste 6 — MiciMike drop-in PCB (no-exploit path, working voice bot immediately)

Open-source ESP32-S3 + XMOS XU316 replacement mainboard, physically fits in the gen 1
enclosure, reuses speaker + fabric shell + mic mute button. Ships with ESPHome →
Home Assistant Assist → Wyoming → Whisper STT + local LLM + Piper TTS + MCP.
~$85 on Crowd Supply, or self-fab from open-source gerbers (CERN-OHL-S v2).
GitHub: https://github.com/iMike78/home-mini-v1-drop-in-pcb
**If you want a working local LLM voice bot in the Mini's shell with zero firmware
risk, this is the weekend path.**

### Piste 7 — Track A software stack (working today, no hardware risk)

Pipeline that works right now with your Pi + DeepSeek:

```
ESP32-S3 mic or ReSpeaker HAT
  → openWakeWord (wake word detection)
  → wyoming-whisper (STT, Docker on Pi)
  → DeepSeek / local LLM via Ollama
  → MCP client pool (arbitrary MCP servers)
  → wyoming-piper (TTS)
  → pychromecast → Mini speaker (Cast audio URL)
```

`glocaltokens` Python library extracts local Cast auth tokens post-provisioning.
Home Assistant Assist orchestrates the Wyoming stack natively if you run HA.
Small LLMs that fit a Pi 4/5: `llama3.2:3b`, `qwen3:4b`, `gemma3:4b` via Ollama.
