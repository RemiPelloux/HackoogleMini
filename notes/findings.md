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
| Device | Google Home Mini, internal product name **`mushroom`** (E1) |
| Build | **`cast_build_revision` 3.75.468362**, `build_version` 468362 (E1) |
| BLE addr | rotating resolvable-private address — observed `4D:64:D0:63:0A:E2`, `73:5F:A9:7F:67:36`, `51:50:10:FA:5E:47` |
| Hardware MAC | `44:07:0B:D2:6F:36` (E1) |
| Hotspot BSSID | `FA:8F:CA:35:5C:46` — matches the advertised service data |
| SSDP UDN | `ad8442f8-f004-f4f4-44cb-ac11eb2d26f6` |
| LAN addr | none — device is not on Wi-Fi (`wpa_configured: false`) |
| Country / locale | `FR`, `fr` |
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

### E1. The device exposes its own open setup access point — full identity recovered

An unprovisioned Home Mini broadcasts an **open** AP whose BSSID is exactly the
`hotspot_bssid` from BLE, and serves the Google Home app's own setup API over
**HTTPS on `192.168.255.249:8443`** (and `http://…:8008`). No Google account, no app,
no BLE crypto handshake is needed to reach it.

`scripts/join-setup-ap.sh` joins that AP, dumps `eureka_info`, and restores the
previous Wi-Fi connection on exit. Results:
`evidence/20261026-133605-eureka-192.168.255.249-8443.json`,
`evidence/20261026-133839-setup-api.json`.

This resolved the remaining identity unknowns in one step:

```json
"detail":     {"model_name": "Google Home Mini", "manufacturer": "Google Inc.",
               "locale": {"display_string": "français"}},
"product_name": "mushroom",
"mac_address": "44:07:0B:D2:6F:36",
"cloud_device_id": "009CCF5F2B42B8E54BD50F2BB713692D",
"ssdp_udn": "ad8442f8-f004-f4f4-44cb-ac11eb2d26f6",
"weave_device_id": "",          // never joined Google's Weave fabric
"setup_state": 10, "wpa_state": 3, "wpa_configured": false,
"has_update": false, "release_track": "stable-channel", "version": 13,
"opt_in": {"crash": false, "opencast": false, "stats": false},
"tos_accepted": false, "uptime": 15174.6
```

**`product_name: "mushroom"` settles U2**: this is the Home Mini gen 1, i.e. the
Marvell Armada 1500 Mini Plus (88DE3006), dual Cortex-A7, ARMv7 little-endian — the
assumption that drove the Ghidra configuration was correct. Note gen 2 is a
*different* product name (`Google Nest Mini`), so this is conclusive, not inferred.

### E2. Setup API surface (GET-only enumeration)

Probed with `scripts/setup_api.py` (read-only; never POSTs):

| Endpoint | Result |
| --- | --- |
| `/setup/eureka_info` | 200, 1137 B |
| `/setup/eureka_info?options=detail` | 200, 1346 B (+`model_name`, `manufacturer`) |
| `/setup/eureka_info?options=detail&params=setup_state,device_info` | 200, 1904 B — **the full `device_info`**, incl. `product_name`, `model_name`, `weave_device_id` |
| `/setup/scan_results` | 200, 1192 B — the device's own Wi-Fi scan |
| `/setup/supported_timezones` | 200, 15984 B |
| `/setup/scan_wifi` | **405** → exists, POST-only |
| `/setup/get_app_device_id` | **405** → exists, POST-only |
| `/setup/offer` | 500 (GET not meaningful) |
| `/eureka_info`, `/setup/icon.png`, `/setup/log`, `/setup/device_info`, `/setup/capabilities`, … | 404 — not present |

So the setup server is a small, closed surface: `eureka_info`, `scan_results`,
`scan_wifi`, `get_app_device_id`, `offer`, plus the mutating endpoints the Home app
uses (`connect_wifi`, `set_eureka_info`, `reboot`). Nothing resembling a debug shell
or a firmware-read endpoint.

Two notes for the on-device track: `params=...` controls which sections are returned
(so the 512-byte BLE cap was a BLE-layer limit, not a device-data limit), and
`weave_device_id` being empty is consistent with a device that has never completed
Google activation.



### E3. Device identity and capabilities (from the BLE setup payloads)

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

### E4. The device exposes your Wi-Fi environment to any passing BLE scanner

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

- **U1 — RESOLVED.** The three BLE payloads are capped at exactly 512 bytes, and it
  is a firmware cap, not an ATT limit:
  - ATT offset reads past 512 return **0 bytes** (not an ATT error), so the
    attribute really is 512 bytes long;
  - `StartNotify` on those three returns **`Operation is not supported`** — they are
    read-only, so there is no notification escape hatch
    (`evidence/20261026-112044-ble-notify-probe.log`, reproducible);
  - writing an offset to the paired `xx6c` characteristic does **not** advance the
    window; each read restarts at the gzip header.
  `scripts/decode_gatt.py` sidesteps the cap by partially inflating the prefixes
  (1–1.4 KB of JSON), but it is no longer needed for identity: the open setup AP (E1)
  returns the full `device_info` over HTTPS, with no BLE handshake, hotspot PSK or app.
- **U2 — RESOLVED.** `product_name: "mushroom"` and `model_name: "Google Home Mini"`
  (E1) prove gen 1 `H0A`, i.e. Marvell Armada 1500 Mini Plus (88DE3006), ARMv7 LE —
  exactly what `scripts/ghidra-headless.sh` already targets.
- **U3 — no firmware image yet.** Nothing from this device has been analysed.
  `scripts/fw-analyze.sh` and `scripts/ghidra-headless.sh` are verified end-to-end on
  a synthetic image only. Blocking prerequisite for everything except Piste 6.
- **U4 — verified boot exists; the bypass route is identified, not proven.** Published
  H0A research (F10) says `postbootloader` RSA/SHA256-verifies the kernel and the
  rootfs is SquashFS + dm-verity, so **Google's images cannot be patched in place**.
  The published exploit instead attacks the kernel from the `cache` partition (mtd8,
  YAFFS2, writable, outside the verified chain). Unverified on this unit — needs a
  NAND dump.
- **U5 — no UART, no JTAG, no USB data path.** Per published teardown (F9) gen 1 H0A
  has no accessible serial/debug pads (BGA only) and micro-USB is power-only (F2).
  **The UART boot-log shortcut is not available**; the only board-level route is
  physical NAND access (Piste 2).
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

Track B's first deliverable is a decision, not code: *can this device run our code,
and at what cost?* Published research (Piste 2) already answers yes-or-no — the
answer is NAND, not signatures:

- **Track B1 — NAND root (Piste 2).** NandBug interposer + YAFFS2 `cache`-partition
  exploit → ring 0 → root shell → our client runs from an unverified rw partition.
  Soldered FPGA hardware; highest effort, only path that modifies *this* device.
- **Track B2 — drop-in PCB (Piste 6).** ESP32-S3 + XMOS board in the same shell,
  reusing the speaker and mic-mute button, running ESPHome → Assist → Wyoming →
  Whisper/LLM/Piper. No exploit, works immediately; the Google silicon is discarded.

Implementation details for B1 (what the device speaks, what to replace) are in
`notes/ondevice-plan.md`.

---

## Research findings (from internet research, 2026-10-26)

### F7. Build `3.75.468362` — YAFFS2 kernel exploit possibly applicable

`cast_build_revision` `3.75.468362` corresponds to a Linux 3.8.13 kernel on this
platform. The upstream YAFFS2 fix dates to **2014**; the Gen-1 H0A kernel of this
lineage is **reported vulnerable** by courk.cc's research.

**Confirmed on our unit (E1/E3):** `cast_build_revision` is exactly `3.75.468362`, and
`new_version: "0.0.0.0"` + `has_update: false` show the device has **never** taken an
OTA, so the factory kernel is what runs today.

**Still unverified on our unit:** that this build's kernel is inside the vulnerable
window. Only the NAND dump can tell us — read the kernel version string off mtd6.
Do not claim vulnerability before that.

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
March 2024 OTA.

**Our unit should be patched for this:** on the same versioning scheme (major.minor)
`3.75.x` > `2.58`. Do not build the plan on it. E1/E2 reaching the setup API
pre-provisioning is the same *class* of exposure, but it is a diagnostic here — the
device is linked to no account, so there is nothing to take over.
Source: https://downrightnifty.me/blog/2022/12/26/hacking-google-home.html

### F12. BLE privacy observation — Wi-Fi environment disclosure

`157c6160` returns the full Wi-Fi scan list with zero authentication from any BLE
device in range: SSIDs (`AcquaProtectionWifi`, `KFC_LIV`, `Livebox-6890`, etc.),
BSSIDs, RSSI, WPA cipher and auth type. An unprovisioned Home Mini in a public space
broadcasts its neighbourhood's SSID inventory. Logged as a privacy observation, not
just a recon convenience (E4).

---

## Open pistes (next steps, ordered by effort)

### Piste 1 — Identify the model precisely (U2) — **DONE**

Resolved without hardware, via the open setup AP (E1):

```bash
./scripts/join-setup-ap.sh --api
curl -sk 'https://192.168.255.249:8443/setup/eureka_info?options=detail&params=setup_state,device_info'
```

`product_name: "mushroom"`, `model_name: "Google Home Mini"` ⇒ gen 1 H0A, Marvell
Armada 1500 Mini Plus. Ghidra already targets `ARM:LE:32:v7` accordingly. Kept as the
record of how it was obtained.

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

---

## Late findings (post-research, 2026-10-26)

### F13. `cast_shell` and `libassistant.so` — the exact audio intercept targets

After root (Track B1), the two files that matter:

| File | Path | Role |
| --- | --- | --- |
| Cast receiver | `/system/chrome/cast_shell` | Main process — Cast protocol, audio stack, wake word |
| Google Assistant gRPC client | `/system/chrome/lib/libassistant.so` | Sends 16kHz 16-bit PCM in AssistRequest, receives AssistResponse |

`libassistant.so` calls `google.assistant.embedded.v1alpha2.EmbeddedAssistant.Assist` at
`embeddedassistant.googleapis.com:443` (TLS, BoringSSL). Audio format: 16 kHz, 16-bit, mono.

Three post-root intercept strategies, ordered by invasiveness:

1. **LD_PRELOAD hook** (`reconstruction/payload/libassist_hook.c`): intercepts `write()`
   / `SSL_write()` calls carrying gRPC AssistRequest frames, tees raw PCM to a UDP socket
   on the Pi. The Pi-side server (`reconstruction/agent/pi_whisper_server.py`) runs
   Whisper → LLM → Piper and sends a Cast-playable URL back. `cast_shell` stays running
   and handles Cast auth — only the cloud leg is replaced.
2. **`libassistant.so` stub replacement**: remove or rename the real `.so`, drop in a
   stub that opens a TCP socket to the Pi and streams raw PCM. Clean but requires
   remounting `/system` rw.
3. **tinyalsa direct capture**: bypass `cast_shell` entirely — run `tinycap` against the
   ALSA PCB device (`/dev/snd/pcmC0D0c`), pipe to Pi Whisper, play TTS back via
   `tinyplay`. No gRPC touched.

**Preferred path post-root:** LD_PRELOAD (option 1). Leaves `cast_shell` auth intact,
survives reboots with a one-line `init.d` patch, and reverting is `rm` + power-cycle.

Deploy steps are in `reconstruction/payload/libassist_hook.c` header.

### F14. Setup hotspot is open — no PSK needed (confirmed by historical analysis)

The setup AP (`FA:8F:CA:35:5C:46`, SSID `GoogleHome4983` or similar) **has no WPA2
password**. This is documented historical Chromecast behaviour: the hotspot BSSID is in
the BLE advertisement precisely so the phone can join without a GATT read — if a PSK
were needed, it would be in the GATT payload.

**We already confirmed this** (E1): `scripts/join-setup-ap.sh` joined the hotspot without
any PSK and retrieved the full `eureka_info` from `https://192.168.255.249:8443`.

Implication for Piste 3: the "HTTPS setup API needs the BLE PSK" concern was a red
herring. The setup API is fully accessible via the open hotspot, and E1/E2 collected
that data. The only thing BLE is still needed for is capturing the exact `fe40` write
format for triggering a provisioning command (Piste 3), which requires the Android HCI
snoop or Frida approach regardless.

### F15. BLE `fe40` write format — no public documentation; HCI snoop is the shortest path

No researcher has published the exact byte format of `WriteValue` calls to the
`0xfea0`/`0xfe40` setup characteristics. Two acquisition methods:

**Android HCI snoop log (fastest, no jailbreak):**
1. Developer Options → *Bluetooth HCI snoop log* → ON.
2. Run through a provisioning attempt with the Google Home app.
3. `adb pull /data/misc/bluetooth/logs/btsnoop_hci.log`.
4. Wireshark → filter `btatt` → every `WriteValue` to `fe40`/`7c6160` is in plaintext.

**Frida (same result, real-time):**
```bash
frida -U -n "com.google.android.apps.chromecast.app" \
  -l frida-ble-hook.js
# hook android.bluetooth.BluetoothGatt.writeCharacteristic
```

Wi-Fi PSK delivery: the Wi-Fi password is **RSA-2048-encrypted with the device's
`public_key` from `eureka_info`** before being POSTed to the setup API. We already have
the public key (E3, `1a7c6160`). The POST endpoint is `/setup/connect_wifi`; the
exact protobuf encoding is the remaining unknown.

### Piste 8 — LD_PRELOAD audio intercept (post-root, production Track B path)

Once Track B1 delivers a root shell:

```bash
# Cross-compile the hook for ARMv7
arm-linux-gnueabi-gcc -shared -fPIC -nostartfiles -Os \
  -o libassist_hook.so reconstruction/payload/libassist_hook.c

# Start the Pi listener (runs Whisper → LLM → TTS, receives PCM from Mini)
python3 reconstruction/agent/pi_whisper_server.py &

# Deploy to the Mini (from root shell via reverse shell)
cp libassist_hook.so /factory_setting/
sed -i 's|exec cast_shell|LD_PRELOAD=/factory_setting/libassist_hook.so exec cast_shell|' \
  /etc/init.d/S80cast_shell
reboot
```

After reboot the Mini speaks to your Pi instead of Google's cloud. The only change
visible externally is that `embeddedassistant.googleapis.com` traffic disappears and a
UDP stream appears on the LAN.

Also of interest for this piste: `factory_store` (mtd10) contains the device's unique
TLS client cert and private key. **Dump this first** (`nanddump -f /tmp/fstore.bin /dev/mtd10`)
before any write operations — losing it permanently breaks Cast device authentication.
