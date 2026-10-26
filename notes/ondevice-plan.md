# On-device plan: replacing the assistant client with our own

Goal (as stated): API-based LLM, no local host, running *on* the Mini. That means
the device itself must call our endpoints. This file is the concrete plan for that,
and the honest odds.

## Where we stand

Known, from the device itself (`notes/findings.md` E1, E3):

| Fact | Value |
| --- | --- |
| Model | `Google Home Mini`, `manufacturer: Google Inc.` |
| Internal product name | **`mushroom`** |
| SoC (inferred from `mushroom`) | Marvell Armada 1500 Mini Plus **88DE3006**, dual Cortex-A7, ARMv7 LE |
| Firmware | `3.75.468362`, `release_track: stable-channel` |
| Weave device id | empty — never joined Google's Weave fabric |
| Capabilities | `assistant_supported: true`, `ble_supported`, `hotspot_supported`, `https_setup_supported` |

## The decisive question

**Can the device execute code we supply?**

Published H0A research answers the shape of this, and it is not what I first
assumed:

- The boot chain **does verify**: `postbootloader` RSA/SHA256-verifies the kernel, and
  the rootfs is SquashFS + dm-verity. So **Google's own images cannot be patched in
  place** — a modified `kernel` or `rootfs` simply will not boot.
- There is **no UART and no JTAG** on this board (the debug pads are BGA), and
  micro-USB is power-only. So the usual "read the boot log, then poke U-Boot" route
  is unavailable.
- What *is* available is an **unsigned, writable partition**: `cache` (mtd8) is
  YAFFS2 and sits outside the verified chain. The published exploit lands there.

So the question is not "is boot signed" (it is) but **"is the kernel still vulnerable
in a way that lets an unverified partition take over ring 0"** — and the only way to
answer that for *our* unit is to read the kernel off the NAND.

## Route: NAND, not signatures

Ordered, cheapest decisive step first. Step 1 requires no exploit at all.

1. **Dump the NAND** (NandBug interposer: ICE40HX1K + FT2232H, soldered to the
   TC58NVG1S3HBAI6, ~256 MB in under a minute).
2. **Read the kernel version** off mtd6 in the dump. That single string decides
   whether the YAFFS2 bug applies at all. If the kernel is patched, stop — no further
   effort is justified, go to the fallbacks below.
3. **Check ECC/format handling** before trusting anything: BCH poly `0x8003`,
   strength 48, 90 B OOB per page, and the first 2080 bytes of each page are
   nibble-swapped before decoding. `scripts/nand-decode.py` does this and parses the
   partitions, so the dump is usable rather than a wall of hex.
4. **Craft the poisoned `cache` image** and write it back, then boot. Expect roughly
   5–10 % success per attempt (heap spray); power-cycle on failure.
5. **Root shell.** From here we run *our* code, not Google's.

## Once rooted — what to replace

Because the rootfs stays verified and read-only, the strategy is **do not patch, run
our own client** from a writable partition (`factory_setting` is remounted rw+exec by
the published chain).

First, the protocol the device already speaks — this is the part worth knowing, since
it means we do not have to invent a wire format:

| Piece | Value |
| --- | --- |
| Transport | gRPC over HTTPS to `embeddedassistant.googleapis.com` |
| Protobuf | `google.assistant.embedded.v1alpha2`, service `Assistant` |
| Methods | `Converse`, `ConverseStream` (bidirectional streaming) |
| Input audio | raw **S16LE, 16 kHz, mono**, in `ConverseRequest.audio_in` |
| Output audio | **24 kHz S16LE** in `ConverseResponse.audio_out` |
| Auth | OAuth token derived from the device identity (the RSA key + X.509 cert we already have) |
| Hotword | on-device (small NN), before any audio leaves the box |

Three ways in, cheapest first:

1. **Hostname redirect + our CA.** Patch the resolved host in `cast_shell` /
   `libassistant` to our endpoint and install our certificate in the trust store. Least
   code, but needs a writable trust store — awkward with a verity rootfs.
2. **Our own client, their audio.** Run a binary that opens the mic via ALSA, streams
   to our endpoint speaking the public `v1alpha2` proto, and plays back
   `audio_out`. Keeps the hardware abstraction the vendor already debugged, drops
   Google entirely. **Preferred.**
3. **Full replacement of `cast_shell`.** Most control, loses Cast, most work.

The resulting flow needs nothing on the LAN:

```
Mini mic ──► ConverseStream ──► our endpoint ──► STT API ──► your LLM API (+ MCP tools)
Mini speaker ◄── audio_out ◄── our endpoint ◄── TTS API ◄──┘
```

This satisfies the "API, no host" requirement literally: the device is the only
thing in the path, and the LLM/MCP live behind an HTTP API.

## If the kernel is patched — the fallbacks

1. **Drop-in PCB (Piste 6).** ESP32-S3 + XMOS board that fits the same shell, reuses
   the speaker and mic-mute button. Real microphone, no boot verification, ESPHome →
   Assist → Wyoming → Whisper/LLM/Piper. ~$85. **This is the option that actually
   ships**, and it can be made API-only (no local host) by pointing the pipeline at
   hosted STT/TTS endpoints.
2. **Stock Mini as Cast speaker.** Works today (`scripts/cast_play.py` validated); the
   agent runs anywhere else.
3. **Accept Google's cloud.** Not compatible with the goal — the agent is inside
   Google's infrastructure with no extension point.

## Firmware acquisition, for reference

| Route | Gets us | Cost |
| --- | --- | --- |
| NAND dump (NandBug) | full flash, all partitions, restorable | solder an FPGA interposer |
| NAND clip/programmer | same, less capable | cheaper, no live decode |
| Lab AP + provisioning (`scripts/lab-ap.sh`) | endpoint map, DNS behaviour, maybe OTA images | destroys the BLE setup surface; needs TLS not pinned |

The lab AP route is worth doing **after** the BLE work only, and it answers a
different question (what does it call, and is the updater TLS-pinned) rather than
"can we run our code".

## Readiness

Verified end-to-end on a synthetic image, so analysis runs the moment real bytes land:

```bash
scripts/fw-analyze.sh target/<mushroom-image>.bin     # regions, extract, analyze
scripts/ghidra-headless.sh target/<region> 0x8000     # ARM:LE:32:v7, all functions
```

First strings/xrefs to chase once a rootfs or binary is open:

| Target | Look for |
| --- | --- |
| assistant client | `embeddedassistant`, `ConverseStream`, `v1alpha2`, `assistant.googleapis.com` |
| auth | `oauth2`, `token`, `jwt`, `device_certificate` |
| trust store | `ca-bundle`, `.pem`, `/etc/ssl`, `pinning` |
| hotword | `hotword`, `speex`, `libhotword` |
| update | `ota`, `update_engine`, `payload`, `signature`, `delta` |
| boot | `verified`, `dm-verity`, `avb`, `otp`, `efuse` |
