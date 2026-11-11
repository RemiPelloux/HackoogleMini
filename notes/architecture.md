# Architecture: putting your own agent behind a Google Home Mini

Short version: **you cannot install an LLM on the Mini.** What you *can* do is stop
using Google's agent and drive the device from your own stack. This file explains
what "replace the agent" concretely means, and the three ways to get there, ranked
by effort.

## What is actually inside the box

| Layer | Where it runs | Replaceable? |
| --- | --- | --- |
| Wake word ("Hey Google") | on-device, small DSP/NN model | only with custom firmware |
| Mic array / beamforming | on-device | no |
| Speech-to-text | **Google cloud** | yes — by not using the device's STT at all |
| Assistant / agent logic | **Google cloud** | yes — this is the part you replace with your LLM |
| Text-to-speech | **Google cloud** | yes — replace with local TTS |
| Playback | on-device (Cast receiver) | no need — Cast is an open-ish protocol |

Two consequences:

1. The Mini's microphone audio never reaches your LAN. There is no supported API to
   pull raw mic audio off a Home Mini. Any design that needs the device's own mic
   requires flashing — i.e. Track B in `findings.md`.
2. Playback *is* reachable: the device is a Cast target, so you can push any audio
   URL to it (`scripts/cast_play.py`). That half works with zero risk today.

Hardware reality check:
- **Gen 1 (H0A):** Marvell Armada 1500 Mini Plus 88DE3006, dual Cortex-A7, ~256 MB RAM,
  256 MB Toshiba NAND (TC58NVG1S3HBAI6), Linux 3.8.13.
- **Gen 2 (H2C, "Nest Mini"):** Synaptics AS370 (not Amlogic — Amlogic is in the Nest Hub,
  a different product). Different SoC, different exploit surface entirely.

Neither runs a useful LLM. Any on-device "LLM" would be a ~100M-parameter toy at best.
The intelligence belongs on a machine with a GPU.

## Option A — Mini as speaker only, agent fully off-device  ← recommended

```
        ┌──────────────────── your home server / laptop ────────────────────┐
mic ───►│ wake word (openWakeWord) ──► STT (whisper.cpp / faster-whisper)    │
(ESP32, │        │                                                          │
 ReSpeaker│       ▼                                                          │
 or old │  LLM (local or API) ◄──► MCP client ──► your MCP servers          │
 phone) │        │                                                          │
        │        ▼                                                          │
        │   TTS (Piper) ──► HTTP wav ──► pychromecast ──► Home Mini speaker │
        └──────────────────────────────────────────────────────────────────┘
```

- **Add a microphone.** The Mini's mic is unusable without flashing, so use an
  ESP32-S3 + INMP441, a ReSpeaker 2-Mic HAT on a Pi, or repurpose an old phone.
- **Keep the Mini** purely as a Cast speaker. `scripts/cast_play.py --play <url>`
  already does this.
- **Agent runtime is yours**, so "connect to any MCP" is free: it is just an MCP
  client in your server process. No firmware, no Google account, no cloud.
- If you use Home Assistant, its *Assist* pipeline (Wyoming protocol: wake, STT,
  TTS) implements most of this and supports a local LLM conversation agent plus MCP
  tool calls.
- Time: a weekend. Risk: none. Reversible.

## Option B — keep Google's device agent but bypass it (hybrid)

Autocast-style hack: run a Cast-enabled Google Home under Home Assistant, expose it
as a media player, and generate TTS. You still cannot get its mic, so it is Option A
with extra steps, and it keeps you dependent on Google's provisioning flow.

Verdict: only worth it if you already run Home Assistant and want the Mini to also
answer some Google-native things.

## Option C — replace the firmware (this REA investigation)

Goal: get our own code onto the Mini so the on-device pipeline — wake word, mic,
playback — is ours, with the network leg pointed at your LLM/MCP stack.

Required sequence, each step a potential stop:

1. **Identify the exact model** (gen 1 `H0A` vs gen 2 `H1A`) — changes the SoC and
   therefore everything downstream. See `findings.md` U2.
2. **Obtain a firmware image.** Either an OTA payload, or a flash dump over UART/SPI.
   See `notes/firmware-plan.md`.
3. **Assess verified boot.** If the bootloader only runs signed images, on-device
   replacement is dead and you stop here. This is the real decision point.
4. **Assess the updater.** How does it validate a payload? Where is the signature
   checked? This is where `scripts/fw-analyze.sh` earns its keep.
5. **Only then:** locate the audio pipeline (`cast_shell`, the Assistant client) and
   consider redirecting it.

Do not start at step 5. Most projects that fail on this class of device fail because
they assume step 3 is fine.

## Where MCP fits

MCP is a *backend* concern and is identical in all three options. Your agent runtime
holds N MCP client connections; the device — flashed or not — only ever sees audio
in and audio out. That is worth stating explicitly, because it means **MCP support
never blocks the hardware work.** You can build and debug the whole MCP side today,
with no device, and swap the audio transport afterwards.

Suggested shape:

- one long-lived agent process with an MCP client pool;
- a tool router that maps LLM tool calls to MCP servers;
- a voice loop that is transport-agnostic (`audio_in`, `audio_out` callbacks) so the
  Mini (Cast), a phone, or a browser can be the endpoint;
- latency budget: wake → STT → LLM → TTS → play should stay under ~1.5 s to feel
  like a speaker. That rules out slow cloud round-trips more than it rules out
  local model size.
