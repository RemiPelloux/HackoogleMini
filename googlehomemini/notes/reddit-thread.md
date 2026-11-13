# Reddit thread — r/hardwarehacking

**Title:** Trying to get shell on Google Home Mini gen 1 via Cast MITM (Chrome 92, no hardware mods) — stuck on TLS cert verification blocking JS execution. What am I missing?

---

**Body:**

I've been trying to replace Google Assistant on a Google Home Mini gen 1 (H0A) with a local LLM that calls MCP servers. No hardware modifications — purely software and network. The device is mine, fully provisioned, sitting on my home LAN.

Here's everything I've done and where I'm stuck. Would love input from anyone who's touched cast_shell, Chrome 92 internals, or IoT MITM.

---

## Device

| Field | Value |
|---|---|
| Device | Google Home Mini gen 1 (H0A, "mushroom"), Marvell Armada 1500 Mini Plus, ARMv7 |
| Firmware | `cast_build_revision` 3.78.540761 |
| Chrome | **92.0.4515.0** (the branch point — never received any stable-channel security patches) |
| OTA | `has_update: false`, `new_version: 0.0.0.0` — never updated since manufacture |
| Manufacture date | 2018-09-05 (from device TLS cert `notBefore`) |
| IP | 192.168.1.29 |
| Attacker | Laptop at 192.168.1.24, same LAN |

The device runs `cast_shell`, a custom Chromium build. All Cast receiver apps (the HTML/JS pages that handle LOAD/PLAY commands) run inside `cast_shell`'s renderer. Getting JS execution in that renderer = game over.

---

## Why Chrome 92.0.4515.0 matters

This is the **unpatched** branch point. Between this and the final stable 92.0.4515.107, Google fixed:

- **CVE-2021-30563** — Type confusion in V8 (HIGH, full renderer compromise with working JS)
- **CVE-2021-30578** — Uninitialized use in Media (HIGH)
- 20+ other HIGH-severity bugs

Both CVEs are **present and unpatched** on this device. But they both need JS execution inside `cast_shell`'s renderer. That's the primitive I'm trying to establish.

**Magellan (CVE-2018-20346/505/506, SQLite FTS3 heap corruption)** is also applicable — the device predates Chrome 71 (the fix). Same dependency: needs JS in the renderer.

---

## Attack surface

The device exposes:
- **Port 8008** — Cast HTTP API (no auth for GET, 401 on most POST)
- **Port 8009** — Cast control (TLS, this is where Cast sender protocol runs)
- **Port 8443** — HTTPS setup API (401 on most endpoints)
- **Port 9000** — mTLS Audio Assist (device-specific client cert required, dead end without root)

The Cast control protocol on port 8009 lets any sender on the LAN send **LAUNCH** (load a receiver app by AppID) and **LOAD** (load media into the active receiver). Zero authentication.

---

## What I've built

Full ARP MITM stack:

```
arpspoof -i wlp0s20f3 -t 192.168.1.29 192.168.1.1   (both directions)
dnsmasq on port 5354 — returns 192.168.1.24 for all *.google.com / *.googleapis.com
iptables PREROUTING (src=192.168.1.29):
  UDP/TCP 53  → 5354   (DNS hijack)
  TCP 80      → 8080   (HTTP intercept)
  TCP 443     → 4443   (HTTPS MITM)
```

**Port 8080**: Python HTTP server serving probe.html, silence.mp3, captions.vtt, fake Cast registry JSON.

**Port 4443**: Python SSL server (self-signed cert, CN=clients3.google.com, SANs *.google.com / *.googleapis.com) — when it gets `/cast/v2/receiver?appId=X`, returns fake registry JSON pointing to `http://192.168.1.24:8080/probe.html`.

---

## What works

**DNS hijack** ✅ — dnsmasq intercepts 70–90 UDP queries per boot from the device. Returns 192.168.1.24 for all Google domains.

**HTTP intercept** ✅ — The device immediately hits our port 8080 on boot:
```
HEAD /generate_204 HTTP/1.1   (connectivitycheck.gstatic.com connectivity check)
```
We now serve `204 No Content` correctly. The device makes HTTP requests through us — the port 80→8080 redirect works.

**TCP 443 redirect** ✅ — iptables PREROUTING counts show 2 TCP 443 connections per boot reach port 4443.

**Cast media loading** ✅ — Sending a Cast LOAD command via pychromecast with `contentId: http://192.168.1.24:8080/silence.mp3` results in `playerState: PLAYING`. The device fetches arbitrary audio and WebVTT caption files from our HTTP server:
```
GET /silence.mp3 HTTP/1.1    → 200, plays
GET /captions.vtt HTTP/1.1   → 200, fetched
```

---

## What doesn't work

### HTTPS registry intercept — blocked by TLS cert verification

The Cast registry fetch (`clients3.google.com/cast/v2/receiver?appId=CC1AD845`) happens **at boot** only, not during LAUNCH. The receiver HTML URL is locally cached; during a normal LAUNCH cycle cast_shell makes zero HTTPS connections.

After two power cycles with the full MITM active:
- TCP 443 connections reach our port 4443 ✅
- `mitm_hits.log` stays **empty** — no HTTP request ever arrives at the handler ❌
- TLS handshake **fails** — cast_shell validates against Chrome's CA bundle and rejects our self-signed cert

The cert works fine from openssl s_client (with the expected self-signed warning), but cast_shell treats it as a hard failure. No HTTP fallback observed on port 8080 for the registry path.

### WebVTT XSS — filtered by Chrome's allowlist shadow DOM

Injected `<img onerror=...>`, `<script>`, HTML breakout into WebVTT cue text. Chrome's WebVTT renderer uses a strict allowlist (`<b>`, `<i>`, `<u>`, `<c>`, `<v>`, `<ruby>`, `<rt>`) and strips everything else before DOM insertion. No callback received.

### HLS LOAD — playlist fetched, segments fail

Sent LOAD with `contentType: application/x-mpegURL`. The M3U8 playlist gets fetched every few seconds (retrying). The TS segment is not decoded by the Default Media Receiver. LOAD stays in LOAD_FAILED state.

### Port 9000 — mTLS, dead end

```
depth=1 O=Google Inc, OU=Cast, CN=Chromecast ICA 7 (Audio Assist 2)
depth=0 O=Google Inc, OU=Cast, CN=L39IRU
```
Requires a client certificate from `factory_store` (mtd10, YAFFS2 ro). Cannot extract without shell access — circular dependency.

---

## The core problem

To get JS in `cast_shell`'s renderer, I need one of:

1. **Change the cached receiver URL** — requires intercepting the registry fetch (HTTPS, cert rejected)
2. **Exploit something reachable via the HTTP media pipeline** — cast_shell fetches arbitrary audio/VTT from our server over HTTP
3. **Find another path to code execution** — Cast protocol, local HTTP API, mDNS/SSDP, etc.

---

## Specific questions

**Q1 — HTTP fallback for the registry?**
Does cast_shell on firmware ~3.78 have any HTTP fallback when HTTPS fails for `clients3.google.com`? We're watching port 8080 carefully but have never seen `GET /cast/v2/receiver?...` arrive there.

**Q2 — Media parser CVE deliverable over HTTP?**
Cast LOAD with the Default Media Receiver accepts MP4, WebM, OGG, FLAC, WAV, DASH (MPD), HLS (M3U8). Chrome 92.0.4515.0's media pipeline is completely unpatched. CVE-2021-30578 ("Uninitialized Use in Media") is specifically a media pipeline bug. Has anyone weaponised this, or know the exact component/file affected? The Chromium patch commit would be enough to understand the bug class.

**Q3 — cast_shell restart without power cycle?**
The registry fetch only happens at boot (or cast daemon restart). Can the cast daemon be restarted via the local HTTP API (port 8008) or the Cast control protocol without a full device reboot? I tried `POST /setup/reboot` but got no response (possibly blocked by subnet routing at the time).

**Q4 — Unknown AppID forces fresh registry lookup?**
If I send `LAUNCH {"appId": "DEADBEEF"}` (an AppID cast_shell has never seen), does cast_shell attempt to fetch the registry for it? If so, and if HTTPS fails, does it fall back to HTTP or just show "app not found"?

**Q5 — DASH MPD as an injection vector?**
DASH manifests are XML. The `<ContentProtection>` element has a `cenc:pssh` and `keyId` that triggers DRM key fetching. Would a crafted MPD cause cast_shell to make additional HTTP requests (key URIs, etc.) that we could intercept? Not looking for XSS — looking for unexpected HTTP connections that could carry a payload.

---

## Repository

Full writeup, all scripts, MITM server code, probe.html, evidence files:
https://github.com/RemiPelloux/HackoogleMini

The end goal is `LD_PRELOAD /factory_setting/libassist_hook.so` on cast_shell to redirect the Google Assistant gRPC stream to a local LLM. Getting there requires root, which requires getting code execution in cast_shell first.

Any pointers appreciated.
