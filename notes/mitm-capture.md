# Capturing the Mini's web traffic with mitmproxy

How we watch the HTTP(S) traffic of the Home Mini (and of the phone running the Google
Home app) **once the device is on the home network**. This complements
`scripts/lab-ap.sh`, which owns the Mini's gateway on a laptop AP and records DNS + pcap
but cannot see inside TLS.

It is using mitmproxy with the leaked emudhra CA. Redirecting all tools.google.com, *.googleapis.com and mtalk.google.com to mitmproxy on dns.

1. **AdGuard rewrites.** AdGuard Home (the LAN resolver) has DNS rewrites pointing the
   target domains — e.g. `*.googleapis.com` — at `10.10.10.12`. The router hijacks every
   port-53 packet to AdGuard, so a client with a hard-coded resolver (`8.8.8.8`) still
   gets the rewritten answer. Hosts that use DoH/DoT or literal IPs are **not** caught.
2. **Reverse mode with a placeholder upstream.** mitmproxy runs two reverse listeners
   whose upstream is `placeholder.invalid`. The real destination is decided per request
   by the addon (below). `connection_strategy=lazy` stops mitmproxy from connecting to
   the placeholder before the request is known; `keep_host_header=true` sends the
   original `Host` upstream.
3. **`forward_by_host.py`** — the whole addon:

   ```python
   def request(flow):
       host = flow.request.host_header or flow.client_conn.sni
       if not host:
           return
       name, _, port = host.partition(":")
       flow.request.host = name
       flow.request.port = int(port) if port else (443 if flow.request.scheme == "https" else 80)
   ```

   It turns the reverse proxy into a transparent-by-name proxy: whatever name the client
   asked for (Host header, else SNI) is where the request goes.
4. **Avoiding a DNS loop.** When mitmproxy resolves `x.googleapis.com` for the upstream
   connection it must get Google's real address, not the AdGuard rewrite pointing back
   at itself. Setting compose `dns:` does not help, because the router hijacks all
   port-53 traffic to AdGuard. So a `dnsproxy` sidecar shares mitmproxy's network
   namespace, listens on `127.0.0.1:53` and forwards over DoH to `1.1.1.1` / `9.9.9.9`;
   `resolv.conf` (mounted over `/etc/resolv.conf`) points at it.
5. **Viewing.** mitmweb's UI (8081) 

Other settings: `block_global=false` is required because IPv6 clients arrive from
public addresses; this is only safe while the router blocks inbound IPv6 to the proxy's
address (checked from an external host).

## Results

Capture: a Google Home Mini booting on the home network, about 7 minutes, 30 flows from
the device. The real capture time is deliberately not recorded (see sanitization).

**This is not the `GoogleHome4983` target** from `findings.md` (unprovisioned, 3.75.468362,
`FR`). It is a second Mini that is already set up and in daily use: same hardware
(`mushroom`, board `joplin-b4`), current firmware 3.78.540761, `de-DE`. Treat results as
"what a current-firmware Mini does"; they apply to the target only where stated.

| Evidence | What |
| --- | --- |
| `evidence/mitm-boot-mini2.flows` | sanitized mitmproxy dump (open with `mitmweb -r` / `mitmproxy -r`) |
| `evidence/mitm-boot-mini2-decoded.txt` | index, headers, schema-less protobuf decode of every body |

`[n]` below = flow index in those files.

**Sanitization** (`scripts/mitm-sanitize.py`, decode with `scripts/mitm-decode.py`):

- **Dropped flows:** the original dump also held two curl test requests and a Firefox
  request carrying the operator's Google session cookies.
- **Blanked headers:** OAuth bearer, API keys, Cast/Nest device cert chain, device JWT,
  request signatures, cookies, and the binary server trailers (`endpoint-load-metrics-bin`,
  `grpc-server-stats-bin`, `pcx-high-bwd-bin`).
- **Identifiers** are replaced in place by same-length placeholders, so gRPC/protobuf framing
  still decodes: `DEVID1`, `SERIAL1`, `MAC1`, `IP1`, `SSID1`, `GAIA1/2`, `ANDROIDID1`,
  `GCMSECRET1`, `FCM1/2`, `OAUTH1..6`, `UTTID1..4`, opaque tokens and server-generated ids
  (`TOKEN…`), and the per-user Knowledge Graph entity lists (`ENTITY…`).
- **Request ids:** every UUID (e.g. `X-Speech-RequestId`, which Google logs server-side) is
  replaced by a fresh random UUID, consistently across flows. The exception is the public
  Omaha appid `{6117439b-…}`.
- **Time:** all absolute time is shifted by one random offset (30–365 days, either
  direction, random seconds). The offset is never printed or stored. This covers flow and
  connection timestamps, `Date`/`Expires` headers, Omaha `x-daynum`/`daystart`, and epoch
  values in text and inside protobuf varints/fixed64. **Relative timing between flows is
  exact; the calendar dates in the files are fake.**
- **Addresses and certificates:** client addresses are rewritten to `2001:db8::/32`, Google
  front-end and proxy addresses to `192.0.2.0/24`. Stored TLS certificates are dropped,
  because their validity dates would bound the capture time.
- **Verification:** the script re-scans its output and refuses on any surviving identifier,
  token, or time value from the original capture window. The result was additionally
  grepped for every original value by hand.
- **Kept:** room name, locale, time zone, firmware versions, public URLs.
- **Not hidden by the files:** the git commit time and the dated notes in `findings.md`
  still reveal the capture day.

### R1. TLS interception of the device works — every redirected host was decrypted

All 30 device flows are TLS 1.3 with the proxy's certificate and full plaintext
headers/bodies, including the Assistant gRPC streams. So the device accepts the emudhra-issued
leaf for `*.googleapis.com` and `tools.google.com`. This contradicts the earlier assumption
(F13, `ondevice-plan.md`) that reading the Assistant traffic needs root on the device, at
least for current firmware.

Exception: `lycraservice-pa.googleapis.com` [3,4,7,10,22,25,27,29]. The device→proxy leg
decrypts fine, but the proxy→Google leg is refused (`http2_handshake_failed`), so the device
never gets an answer and retries with back-off (t+60 s, 177 s, 225 s, 416 s). Likely cause:
Google requires the device's own mTLS client certificate on that host, which the proxy cannot
present. **Unverified.**

### R2. Versions of the captured Mini: 3.78.540761, current stable

| Source | Value |
| --- | --- |
| Omaha update check [0] | `updater: GoogleTvEureka`, `board: joplin-b4`, `hardware_class: Google Home Mini`, `version: 540761`, `track: stable-channel`, appid `{6117439b-1508-4065-9e69-2a006d8f7730}` |
| Omaha response [0] | `updatecheck.status: noupdate` |
| Lycra TechnicalInfoTrait [7], experiments [15] | system build `3.78.540761` |
| HTTP user agent [5,9,17] | `Chrome/92.0.4515.0 … CrKey/1.56.500000 DeviceType/SmartSpeaker` |
| Assistant client info [1,6,8] | `libassistant/cast/production`, libassistant `16.60.15.918100692`, hardware rev `1184-KNS1` |
| gRPC stacks | Assistant: `grpc-c++/1.79.0-dev`; Lycra: `grpc-c++/1.54.0-dev` (two separate gRPC builds, probably two processes) |

Consequences:
- 3.78.540761 is the current stable build for this hardware (`noupdate`). The target
  (3.75.468362) is older, so its kernel/Chrome findings (F7, F16) are unaffected.
- Chrome 92.0.4515.0 / CrKey 1.56.500000 is the **current-firmware** reference for Piste 9;
  the target's own Chrome version is still unmeasured.
- F18: the update check is plain Omaha JSON with no signature or auth header. Sending it
  with the target's `version: 468362` (from a laptop, not the device) might return a
  `payload_url` without risking an auto-update of the target. **Untested idea.**

### R3. The Assistant protocol is Google-internal "S3", not EmbeddedAssistant v1alpha2

F13 assumed `google.assistant.embedded.v1alpha2.EmbeddedAssistant/Assist`. The capture shows:

| Host | gRPC method | Use | Result |
| --- | --- | --- | --- |
| `assistant-s3-pa.googleapis.com` | `speech.s3.S3StubbyClientConnectorService/S3Bidi` | all Assistant traffic (`assistant-settings`, `assistant-voiceless` sessions) [6,8,11,12,14,21] | `grpc-status 0` |
| `embeddedassistant.googleapis.com` | `google.internal.speech.S3OnePlatform/Assistant` | Voice Match enrollment check (`enrollment-fetcher` / `voicematch-enrollment`) [1] | ok: "No new audio but has new voiceprint version" |
| `embeddedassistant.googleapis.com` | `speech.s3.S3StubbyClientConnectorService/S3Bidi` | same enrollment fetch [2,13,18,20] | `grpc-status 12` "GRPC target method can't be resolved", retried 4× |

Envelope of every S3 request (protobuf field numbers from the decode, names inferred):
- field 1: session type (`assistant-settings`, `assistant-voiceless`, `enrollment-fetcher`);
- 293000: locale `de-DE`, plus **one OAuth token per linked user**, scope
  `https://www.googleapis.com/auth/androidathome` (two users on this device → two tokens,
  two Gaia IDs in the settings response);
- 293100: audio config, `fixed32` = **16000.0** (sample rate);
- 294000: client identity: `qsb-android`, `voice-search`, UA `GoogleChirp/1.0.1 …`,
  `cast/mushroom/Google Home Mini/Google Inc.`, `com.google.android.apps.chirp/mushroom/prod`,
  device class `small-bluetooth-speaker-class-device`, ~17 experiment IDs;
- Auth on the wire: `authorization: Bearer ya29…` plus a fixed `x-goog-api-key` (same key for
  every Assistant call, so it is baked into the firmware).

No utterance was spoken during the capture, so there is no audio stream in it.

### R4. Boot handshake: the device declares its client-op capabilities

At boot the device sends `libassistant.BOOTUP` [8] with `query_settings` (`device_type: joplin`,
`has_mic_switch`, `build_number 918100692`, `sound_sensing_version 3`) and an
`assistant.api.DeviceCapabilities` block. That block lists the **client ops** the cloud can
order the device to run. This is the contract a local replacement agent would have to speak:

| Namespace | Ops |
| --- | --- |
| speech / UI | `tts.OUTPUT`, `led.SET_LED_ANIMATION`, `device.UPDATE_VOLUME`, `device.STOP`, `device.ENABLE_SIMPLE_STOP`, `mic.UPDATE` |
| conversation | `client.SEND_CONVERSATION_REQUEST`, `client.RECONNECT`, `conversation.ENTER_LIVE_MODE` / `EXIT_LIVE_MODE`, `execution.WAIT` |
| timers / alarms | `timer.{CREATE,ADD_TIME_TO,MUTATE,PAUSE,RESUME,RESET,RING,STOP,REMOVE}_TIMER`, `alarm.{CREATE,MUTATE,REMOVE,RING,SNOOZE,SNOOZE_LOCAL,STOP}_ALARM`, `scheduler.{SET,REMOVE,RESTORE,OVERRIDE_FALLBACK}` |
| media / multi-device | `media.SET_FOCUS` / `CLEAR_FOCUS`, `multi_device.CIRCULATE_CONVERSATION_CONTEXT` / `CIRCULATE_MDE_STATE`, `common_clock.SET_SOURCE` |
| device / config | `device.GET_SETTINGS`, `device.MODIFY_SETTING`, `device.GET_DEVICE_TIME`, `configuration.PROCESS_SETTINGS`, `configuration.UPDATE_EXPERIMENTS` |
| other | `notification.*`, `bluetooth.{CONNECT,DISCONNECT,DISCOVERY,UNPAIR}`, `call.*`, `sdk_actions.EXECUTE` (handler `device_control_cast_builtin`), `chirp_action_script.EXECUTE`, `feedback.UPLOAD_CRASH_REPORT` |

Scheduler kinds announced: `alarm`, `reminder`, `sleep_timer`, `timer`, `baby_shusher`, `haunt_my_house`.

The server replies with client ops the same way:
- `configuration.PROCESS_SETTINGS` [6,8,21] carries an `assistant.api.settings.DeviceConfig`:
  locale, time zone `Europe/Berlin`, per-user settings for both Gaia IDs, and two downloadable
  model URLs:
  - TTS voice: `https://dl.google.com/dl/assistant/client/home/resources/pak/3/tts/1.46.0/resources_tts_joplin_de-DE_VOICE141.pak`
  - hotword model: `https://dl.google.com/dl/assistant/client/home/resources/pak/experimental/de_maxp_sens/2.7/resources_hotword.pak`
- `common_clock.SET_SOURCE` [11].

Implication: since TLS to `assistant-s3-pa` is interceptable (R1), a network-side agent that
answers `S3Bidi` with its own client ops (e.g. `tts.OUTPUT`) is conceivable **without
rooting the device**. Blockers: the S3 schema is undocumented (we only have tag numbers), and
the stream is driven by the device's own OAuth tokens. **Not attempted.**

### R5. Device settings sync: Nest "Lycra" traits

`nest.cloud.platform.lycra.LycraService/Get` and `/Update` [3,4,7,10,…] sync these device
traits: `a11y_trait`, `alarm_volume_settings`, `assistant_volume_settings`,
`do_not_disturb_settings`, `eureka_info_settings`, `night_mode_settings`,
`preview_program_settings`, `privacy_settings`, `technical_info`,
`touch_interaction_presence_detection_settings`, `user_eq_settings`,
`user_interface_settings`, `voice_interaction_presence_detection_settings`, `wifi_settings`,
`fcm_trait`.
- `TechnicalInfoTrait` [7] uploads the Wi-Fi SSID, LAN IP, MAC, build, channel and country.
- `EurekaInfoSettingsTrait` [10] uploads the device name and a time-zone table.
- Auth is device identity, not user OAuth: `x-goog-nest-cert` / `-cert-chain` (Cast Root CA →
  "Chromecast ICA 7 (Audio Assist 2)" → device cert), plus a device-signed JWT in
  `x-goog-nest-jwt` (audience `https://www.googleapis.com/oauth2/v3/token`, issuer
  `<device-id>@cast-chirp…`).

### R6. Other endpoints seen

| Flow | Endpoint | Notes |
| --- | --- | --- |
| [9] | `home-devices.googleapis.com/v1/micstate/update` | body `08 01`; request signed with `cast-cert`, `cast-signature`, `cast-jwt`, `cast-serial-num` headers |
| [5,19,23,26,28] | `gcm-http.googleapis.com/c2dm/register3` | legacy GCM registration (`AidLogin` auth). Google answers `301 Error=DEPRECATED_ENDPOINT`; the device keeps retrying |
| [15] | `www.googleapis.com/experimentsandconfigs/v1/getExperimentsAndConfigs` | experiment flags for `com.google.ghp_cpp` / `com.google.ghp_common`, release `fopo_release_2026_w10_RC05` |
| [16] | `play.googleapis.com/log` | telemetry upload (log sources `ANDROID_BACKUP`, `BATTERY_STATS`, `SMART_SETUP`, `TRON` in the response) |
| [17] | `storage.googleapis.com/…/aogh.html` | **Home Assistant's Local Home SDK app** (`VERSION 2.1.6`, `HA-Cloud-Version` header). The Mini runs it as a local-fulfilment hub: it finds HA by mDNS `_home-assistant._tcp` and forwards IDENTIFY / QUERY / EXECUTE / REACHABLE_DEVICES intents as `POST /api/webhook/<id>` to HA on the LAN. So a device-to-HA local path already exists. |
| [24] | `ajax.googleapis.com/…/shaka-player/4.15.56/…?google_cast_bg=true` | media player library for the Cast receiver |

### Not covered by this capture

- **No `mtalk.google.com`**, although it is in the DNS rewrites. FCM's persistent channel
  normally uses TCP 5228 (fallback 443), and the proxy only listens on 80/443. Whether the
  device fell back to 443 and failed, or used a hard-coded address, is unknown.
- No OAuth token mint (`oauth2/v3/token`) appears; the device presumably reused cached tokens.
  A capture after the token expiry (~1 h) or a factory reset would show the JWT exchange.
- No `dl.google.com` traffic: that host is not in the rewrite list, and the model packs were
  likely cached already.
- No voice query, so the audio leg of `S3Bidi` (framing, codec) is still unobserved. Next
  capture: say a wake word plus a short query while recording.
- Protobuf field names are unknown. Everything above is tag numbers plus string context.
