# The anti-bot layer: FCaptcha 1.21.0 (self-hosted)

`/gc.js` — 122 280 bytes, served **unminified with comments**, MIT header, `version: '1.21.0'`.
If you want to know what GhostCLI actually runs, this file is more forthcoming than any of their
pages. It is also the only anti-abuse control in the product, which makes it the interesting one.

## What it is

A homegrown "Open Source CAPTCHA" whose own header claims it *"detects bots, vision AI agents,
headless browsers and automation frameworks through behavioral analysis, environmental
fingerprinting and temporal signals."* Wired in by module 88364 of the chat bundle:

```js
FCaptcha.configure({ serverUrl: "/gc" })
const t = await FCaptcha.execute("ghostcli", { action: "chat", minTime: 500 })
fetch("/api/chat", { headers: { "x-gc-verify": t.token }, … })
```
and on login the same token is sent as `capToken` in the JSON body.

## Protocol, as implemented

```
1. GET  /gc/challenge            → {nonce, prefix, difficulty}      (fallback if it fails: client picks)
2. prefix = `${Date.now()}:${Math.random().toString(36).substr(2)}` (client-generated)
3. target = "0".repeat(difficulty)          difficulty default 4   ← 4 hex nibbles ≈ 65 536 hashes
4. pow    = sha256(`${prefix}:${nonce}`) until it starts with target
5. collect signals → JSON → sha256 → signalsHash  (PoW bound to the signals)
6. POST /gc/api/verify {signals, powSolution, signalsJson, signalsHash, powTiming}
7. ← {token}  → sent as x-gc-verify
```

`_clientSideVerify(signals)` runs instead of any server call when `serverUrl` is unset — and also on
any network error. It returns `btoa(JSON.stringify({timestamp, score, id}))`: an unsigned token that
asserts its own score.

## Signals it harvests — this is the part that matters

```
behavioral     mouse/keyboard timing, click patterns, form typing analysis
environmental  fonts (9 refs), WebGLRenderingContext, screen{w,h}, deviceMemory,
               hardwareConcurrency, navigator.platform/languages/connection/permissions,
               mediaDevices, touch events (115 refs), sensor data, rAF consistency
temporal       performance.now() deltas (33 refs), timezone, Intl.DateTimeFormat
meta           userAgent, viewport, timezone, siteKey, challengeNonce, timestamp
detection      webdriver (28), headless, CDP (11), puppeteer, playwright, selenium
```

That is a browser fingerprint **plus keystroke dynamics**, transmitted to a self-hosted endpoint and
retained server-side to score you. Under GDPR and LGPD that is personal data processing that needs
a lawful basis, a consent surface and a DPIA — and the site has **no consent banner**: those strings
appear only inside legal/docs prose, never as an interstitial. Every visitor is fingerprinted before
they click anything, including the login page.

## Findings

**C1 — PoW cost is decorative (Medium).** `difficulty: 4` means a SHA-256 hex prefix of four zero
nibbles: ~65 536 hashes, milliseconds on any device. Their own `minTime: 500` is a *client-side*
floor — the browser promises to spend 500 ms doing it. Nothing in the shipped code shows the server
enforcing either number.

**C2 — The challenge falls back to client-chosen values (Medium).** A normal run fetches
`GET /gc/api/pow/challenge?siteKey=…`, so the nonce really is server-issued and the design is sound.
But on any non-200 or exception the client calls `_generateLocalChallenge()` and proceeds with a
self-chosen `challengeId`, `prefix` and `difficulty: 4`, flagged `local: true`. Whether that flag is
honoured is a server question I did not test. Full detail: `notes/captcha-deep.md` §5.

**C3 — Solve time is self-reported and uncommitted (Low).** `powTiming{duration, iterations,
difficulty}` is submitted *outside* `signalsHash`. The source comments say so outright: "not part of
committed signals". A "too fast to be human" signal that the client reports about itself is not a
signal.

**C4 — Forkable by design (Low/Info).** MIT, unminified, version pinned at 1.21.0 and shipped from
the apex domain. Any future CVE or published heuristic list applies to whatever they deploy, and the
integrator version string is a free fingerprint of *them* to anyone watching.

None of this is an existence proof of bypass — that requires sending forged verifications, which I
have not done and will not. What it is, is a redesign brief: bind the PoW to a server-issued nonce,
verify difficulty server-side, drop the client-reported timing, and get consent for the fingerprint.

## The irony worth putting in the report

They built a captcha that profiles fingerprints, typing rhythm and browser automation markers...
and shipped a public `/v1/models` endpoint that hands over `base_instructions`, internal `priority`
tiers and a hidden upstream model without any authentication at all (F1). The front door has a
fingerprint scanner; the API has no door.
