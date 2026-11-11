# Findings — ghostcli.cloud (2026-10-27)

Scope: public client bundle + documented API surface of a **third-party** service, using a
key the user owns. No vulnerability exploitation, no attack tooling. Evidence in `evidence/`,
artifacts in `target/web/`.

Authority: `shipped-artifact` (public JS chunks), `external-service` (public HTTP GET on
documented routes with the user's own key), `analyst-inference` (business model, upstream).

## F1 — `GET /v1/models` is unauthenticated and over-discloses · Medium · observed
No `Authorization` header required (`ev`: `04-models-api.json`, reproduced with a deliberately
invalid key and with no key at all). Each of the 7 entries returns 30 fields:

- `base_instructions` — 485 chars of their system prompt, per model.
- `priority` — internal queue ranks 0…4 and 103/104 for the `[1m]` variants.
- `truncation_policy`, `minimal_client_version`, `shell_type`, `apply_patch_tool_type`,
  `use_responses_lite`, `supports_*` flags — internal client-emulation profile.
- Hidden slug `z-ai/glm-5.3` plus `z-ai/glm-5.3[1m]`, absent from `/docs`.

Consequence: anyone can fingerprint the proxy's internal routing, read its system prompt, and
learn which third-party model is being resold. No key, no rate limit, no plan needed.

## F2 — Silent model substitution and capability downgrade · Medium · observed
Verified per-id via `GET /v1/models/{id}` (evidence `06-bundle-surface.json` for the alias map
recovered from the bundle, resolution confirmed live):

| Requested | Returns | Note |
|---|---|---|
| `claude-haiku-4-5`, `-20251001`, `claude-3-5-haiku-latest`, `claude-3-5-haiku-20241022`, `claude-3-haiku-20240307` | `claude-sonnet-5` | every Haiku name bills/behaves as Sonnet |
| `claude-opus-5-5[1m]`, `claude-sonnet-5[1m]`, `claude-fable-5.1[1m]` | same id, `context_window: 256000` | `[1m]` accepted then stripped — no 1M |
| `gpt-6-astra` | `gpt-6-astra[1m]` | base id is upgraded to the 1M variant |
| `claude-opus-5`, `claude-fable-5`, `claude-fable-5-1` | `claude-opus-5-5`, `claude-fable-5.1` | benign forward alias |
| `claude-opus-4-5`, `claude-sonnet-4-5`, `gpt-5*`, `gemini-*`, `deepseek-*`, `kimi-*`, `grok-*` | 404 `not_found_error` | old configs break loudly |

The `[1m]` case is the worst: a client asks for 1M context, gets 200, silently works at 256k.

## F3 — Hidden Z.ai model behind an OpenAI-looking alias · Medium · observed+inferred
Bundle: `t.filter(e=>"zai"!==e.provider)` removes Z.ai from the web UI, and
`p={"gpt-5.6-sol":"z-ai/glm-5.3", ...}` maps an OpenAI-shaped name onto it.
Live: `GET /v1/models/gpt-5.6-sol` → `z-ai/glm-5.3[1m]`. Marketing says "4 frontier models";
the API serves 5, one of them a different vendor under an OpenAI-style id.

## F4 — `/v1/models/{id}` cannot address the GLM model · Low · observed
`z-ai/glm-5.3` in the path yields `{"code":"unknown_route"}` — the route is single-segment, so
the slash-bearing id is unreachable. Any OpenAI-SDK `models.retrieve("z-ai/glm-5.3")` fails
while the same id works fine in `model:` of a completion request.

## F5 — Auth check ordering + IP echo · Low · observed
`POST /v1/messages` returns `403 permission_error` ("Network for IP 2a01:… is not authorized
for this key") before the API-entitlement check would fire (402). The body echoes the caller's
public IPv6. Minor, but it confirms the authorization decision path order.

## F6 — Client bundle is clean · Informational · observed
28 chunks, 1.8 MB, scanned for `sk-`, `pk_live/pk_test`, JWT `eyJ`, `whsec_`, `AKIA`, `ghp_`,
`AIza`: **zero hits** (`06-bundle-surface.json → secret_scan`). Server-side work stays
server-side. Vendor fingerprint: Next.js (REA `vendor_fingerprint`, high confidence,
`web-bundle` record).

Public client surface (`/api/*`, recovered by grep + confirmed by REA `endpoint_candidate`
observations): `auth/login`, `auth/logout`, `me`, `config`, `plan`, `subscription`, `usage`,
`keys`, `keys/ips`, `chats`, `chat`, `chat/upload`, `affiliate`, `pay/whop/check`, `uptime`.
External browser call: `https://ipapi.co/json/` (client-side IP lookup that prefills the
key-IP authorization form).

## F10 — Streaming is buffered, not incremental · Medium · observed (`08-inference-probes.json`)
With `stream: true`, a 229-character answer arrives as **one** text delta at the end: first
delta at 6.05 s = whole answer (sonnet), 18.11 s (astra). Claude Code, Codex and pi therefore
show nothing, then a burst. Any timeout tuned for token streaming will look like a hang.

## F11 — Effective throughput is low · Informational · observed
Same 57-token answer, 2 rounds, median, measured from response headers to body end
(thinking time included, it cannot be separated while buffered):

| model | headers | total | effective tok/s |
|---|---|---|---|
| `claude-sonnet-5` | 2.18 s | 6.73 s | 11.8–13.4 |
| `claude-fable-5.1` | 2.17 s | 6.88 s | 10.8–13.8 |
| `gpt-6-astra[1m]` | 0.22 s | 14.14 s | 3.2–5.7 |
| `claude-opus-5-5` | 2.19 s | 23.15 s | 1.9–3.0 |

Opus 5.5 is the slowest model in the catalog, ~4× slower than Sonnet 5.

## F12 — GLM 5.3 is down on every surface · High (for that model) · observed
`z-ai/glm-5.3`, `z-ai/glm-5.3[1m]` and its alias `gpt-5.6-sol` return **502 after 57–67 s** on
`/v1/messages`, `/v1/chat/completions` and `/v1/responses`. Streaming returns only `: ping`
keepalives, never content or usage. The one model that carries the "cheap 1M context" value
proposition does not answer.

## F13 — Image input is broken · Medium · observed
Every model advertises `input_modalities: ["text","image"]`. Sending an 8×8 PNG returns
**502** on all three surfaces (anthropic `image` block, OpenAI `image_url` data URI, Responses
`input_image`), while a text-only request to the same model and endpoint returns 200.

## F14 — Tool calling works · Informational · observed
Through pi with the bash tool: `claude-sonnet-5` ran a command and reported its output;
`gpt-6-astra[1m]` returned `ZX9-7712`, a token only obtainable by executing the command.

## F15 — The API key is not bound to the account that owns it · Middle · confirmed
With a valid `gc_session` cookie for user **5599** (plan `free`, `api.active: false`), `/api/keys`
returns `{"keys": [], "max": 0}` and `/api/usage` is zero for every day — yet the `gcli_` key
infers normally. The key is therefore not attached to the account shown by the session: whatever
entitlement gates `/v1`, it is not the plan on the dashboard. Read the other way, this means a
key can keep working after the account believing it owns that key has no subscription and no
keys on file. (`evidence/10-perf-and-account.json`, `account_surface_ro`)

## F16 — The effort lever is exposed and dominates latency · Middle · confirmed
`output_config.effort` on `/v1/messages` and `reasoning_effort` on `/v1/chat/completions` both
change wall-clock time by 5–20×. Three samples per setting, seconds:

| effort | sonnet-5 | astra[1m] |
|---|---|---|
| none | 65.17 / 2.72 / 3.17 | 7.87 / 8.35 / 18.51 |
| low | 3.11 / 2.96 / 3.09 | 2.49 / 2.72 / 2.82 |
| medium | 3.28 / 4.32 / 2.93 | 2.33 / 3.48 / 4.50 |
| high | 8.92 / 7.07 / 18.10 | 7.08 / 7.52 / 9.75 |
| xhigh | — | 6.38 / 6.77 / 9.18 |

`effort: none` on sonnet-5 produced one 65 s outlier — the same stall signature as F18. Claude
**thinking blocks** barely move (9.76 s disabled vs 10.28 s with `budget_tokens: 1024`), so the
lever that matters is effort, not thinking. Through pi, pinning thinking `off` cut wall-clock from
6.4–7.0 s to 4.2–4.5 s. (`evidence/10-perf-and-account.json`, `effort_lever`)

## F17 — The injected system prompt is obeyed but never counted · Middle · confirmed
A ~2 100-token `system` is honoured ("reply only in French" → `Bonjour`; "answer BANANA" →
`BANANA`) while the response reports `input_tokens: 15`. User-message accounting is accurate by
contrast: ~3 395 padded tokens in, `input_tokens: 3395`. So user content is metered honestly and
the proxy's own prompt is free — the same asymmetry F41 shows on `countTokens`.

## F18 — Capacity is shared and fails in Portuguese · Informational · confirmed
`429 overloaded_error` with a Portuguese body (*"O upstream está congestionado"*), plus a single
65 s stall on an otherwise 3 s path. The error surface is the operator's own, not Anthropic's, and
it discloses that the upstream is pooled. Consistent with F29.

## F19 — CSP discloses third-party browser endpoints · Info · observed
The `Content-Security-Policy` header names hosts the app talks to, including two non-obvious
infrastructure endpoints — a Cloud Run service (`mpc2-prod-29-is5qnl632q-uc.a.run.app`) and an AWS
ECS host (`5z-2b6b7616f94640c2840d1841e1ac24c3.ecs.us-east-1.on.aws`) — plus `ipapi.co`,
`api.ipify.org` and `api6.ipify.org` for client IP discovery. `x-powered-by: Next.js`. The
read-only account surface is otherwise small and tidy: `/api/keys` → `{"keys": [], "max": 0}`,
`/api/usage` all-zero, `/api/keys/ips` → `404 ipKeyNotFound`, `/api/chats` → one chat (`18369`).
(`evidence/09-authenticated-surface.json`, `evidence/10-perf-and-account.json`)

## F7 — No image generation, no embeddings, no audio · Informational · observed
`POST /v1/images/generations`, `/v1/images/edits`, `/v1/images`, `/v1/audio/speech`,
`/v1/embeddings` → 404 `unknown_route`. Every catalog model declares
`input_modalities: ["text","image"]` and no output-modality field: vision **in**, text **out**.

## F8 — Latency · observed (`05-latency.json`)
IPv6: TCP 8–11 ms, TLS 27–35 ms, TTFB **167 ms** median. IPv4: TCP 13 ms, TLS 44 ms,
TTFB **172 ms** median, p90 228 ms, max 272 ms, σ 37 ms over 20 samples.
Vendor's own monitor reports 108 ms; their `/api/uptime` gives 99.93 % (24 h), 99.61 % (7 d),
98.89 % (30 d). ~120 ms of the TTFB is server-side app routing, not network. Inference numbers
separately in F10/F11 — the IP gate that blocked completions earlier in the session cleared
mid-run (`08-inference-probes.json`).

## F9 — Business model · inferred, not verified
Bundle strings describe quota as "cota no formato Max 20x (sessão de 5h + teto semanal)" and
Enterprise as "Authorized proxying and reselling … no risk of ban". Consistent with pooling
real Anthropic/OpenAI subscription seats and re-exposing them, rather than paying per token.
Risk to a buyer: the service's continuity depends on the upstream vendor not objecting;
`/api/keys/ips` authorizes by ASN, so the "authorized IP" is really your network provider.

## Explicitly not tested (out of authorized scope)
- `GET /api/keys/ips?keyId=` and `DELETE /api/keys/ips?id=` take a client-supplied id; whether
  the server enforces ownership is **unknown**. Vendor should confirm; we did not probe it.
- Whether the key-IP authorization trusts the client-supplied IP from `ipapi.co` vs the socket
  peer. Unknown, not probed.
- Rate-limit enforcement (`rpm`, `maxIps`) — untestable, calls are refused before metering.

## F20 — Client routes recovered statically (REA) · Info · observed
REA `analyze-javascript-application` over 18 sources: 278 691 AST nodes, 494 modules, 1 873
findings, 0 parse failures. Routes view yields 12 client routes including `/admin` and
`/afiliados`, which `robots.txt` and the sitemap never mention
(`evidence/11-javascript-routes.json`).

## F21 — Authorization ids are client-supplied on every key operation · Medium · observed (static)
`fetch(\`/api/keys?id=${e}\`,{method:"DELETE"})`, `fetch(\`/api/keys/ips?keyId=${e}\`)`,
`fetch(\`/api/keys/ips?id=${e.id}\`,{method:"DELETE"})`. Ownership can only come from a server-side
`WHERE user_id =`. Client-supplied integers are brute-forceable. Not tested — see
`notes/weakpoints.md` W1.

## F22 — Admin UI is client-gated · Low · observed (static)
`x.isAdmin && p.push({href:"/admin",label:"Admin"})`, and `enterprise` panels derived from
`me.user.plan`. Hiding a button is not authorization; `/api/me` also returns `isAdmin` to any
logged-in client. Not tested — W2.

## F23 — Defensive code that is actually correct · Info · observed (static)
Login's `next` parameter is validated with `/^\/(?![/\\])/` (blocks `//host` and `/\host`); the
syntax highlighter escapes `&`, `<`, `>` before `dangerouslySetInnerHTML`; sensitive reads use
`cache:"no-store"`; no secrets and no auth material in `localStorage`/`sessionStorage`.

## F24 — Full client API contract recovered · Info · observed (static)
19 endpoints with methods, bodies and the response fields the UI trusts
(`evidence/12-api-contract.json`, `notes/api-contract.md`). Every tenant identifier —
`keyId`, `id`, `chatId`, `reference` — is client-supplied. Seven inputs need server-side
ownership/entitlement checks; the list is ranked in the note.

## F25 — Payment confirmation rests on a URL parameter · High (hypothesis) · observed (static)
`POST /api/pay/whop/check` is called with `{reference: new URLSearchParams(location.search).get("ref")}`
and the UI treats `{"paid":true}` in the reply as a completed purchase. If that decision is not
derived from Whop's signed webhook or a server-to-server lookup, a subscription can be obtained by
choosing a URL parameter. Not tested — testing it means attempting to obtain a paid plan without
paying.

## F26 — Quota enforcement exists on the chat path, not visibly on /v1 · Low · observed (static)
The chat handler distinguishes `402` (quota reached) from `403` (locked model), so plan limits are
enforced there — which sharpens F15: the unentitled key still inferring on `/v1/messages` looks like
an unenforced path, not a policy choice.

## F27 — Domain is 18 days old, no MX, no DMARC, no CAA, no security.txt · Medium · confirmed (public record)
Registered 2026-10-09 11:35 UTC at GoDaddy, expires 2027-10-09, Cloudflare DNS, DNSSEC unsigned.
Zero MX records (the domain cannot receive mail), SPF `~all` softfail, no `_dmarc` → `From:
@ghostcli.cloud` is spoofable, on a service that emails API-key IP authorization codes via
MailerSend. `/.well-known/security.txt` and `/security.txt` → 404: no security contact at all.
The advertised "98.89 % 30-day uptime" (F8) cannot be true on an 18-day-old domain.

## F28 — Infrastructure chain · Info · confirmed (public record)
Cloudflare (ray MRS, h3) → Next.js app router → **Cloud Run** `mpc2-prod-29-…a.run.app` (29th prod
revision) + **AWS ECS** `…ecs.us-east-1.on.aws`; IP discovery via `ipapi.co`/`api.ipify.org`/
`api6.ipify.org`; codes via **MailerSend**; attribution via Cloudflare Insights + Facebook pixel +
**utmify.com.br**. The Brazilian attribution platform plus pt-BR UI, the Portuguese 429 body and
`/afiliados` identify a Brazilian infoproduct operation. Details: `notes/infrastructure.md`.

## F29 — Unit economics prove pooled-seat resale · High (inference) · confirmed by measurement
"Unlimited messages" with Opus-class models at $31.10/mo is below API list cost for a single long
session. Measured behaviour (1.9–13.8 tok/s F11, buffered streaming F10, 429 "upstream
congestionado" F18, 60 s→502 on the hidden GLM F12, priority 103/104 pools F1, silent Haiku→Sonnet
substitution F2, unbilled injected system prompt F17) is the signature of shared subscription
capacity resold through a proxy, not dedicated API access. Consequence: the service is one upstream
policy change from termination, and paid plans carry that risk.

## F30 — Anti-bot layer is a self-hosted fingerprinting captcha · Medium (privacy) · confirmed (static)
`/gc.js` — 122 280 B, **unminified**, MIT, `FCaptcha 1.21.0`, served from the apex. Collects fonts,
WebGL, screen, deviceMemory, hardwareConcurrency, timezone, language, permissions, mediaDevices,
touch/sensor data, **form typing analysis** and automation markers, then POSTs it to `/gc/api/verify`
bound to a SHA-256 PoW. Wired as `x-gc-verify` on `/api/chat` and `capToken` on login. **No consent
banner anywhere.** LGPD/GDPR exposure. Details: `notes/captcha-review.md`.

## F31 — PoW is advisory by construction · Low · confirmed (static)
`target = "0".repeat(4)` ≈ 65 536 hashes; `minTime: 500` is enforced in the browser; if
`/gc/challenge` fails the client sets `this.challenge = {nonce: random, difficulty: 4}` itself; and
`powTiming{duration, iterations}` is submitted *outside* the committed `signalsHash` ("not part of
committed signals" in their own comment). A proof the client chooses the nonce for, and rates itself.

## F32 — The front door has a fingerprint scanner, the API has no door · Info · rhetorical
FCaptcha profiles typing rhythm and headless markers while `/v1/models` hands `base_instructions`,
priority tiers and a hidden model to anyone unauthenticated (F1). The security investment is on the
wrong surface.

## F33 — `navigator.webdriver` is weighted at half the pass threshold · Medium · confirmed (static)
Published weights in `/gc.js`: pass requires `score < 0.5`; `navigator.webdriver === true` scores
**0.25**. With `plugins===0` (0.05) and `innerEqualsOuter` (0.05) a plainly automated browser still
scores 0.35 and passes unless a second class of heuristic fires. The rest of the model is pointer
kinematics (no path 0.35, tremor 0.12, velocity variance 0.10, straight-line 0.08). "Vision AI agent"
detection is not present in the code. `notes/captcha-deep.md` §3.

## F34 — Anti-bot control fails open · Medium (High if server accepts) · confirmed (static)
Three client paths downgrade a security verdict to the trusting side: `serverUrl` unset, any network
error inside `_verify` ("Server unavailable, using client-side verification"), and challenge-fetch
failure (`_generateLocalChallenge()` with `local: true`, self-chosen `challengeId`/`prefix`/
`difficulty`). The fallback returns `btoa(JSON.stringify({timestamp, score, id}))` — **unsigned
base64 asserting its own score**. Paths 2–3 are one flaky `/gc` away, and this deployment has
measured 65 s stalls and 429s (F18). Whether the server accepts that token shape is untested.

## F35 — Captcha monkey-patches `HTMLFormElement.prototype.submit` globally · Low · confirmed (static)
`_interceptFormSubmit()` replaces the platform prototype method at document level and never restores
it; a `submit` listener is also bound with `capture:true`. Composition hazard with any other library
touching the same method, plus an integrity side effect from a widget that is supposed to only observe.

## F36 — Keystroke privacy is handled honestly; the fingerprint is not consented · Info/Medium
Credit: textarea keystroke stats are scoped to `TEXTAREA` on purpose, and document-level typing
"modality" records only *how* text arrived — no values, no key codes ("never what or where… including
password inputs a password manager fills"). Remaining collection: pointer kinematics, typing cadence,
fonts, WebGL renderer, `deviceMemory`, `hardwareConcurrency`, timezone, media devices, sensors — sent
to `/gc/api/verify` and `/gc/api/score`, i.e. stored and profiled. No consent surface, no retention
statement. LGPD/GDPR.

## F37 — Documentation contradicts measured behaviour in 9 of 12 claims · Medium · confirmed
`notes/api-docs-vs-reality.md`. Headlines: docs promise token-by-token streaming (measured: one
delta), a `429` meaning "free daily limit" (measured: `overloaded_error`, Portuguese upstream-
congestion body), a `402` add-on gate (never fired for a key bound to no account), "1M context"
(then their own Claude Code snippet sets `CLAUDE_CODE_DISABLE_1M_CONTEXT=1`), "4 best models" (5 in
catalogue + 1 hidden), "key never leaves your browser" (server returns it), "someone else's key will
not work" (the key in use does), and "verified end to end" (GLM and vision 502 on every surface).

## F38 — Catalogue routes are open while inference is gated · Low · confirmed
`GET /v1/models`, `/v1/models/{id}` and `/v1beta/models` need no key, no add-on, and return
`base_instructions`, priority tiers, hidden models and pt-BR operator-written descriptions
("O cavalo de batalha do código agêntico…"), i.e. hand-curated metadata. The authorization boundary
sits on the wrong side of the catalogue.

## F39 — Internal deployment counters exposed in public responses · Info · confirmed
`priority: 103/104` per model, `version: "001"` per Gemini model, `mpc2-prod-29` visible in the CSP.
Free fingerprinting of the deploy lineage for anyone watching.

## F40 — Cloudflare blocks the stdlib Python UA with a non-API error · Low · confirmed
`urllib.request`'s default `Python-urllib/3.13` → `HTTP 403`, body `"error code: 1010"` (Cloudflare
browser-integrity, 17 bytes, not JSON, not in the documented error table) on `/v1beta/models` and the
inference routes. `python-requests`, `curl`, Anthropic/OpenAI/Google SDK UAs and a browser UA all get
200. Evidence: `evidence/13-gemini-surface.json`.

## F41 — `countTokens` ignores the system prompt · Medium · confirmed
`POST /v1beta/models/claude-sonnet-5:countTokens` with a 4 000-character `systemInstruction` returns
`totalTokens: 12`; without it, `totalTokens: 12`. **Delta 0.** Independent confirmation of F17 on a
second surface: the injected system prompt is inserted after metering. Any client pre-flighting
context with `countTokens` will under-count by the size of the proxy's own prompt.

## F42 — Streaming is buffered on all four dialects · Medium · confirmed
`streamGenerateContent?alt=sse` returns **2 frames**: frame 0 carries the entire 246-character answer,
frame 1 carries `finishReason:"STOP"` + `usageMetadata`. Extends F10 to the Gemini shape, so the
behaviour is in the proxy core, not in one adapter.

## F43 — Format translation is a costume over one upstream · Info · confirmed
A Gemini-shaped `generateContent` response returns `functionCall.id: "toolu_1793096724411_1"` — an
Anthropic tool-use id — plus `modelVersion: "claude-sonnet-5"` and `responseId: "gem_…"`. Tool calling
does work on all four dialects, and the ids betray the single upstream behind them.

## F44 — Content Security Policy is strict; no `unsafe-eval` or `unsafe-inline` in app chunks · Info · confirmed (static)
The CSP header (`default-src 'self'; script-src 'self' ...`) blocks external script execution and inline code unless explicitly allowed for specific trusted CDNs (Facebook, Cloudflare Insights). Static analysis of all 28 client chunks confirms zero usage of `eval()`, `new Function()`, or string-based `setTimeout/setInterval`. The application relies on standard DOM manipulation and Next.js hydration, which significantly reduces the risk of reflected XSS via script injection.

## F45 — The Cloudflare UA gate breaks default programmatic clients · Low · confirmed client-side
Reproduced from a real integration (a local voice assistant calling `/v1/messages` as its
LLM backend). `urllib.request` with its default `Python-urllib/3.15` UA receives
**`403 Forbidden`**; the same request from `curl` or from urllib with any custom
`User-Agent` returns **`200`**. Independent confirmation of **F40** from the client side:
`/v1/models` is open, but every documented inference route is behind a UA filter that no
SDK advertises. Anyone building against this API hits an opaque 403 on their first call
and has no way to distinguish it from the IP allowlist (F5) or a quota error. Mitigation
for integrators: always set an explicit UA.
