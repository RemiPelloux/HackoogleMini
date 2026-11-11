# GhostCLI — security submission (draft, ready to file)

**Submitted by** Rémi Pelloux · pellouxremi@gmail.com
**Target** `https://ghostcli.cloud` — API `/v1/*`, web `/dashboard`
**Method** read-only: unauthenticated catalogue reads, source review of publicly served bundles and
`/gc.js`, one authenticated `GET` on the reporter's own account. **No state-changing request, no
enumeration of other tenants' identifiers, no third-party infrastructure was touched.**

Severity is CVSS-3.1-informed but expressed as impact, since the vendor's own scale is unknown.

---

## GH-01 · Unauthenticated model catalogue leaks proxy internals — Medium (5.3)

`GET /v1/models` needs no key and returns, per model, `base_instructions` (485 characters of the
proxy's own system prompt), `priority` tiers (103/104), `truncation_policy`, `minimal_client_version`,
`shell_type`, `apply_patch_tool_type`, and `z-ai/glm-5.3` — a model their UI deliberately hides via
`t.filter(e => "zai" !== e.provider)` and sells separately as `gpt-5.6-sol`.

**Impact** Mapping of internal architecture, upstream routing priority and undisclosed inventory,
without any credential. Competitive and social-engineering value; also proof that the "Enterprise
1M-context" tier is a queue priority on a hidden upstream.

**Fix** Require auth on `/v1/models`; return only `id`, `context_length`, `max_output_tokens`.
Never ship `base_instructions` in a catalogue response.

---

## GH-02 · Payment confirmation derived from a client-supplied reference — High, unverified

```js
// chunks_app_dashboard_page-*.js
fetch("/api/pay/whop/check", { method:"POST",
  body: JSON.stringify({ reference: new URLSearchParams(location.search).get("ref") }) })
if (res.paid) { refreshPlan(); hideCheckout(); history.replaceState({}, "", "/dashboard") }
```

The client takes `?ref=` **from the URL bar**, posts it, and treats `{"paid":true}` as a completed
purchase. If the server derives `paid` from that reference rather than from Whop's signed webhook or
a server-to-server lookup, a paid plan is obtained by editing a URL.

**Why I did not verify it** Doing so requires obtaining a paid plan without paying — that is fraud,
not testing. It is filed as a hypothesis with the client code as evidence.

**Fix** Treat the Whop webhook (signature-verified, replay-protected) as the only source of truth;
`/pay/whop/check` must only *read* already-recorded state for the authenticated session's own
reference, never infer it.

---

## GH-03 · Hidden upstream model is dead on every surface — High (7.5, availability)

`z-ai/glm-5.3`, its `[1m]` variant, and the alias sold as `gpt-5.6-sol` return **502 after 57–67 s**
on `/v1/messages`, `/v1/chat/completions` and `/v1/responses`; the streaming variant emits only
`: ping` for over a minute. Reproduced repeatedly. Every other model answers in 2–23 s.

**Impact** A model is sold that cannot serve a single token, with a client-visible hang of ~60 s.

**Fix** Remove or alias it out of the catalogue; health-check per model before advertising.

---

## GH-04 · Image input 502s on all three API dialects — Medium (5.3)

An 8×8 PNG returns 502 on `/v1/messages` (`image` block), `/v1/chat/completions` (`image_url` data
URI) and `/v1/responses` (`input_image`), while the same request without the image returns 200 on the
same model. Vision is advertised in `/v1/models`.

**Fix** Reject unsupported content types with `400` and a reason, and stop advertising the capability.

---

## GH-05 · Streaming is fully buffered — Medium (4.3)

Measured across all five models: the first SSE `content_block_delta` carries the **entire** answer
(229 characters in one frame at t=6.05 s for sonnet-5, 18.11 s for astra). `stream_deltas: 1` on
every run. Clients get no partial output, so streaming is cosmetic.

**Fix** Emit upstream deltas as they arrive; do not accumulate before forwarding.

---

## GH-06 · API key not bound to the account that uses it — Medium (5.4)

The supplied `gcli_` key works for inference while the owning session reports `plan: "free"`,
`api.active: false`, `GET /api/keys → {"keys": [], "max": 0}` and `/api/usage` all-zero. The key
cannot be rotated, metered or rate-limited by the account using it, and an IP-allowlist change by
its real owner flipped an identical request from `403` to `200` mid-session.

**Impact** Entitlement and metering are decoupled from identity; usage by such keys is invisible to
the account that appears to be using them.

**Fix** Bind keys to a tenant, enforce entitlement at inference time, and surface key-level usage.

---

## GH-07 · Anti-bot layer collects browser fingerprints without consent — Medium (privacy, LGPD/GDPR)

`/gc.js` (FCaptcha 1.21.0, self-hosted at `/gc`) collects fonts, WebGL, screen metrics,
`deviceMemory`, `hardwareConcurrency`, timezone, language, permissions, media devices, touch and
sensor data, **form typing analysis**, and automation markers — then POSTs the lot to
`/gc/api/verify` bound to a SHA-256 proof of work. There is no consent surface anywhere in the app.

**Fix** Consent or remove the fingerprinting; publish the retention period; document it in the
privacy policy.

---

## GH-08 · Proof of work is advisory by construction — Low

`difficulty: 4` (≈65 536 hashes, milliseconds), enforced client-side by `minTime: 500`; when
`/gc/challenge` fails the client **chooses its own nonce and difficulty**; and
`powTiming{duration, iterations}` is submitted outside the committed `signalsHash`, i.e. the client
reports its own solve speed. Details in the note accompanying this report.

**Fix** Server-issued single-use nonce, server-side difficulty verification, drop the self-reported
timing.

---

## GH-09 · Domain hygiene — Low

Registered 2026-10-09 (18 days old at filing) with **no MX record**, **no DMARC**, SPF `~all`,
no CAA, DNSSEC unsigned, `/.well-known/security.txt` → 404. Mail is outbound only via MailerSend —
the same channel that carries API-key IP authorisation codes. Anyone can spoof
`From: @ghostcli.cloud`, and there is no published security contact.

**Fix** Publish `_dmarc` with `p=reject`, CAA for the issuing CAs, a `security.txt`, and an
abuse@ mailbox.

## GH-10 · Token counting ignores the system prompt — Medium (billing integrity)

`POST /v1beta/models/claude-sonnet-5:countTokens` returns `totalTokens: 12` **with** a 4 000-character
`systemInstruction` and `totalTokens: 12` without it. `usage.input_tokens` on `/v1/messages` behaves
the same way (2 100-token system prompt → `input_tokens: 15`). The proxy's injected system prompt is
metered at zero, and any client pre-flighting context with `countTokens` will under-count by its full
size. Counts are also inconsistent between endpoints (`12` vs `promptTokenCount: 18` for a
seven-token prompt).

**Fix** Count the assembled prompt, including injected instructions, and use one tokenizer across
`countTokens`, `usage` and the quota accounting.

---

## Out of scope / not performed

IDOR probing (`/api/keys/ips?keyId=`, `/api/chats/{id}`, `POST /api/chat` with a foreign `chatId`),
CSRF testing, rate-limit and auth-bypass attempts, subdomain enumeration, port scanning, and any
request to the Cloud Run / AWS hosts named in the CSP. Those need written authorization naming
assets and test accounts, which is what I would ask for before continuing.

## Artefacts

`notes/findings.md` (F1–F33) · `notes/security-review.md` · `notes/weakpoints.md` ·
`notes/api-contract.md` · `notes/infrastructure.md` · `notes/captcha-review.md` ·
`evidence/01–12` (JSON) · `REPORT.md`.
