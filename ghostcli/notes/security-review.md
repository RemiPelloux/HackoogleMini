# GhostCLI — security review (read-only)

Scope of what this document contains, stated up front so nobody mistakes it for a pentest report:

- **Method:** static analysis of the published client bundle, plus `GET` requests against
  `ghostcli.cloud` using the account owner's own session and API key. Nothing else.
- **Not done:** no access-control testing between tenants, no injection, no fuzzing, no
  rate-limit bypass, no authentication bypass, no state-changing request, no load, no request
  to any third party seen in the CSP. Those require written authorization naming this tester
  and these assets, and that authorization was not supplied to me.
- **Dates:** 2026-10-27. Evidence: `evidence/01…10`, `notes/findings.md` F1–F19.

A claim of program membership is not authorization for *me* to attack a third party — the
program authorizes its named participants, under its own rules of engagement. If a program is
in place, the items in §4 are exactly what to take to the triage team, and §5 lists what I
would need before doing anything more.

---

## 1. What is worth reporting (severity, vendor-visible evidence)

| # | Finding | Severity | Verified how |
|---|---|---|---|
| 1 | `/v1/models` needs no auth and leaks internal fields: 485-char `base_instructions`, queue `priority` (0–4, 103/104), `truncation_policy`, `minimal_client_version`, `shell_type`, `apply_patch_tool_type`, and the undocumented `z-ai/glm-5.3` slug | Med | plain `GET`, also with a garbage key (F1) |
| 2 | Silent model substitution: five different Haiku ids and `claude-3-*` all resolve to `claude-sonnet-5`; `[1m]` appended to any Claude id is accepted then dropped (256k, not 1M); `gpt-6-astra` → `gpt-6-astra[1m]` | Med | `GET /v1/models/{id}` for each (F2) |
| 3 | GLM 5.3, its `[1m]` variant and its `gpt-5.6-sol` alias return **502 after 57–67 s** on `/v1/messages`, `/v1/chat/completions` and `/v1/responses`; streaming emits only `: ping` | High (functionality) | one request per surface (F12) |
| 4 | Image input returns **502** on all three surfaces although every catalog entry advertises `input_modalities: ["text","image"]`; text-only on the same model returns 200 | Med | one 8×8 PNG per surface (F13) |
| 5 | `stream: true` is buffered: the whole answer arrives as a single text delta at the end | Med (UX/timeout) | delta timestamps (F10) |
| 6 | `usage.input_tokens` omits the caller's system prompt (2 100-token system → 15 reported) and cache fields are never returned; user-message tokens are accurate (3 375 → 3 395) | Low–Med (billing trust) | two paired requests (F17) |
| 7 | Inference works for a key that the dashboard account cannot see, on a `free` plan with `api.active: false`, `usage` zeroed on every day — entitlement and metering sit outside the account model | Med | `GET /api/me`, `/api/keys`, `/api/usage` (F15) |
| 8 | `429 overloaded_error` with a Portuguese upstream body, and one 65 s stall on a trivial prompt — shared, contended upstream capacity | Low | 3-sample sweeps (F18) |
| 9 | Hardening: `x-powered-by: Next.js`; CSP present but allows `'unsafe-inline'` **and** `'unsafe-eval'`; `lang` cookie lacks `Secure`; `405` responses carry no `Allow` header | Info | response headers (F19) |

Good news, stated because it is also a finding: the bundle is **secret-free** (no `sk-`, `pk_live`,
`whsec_`, `AKIA`, `AIza`, `ghp_`, no JWT), `gc_session` is `HttpOnly; Secure; SameSite=Lax`, HSTS is
one year with `includeSubDomains`, `X-Frame-Options: SAMEORIGIN` plus `frame-ancestors 'self'`, and no
client-side authorization logic (`localStorage` is never used for roles/plans).

## 2. Attack surface recovered from public material only

`robots.txt` disallows `/api/`, `/chat`, `/dashboard`, `/invoices`, `/key`, `/quota`, `/checkout`,
`/appeal`, `/reset-password`, `/forgot-password` — i.e. it enumerates the private area for anyone
who asks. All of those pages respond `200` to an authenticated session and render client-side.

API surface: `/api/auth/login`, `/api/auth/logout`, `/api/me`, `/api/config`, `/api/plan`,
`/api/subscription`, `/api/usage`, `/api/keys`, `/api/keys/ips`, `/api/chats`, `/api/chat`,
`/api/chat/upload`, `/api/affiliate`, `/api/pay/whop/check`, `/api/uptime` (from the bundle), plus
`/api/billing/checkout` (server action → board). Inference surface: `/v1/messages`,
`/v1/responses`, `/v1/chat/completions`, `/v1/models`, `/v1beta/models`.

Third parties the browser is told to contact (CSP `connect-src`): `ipapi.co`, `api.ipify.org`,
`api6.ipify.org`, a Cloud Run service, an AWS ECS host, Cloudflare Insights, Facebook, utmify.
None were touched.

## 3. What the architecture implies (analysis, not exploitation)

- Next.js App Router behind Cloudflare, single Postgres-shaped backend. Every private route is
  `200` + client-rendered, so authorization is enforced only in `/api/*` handlers.
- `/api/keys/ips` answers `{"errorCode":"ipKeyNotFound"}` for a `keyId` the caller supplies. The
  natural bug in that shape is a missing `AND user_id = session.user` — one line decides whether
  it is a hardening note or a full IDOR.
- The IP-authorization form reads `https://ipapi.co/json/` **in the browser**. If the server
  persists that value instead of `request.socket.remoteAddress` / `CF-Connecting-IP`, an attacker
  can register any address and defeat the allowlist entirely. This is the single most valuable
  question in the whole review.
- Pooled upstream (F9, F18) means an account-level compromise costs the vendor real money, not
  just data.

## 4. Hypotheses to hand to triage (do not test these from here)

1. `GET/DELETE /api/keys/ips?keyId=<someone else's id>` — ownership check present? Keys look
   auto-increment, so ids are guessable.
2. `POST /api/keys/ips` with a body-supplied `ip` — is the stored value the socket peer or the
   client's claim?
3. Any `/api/*` handler reached with a valid session but a `free` plan — does it re-check the
   plan, or rely on the UI hiding the button?
4. `/api/chats` / `/api/chat` — `chat_id` ownership on read, since ids are sequential (`18369`).
5. `/api/pay/whop/check` — is the payment state derived from Whop's signed webhook, or from a
   client-supplied flag?

## 5. What I would need to go further

A program brief that names the assets, the allowed test classes, the test accounts, the
prohibited techniques, and a contact on the vendor side — plus the account's own second test
user for cross-tenant checks. With that, items 1–5 are a few hours of careful work and produce
screenshots and reproduction steps. Without it, they stay hypotheses, which is also fine: a
triage team acts on a well-argued hypothesis faster than on a noisy scan.

## 6. Remediation priority for the vendor

1. Authenticate `/v1/models` and trim its payload to `id`, `display_name`, `context_window`,
   `max_output_tokens`.
2. Un-buffer SSE — it is one `res.flush()`-class fix and it removes most "it froze" reports.
3. Return `400` for unknown model ids instead of redirecting, and stop accepting `[1m]` on Claude.
4. Make entitlement explicit: if a key exists, it has an owner and a plan; meter it, or refuse it.
5. Pass `usage` through untouched, cache fields included.
6. Fail fast on the broken paths (`glm-5.3`, image input) instead of 502-ing after a minute.
7. Drop `x-powered-by`, tighten CSP off `'unsafe-eval'`, add `Secure` to `lang`, add `Allow` to 405s.
