# GhostCLI — recon, REA analysis and report

Investigation: 2026-10-27 · target `https://ghostcli.cloud` · key `gcli_-K9CI…ApRA` (user-owned)
Artifacts: `target/web/` (28 public JS chunks, 5 HTML pages) · Evidence: `evidence/`
Method: public-bundle static analysis (REA `analyze-web-bundle` + grep), documented API GETs,
latency measurement. **No vulnerability exploitation was performed** — see §6.

---

## 1. What the service is

A subscription proxy in front of other vendors' frontier models: one `gcli_` key, four wire
formats (Anthropic `/v1/messages`, OpenAI `/v1/responses` + `/v1/chat/completions`, Gemini
`/v1beta/models/{m}:generateContent`). Plans: Pro $31.10, Max $41.10, Enterprise $130,
Teams $295 per 30 days; API/CLI access is a **separate add-on** ($7.90 / 30 d) on top of the
chat plan. Key authorization is by **IP/ASN**, confirmed by an emailed code.

## 2. Model catalog — 5 real models, 7 listed ids

| id | Name | Vendor | Ctx in/out | Plan |
|---|---|---|---|---|
| `claude-opus-5-5` | Claude Opus 5.5 | Anthropic | 256k / 128k | Pro |
| `claude-sonnet-5` | Claude Sonnet 5 | Anthropic | 256k / 128k | Pro |
| `claude-fable-5.1` | Claude Fable 5.1 | Anthropic | 256k / 128k | Max |
| `z-ai/glm-5.3` | GLM 5.3 | **Z.ai — hidden** | 1M / 128k | Pro |
| `gpt-6-astra` | GPT-6 Astra | OpenAI | 1M / 128k | Enterprise |

Plus `z-ai/glm-5.3[1m]` and `gpt-6-astra[1m]` (same models, queue priority 103/104 = slower).
Reference market rates in the bundle: Opus 5/25, Fable 10/50, Sonnet 3/15, Astra 2.5/12,
GLM 0.6/2.2 USD per 1M in–out.

Alias map recovered from the bundle and verified live:
`gpt-5.6-sol→glm-5.3[1m]`, `claude-fable-5|claude-fable-5-1→claude-fable-5.1`,
`claude-opus-5→claude-opus-5-5`, all five Haiku ids → `claude-sonnet-5`.
Everything else 404s (`gpt-5*`, `gpt-4o`, `o3`, `claude-*-4-5`, `gemini-*`, `deepseek-*`,
`kimi-*`, `grok-*`, `qwen*`).

**No image generation**: `/v1/images*`, `/v1/audio/speech`, `/v1/embeddings` all 404
`unknown_route`. Models are vision-**in**, text-**out** only.

## 3. Latency (metadata endpoints, from France)

| Path | TCP | TLS | TTFB med | p90 | max |
|---|---|---|---|---|---|
| IPv6 | 8–11 ms | 27–35 ms | **167 ms** | — | 440 ms |
| IPv4 | 13 ms | 44 ms | **172 ms** | 228 ms | 272 ms |

~120 ms of that is server-side app routing. Vendor monitor claims 108 ms; `/api/uptime` is
public and reports 99.93 % / 99.61 % / 98.89 % (24 h / 7 d / 30 d).

Inference (`evidence/07-latency-inference.json`, `08-inference-probes.json`) — 57-token answer,
2 rounds, median, proxy headers to body end:

| Model | Headers | Total | Effective tok/s | Stream deltas |
|---|---|---|---|---|
| `claude-sonnet-5` | 2.18 s | 6.73 s | 11.8–13.4 | 1 |
| `claude-fable-5.1` | 2.17 s | 6.88 s | 10.8–13.8 | 1 |
| `gpt-6-astra[1m]` | 0.22 s | 14.14 s | 3.2–5.7 | 1 |
| `claude-opus-5-5` | 2.19 s | 23.15 s | 1.9–3.0 | 1 |
| `z-ai/glm-5.3` | — | 57–67 s | **502** | ping only |

Two things dominate: **streaming is fully buffered** (the whole answer arrives as a single
delta, so the CLI looks frozen then dumps text), and Claude models pay a fixed ~2.2 s of proxy
overhead before the upstream is even contacted.

## 4. Access

Earlier in the session every completion returned
`403 permission_error: Network for IP 2a01:cb1d:… is not authorized for this key`. Mid-run the
same request started returning 200, so the network/add-on was enabled on the account. Metadata
reads worked even while completions were blocked, i.e. the key itself was always valid.

## 5. REA pass

`rea analyze-web-bundle` against a headless Chromium target
(`evidence/01-browser-targets.json`, `evidence/03-web-bundle-routes.json`,
`evidence/web-bundle` = full Evidence, 79 KB):

- 21 scripts observed / 21 analyzed, 20 parsed, 0 parse failures, 176 082 AST nodes.
- Vendor fingerprint: **Next.js** (high confidence).
- Route inventory + `endpoint_candidate` observations: `/api/me`, `/api/config`,
  `/api/auth/logout`, `/api/uptime`, external `https://ipapi.co/json/`.
- REA's stated limits: routes are *static candidates*; reachability, permissions and
  server-only routes unverified; REA never executes captured JS.

Combined with direct grep of the same chunks: 15 `/api/*` client routes —
`auth/login`, `auth/logout`, `me`, `config`, `plan`, `subscription`, `usage`, `keys`,
`keys/ips`, `chats`, `chat`, `chat/upload`, `affiliate`, `pay/whop/check`, `uptime`.

**Secret scan of the shipped bundle: clean.** 28 chunks searched for `sk-`, `pk_live/pk_test`,
JWT `eyJ…`, `whsec_`, `AKIA`, `ghp_`, `AIza` → zero hits. Paywall/payment logic is server-side
(Stripe + crypto; `/api/config` returns `{"paymentMethods":{"card":true,"pix":false,"crypto":true}}`).

## 6. Boundaries

GhostCLI is a third party. The key authorizes API calls, not security testing of their
infrastructure — so no scanning, fuzzing, auth-bypass or exploit attempts were run, and none
should be. Two things the vendor should verify themselves are listed as *untested* in
`notes/findings.md` (`/api/keys/ips` ownership enforcement on a client-supplied `keyId`; whether
the IP submitted for authorization is trusted from the browser). Reporting beats exploiting.

## 7. Findings (detail + evidence links in `notes/findings.md`)

| # | Finding | Severity | Basis |
|---|---|---|---|
| F1 | `/v1/models` requires **no auth**, leaks `base_instructions` (system prompt), queue `priority`, truncation policy, hidden GLM slug | Medium | observed |
| F2 | Silent substitution: all Haiku ids → Sonnet 5; `[1m]` on Claude accepted then stripped (256k, not 1M) | Medium | observed |
| F3 | Z.ai GLM 5.3 removed from UI (`filter(provider!=="zai")`), sold as `gpt-5.6-sol`; "4 models" marketed, 5 served | Medium | observed |
| F4 | `/v1/models/{id}` cannot address `z-ai/glm-5.3` (slash → `unknown_route`) | Low | observed |
| F5 | IP-allowlist check (403) precedes entitlement (402); error echoes caller IPv6 | Low | observed |
| F6 | Client bundle secret-free; Next.js; 15 `/api/*` routes | Info | observed |
| F7 | No image/embedding/audio endpoints; vision-in text-out only | Info | observed |
| F8 | TTFB 167–172 ms median, 98.89 % 30-day uptime | Info | observed |
| F10 | `stream:true` is **buffered** — whole answer in one delta, no token streaming | Medium | observed |
| F11 | Throughput 1.9–13.8 tok/s effective; Opus 5.5 slowest (~2.5 tok/s), ~2.2 s fixed proxy overhead on Claude | Info | observed |
| F12 | **GLM 5.3 / `gpt-5.6-sol` returns 502** on all three APIs after ~60 s | High | observed |
| F13 | Image input **502** on all three APIs despite advertised vision | Medium | observed |
| F14 | Tool calling works (bash round-trip verified on both APIs) | Info | observed |
| F15 | The supplied key **is not attached to the account** in the dashboard session: plan `free`, `/api/keys` → `[]`, `max: 0`, usage 0 on every day, yet inference on that key succeeds | Medium | observed |
| F16 | Reasoning effort is the single latency lever: `reasoning_effort`/`output_config.effort` `low` is **3× faster** than default on astra (2.7 s vs 8.4 s) and 3× faster than `high` on sonnet (3.1 s vs 8.9 s) | Info | observed |
| F17 | Caller system prompts are forwarded and obeyed, but **not counted** in `usage.input_tokens` (2 100-token system → 15 reported); user-message tokens are counted accurately (3 375 → 3 395) | Low | observed |
| F18 | `429 overloaded_error` with a Portuguese body ("O upstream está congestionado") — shared, contended upstream capacity, consistent with F9 | Low | observed |
| F19 | CSP discloses two non-obvious third-party browser endpoints (a Cloud Run service and an AWS ECS host) plus `ipapi.co`/`ipify` for IP discovery; `x-powered-by: Next.js`; CSP allows `'unsafe-inline'` + `'unsafe-eval'` | Info | observed |
| F9 | Quota shaped like "Max 20x (5 h session + weekly cap)", Enterprise sells "authorized proxying and reselling" → pooled upstream subscription seats | Info | inferred |

## 8. Practical recommendation

- `claude-sonnet-5` is the only model that is fast enough to drive an agent loop: ~6.7 s for
  a 57-token answer, tools working. `claude-fable-5.1` matches it and is the better buy if you
  are on Max. `claude-opus-5-5` costs 3.5× the wall-clock for the same output.
- **Do not rely on `z-ai/glm-5.3` / `gpt-5.6-sol`**: 502 on every surface.
- **No vision**, despite the catalog. **No incremental streaming** — expect freeze-then-burst.
- Treat it as a convenience proxy, not an API of record: hidden/renamed models, silent
  substitution, a 502-prone cheap tier, and a business model (F9) that can vanish if the
  upstream vendor objects. Keep direct vendor access for anything production.

## 9. pi integration (`~/.pi/agent/models.json`)

Provider `ghostcli`, key resolved at request time from `~/.config/ghostcli/env` (mode 600):

```json
"ghostcli": {
  "name": "GhostCLI",
  "baseUrl": "https://ghostcli.cloud",
  "api": "anthropic-messages",
  "apiKey": "!. \"$HOME/.config/ghostcli/env\" && printf %s \"$GHOSTCLI_API_KEY\"",
  "models": [ /* per-model api + baseUrl overrides */ ]
}
```

| Model id in pi | api | ctx | max out |
|---|---|---|---|
| `claude-opus-5-5` | anthropic-messages | 256k | 128k |
| `claude-fable-5.1` | anthropic-messages | 256k | 128k |
| `claude-sonnet-5` | anthropic-messages | 256k | 128k |
| `gpt-6-astra[1m]` | openai-completions (`/v1`) | 1M | 128k |
| `z-ai/glm-5.3[1m]` | openai-completions (`/v1`) | 1M | 128k |

Verified with `pi --list-models` (all five listed) and `pi -p` on both API paths — see F14.
Costs are the catalog's reference market rates, not what the subscription bills.

`settings.json` pins `modelThinkingLevels` to `off` for all five: measured 4.2–4.5 s vs
6.4–7.0 s per turn on `claude-sonnet-5` (thinking requests cost ~2 s for nothing, because the
proxy already runs the model at its default effort).

## 10. Account surface (own account, read-only)

`GET` only, on the owner's session: `/api/me`, `/api/subscription`, `/api/usage`, `/api/keys`,
`/api/keys/ips`, `/api/affiliate`, `/api/chats`, `/api/config`, `/api/uptime` →
`evidence/09-authenticated-surface.json`.

The account behind the session cookie does **not** own the API key:

| field | value |
|---|---|
| user id / plan | 5599 / `free` (`api.active: false`, `apiAccessUntil: null`) |
| `/api/keys` | `{"keys": [], "max": 0}` |
| `/api/usage` | `marketUsdTotal 0`, every day `messages 0, tokens 0` |
| `/api/chats` | 1 empty chat, created at signup |
| `/api/keys/ips` | `404 ipKeyNotFound` — needs a `keyId` that belongs to the caller |

So the key works while no account-level entitlement or metering covers it: you cannot see its
usage, rotate it, or raise its limits from this dashboard. That also means the earlier
`403 → 200` flip was someone else's allowlist edit, not yours.

Hardening observations (report only, not tested): `gc_session` is `HttpOnly; Secure; Lax` (good),
the `lang` cookie is `Secure: false`, HSTS is 1 year with `includeSubDomains`, CSP — although
present — allows `'unsafe-inline'` and `'unsafe-eval'`, and `x-powered-by` advertises the stack.

**Not tested, by design:** whether `/api/keys/ips` (and `/api/keys`) validate that the supplied
`keyId` belongs to the session user. That is an IDOR, and testing it means requesting another
customer's data — out of scope for me, and criminal under FR 323-1 / US CFAA regardless of
intent. It is written up as a question for the vendor in `notes/vendor-report.md`.

## 11. Making it faster (measured)

| lever | effect | how |
|---|---|---|
| Reasoning effort `low` | **3× faster** (astra 8.4 s → 2.7 s, 57 tok) | `"reasoning_effort":"low"` (OpenAI API) / `"output_config":{"effort":"low"}` (Anthropic API) |
| Thinking level `off` in pi | 6.4–7.0 s → 4.2–4.5 s per turn | already pinned in `settings.json` → `modelThinkingLevels` |
| Model choice | 12 tok/s vs 2.5 tok/s | `claude-sonnet-5` or `claude-fable-5.1`; avoid `claude-opus-5-5` (~23 s for 57 tok) |
| Avoid `[1m]` variants | priority 103/104 = slower queue | use them only above 256 k context |
| Connection reuse | TLS is only 30 ms, HTTP/2 is on | keep one long-lived client, do not re-CONNECT per call |
| Retries | 429/502 happen | pi `retry.maxRetries: 3` (default) handles it; a 65 s stall was observed once |
| `stream: true` | **no gain** — buffered (F10) | do not tune for token streaming; tune total timeout instead |
| Prompt caching | unverifiable — cache fields are not returned | keep the stable system prefix byte-identical between calls and hope |

Ceiling: ~2.2 s of every Claude call is proxy overhead before the upstream is contacted, and
nothing client-side removes it. If you need real speed, this proxy is not the tool.

## 12. Security review

`notes/security-review.md` — nine reportable items with severity, the recovered attack surface
(from `robots.txt` and the bundles), five authorization hypotheses stated as questions for the
vendor, and a remediation order. Read-only: static analysis plus `GET` on the owner's own session.
Nothing on that list was exploited, and the two highest-value questions (ownership on
`/api/keys/ips`, socket-vs-client IP on the allowlist form) are left explicitly untested.

## 13. Static weak-point pass (REA)

`notes/weakpoints.md`, from `analyze-javascript-application` over 18 client sources: 278 691 AST
nodes, 494 modules, 1 873 findings, 0 parse failures, `evidence/11-javascript-routes.json`.

Ranked: **W1** every key operation takes its id from the client (`?id=`, `?keyId=`) → IDOR if the
server omits `AND user_id = session`; **W2** `/admin` and `enterprise` panels are gated only by
`me.user.isAdmin` in the browser; **W3** upload `accept` whitelist is client-side and includes
`.py/.js/.go/.c`; **W4** the highlight path builds HTML with `dangerouslySetInnerHTML` (escaper is
present and correct, no sanitizer behind it); **W6** plan and quota maths run in the browser.
`notes/api-contract.md` then maps all 19 endpoints and their bodies (`evidence/12-api-contract.json`):
`keyId`, `id`, `chatId` and `reference` all arrive from the client — and `POST /api/pay/whop/check`
decides a purchase from `?ref=` in the URL (F25), which outranks every other hypothesis here.

Also worth stating: no open redirect on `next` (`/^\/(?![/\\])/`), no secrets, no token in
`localStorage`, `cache:"no-store"` on sensitive reads. Static reading proves what the client does
**not** check — it cannot prove what the server does. W1–W3 remain hypotheses.


## 14. Provenance and infrastructure (passive OSINT)

`notes/infrastructure.md`. Domain **registered 2026-10-09**, i.e. 18 days old at time of writing,
GoDaddy, Cloudflare anycast, Let's Encrypt wildcard. **No MX** (cannot receive mail), **no DMARC**,
SPF softfail, **no CAA**, no `security.txt` (404), DNSSEC unsigned — yet the site advertises
"98.89 % 30-day uptime", which an 18-day-old domain cannot support.

Chain: Cloudflare → Next.js → Cloud Run `mpc2-prod-29` + AWS ECS `us-east-1`; codes via MailerSend;
attribution via `utmify.com.br` (Brazilian infoproduct tooling). The economics — "unlimited"
Opus-class capacity at $31.10/mo — are below API list price, so the capacity is pooled subscription
seats resold through a proxy. That single fact explains F10 (buffered), F11 (slow), F12 (502), F18
(429) and F17 (unbilled injected prompt) as symptoms rather than bugs.

## 15. The anti-bot layer, and a submission-ready draft

`/gc.js` (F30) turned out to be a 122 KB **unminified** MIT captcha, `FCaptcha 1.21.0`, self-hosted at
`/gc`. It fingerprints the browser (fonts, WebGL, `deviceMemory`, timezone, media devices), analyses
form typing rhythm, looks for `webdriver`/CDP/Playwright/Selenium, and submits the lot to
`/gc/api/verify` bound to a SHA-256 proof of work — with **no consent surface anywhere in the app**
(LGPD/GDPR). The proof itself is advisory: difficulty 4 (≈65 k hashes) enforced client-side by
`minTime: 500`, a client-chosen nonce when `/gc/challenge` fails, and self-reported solve timing
outside the committed hash (F31).

`notes/submission.md` assembles nine findings — GH-01…GH-09 — as a fileable report with impact and
fixes: the unauthenticated catalogue, the `?ref=` payment decision, the dead hidden model, image
502s, buffered streaming, the unbound key, the fingerprinting captcha, the advisory PoW and the
domain hygiene. It states explicitly what was not performed and what authorization would be needed
to go further.

## 16. Deep read of `/gc.js`

`notes/captcha-deep.md` — 8 modules, 3 endpoints (`/api/pow/challenge`, `/api/verify`, `/api/score`),
and the scoring model published in the file. Pass is `score < 0.5`; **`navigator.webdriver` is worth
0.25**, so a blatantly automated browser passes unless a second heuristic class fires (F33). The rest
is pointer kinematics — the "vision AI agent" claim has no vision in it.

The structural problem is fail-open: no `serverUrl`, any network error, or a challenge-fetch failure
each downgrade the verdict to `_clientSideVerify`, which returns an **unsigned base64 token asserting
its own score** (F34). Paths 2–3 are one flaky `/gc` from live, on a deployment that has already shown
65 s stalls. Also: `HTMLFormElement.prototype.submit` is monkey-patched globally and never restored
(F35). Privacy is handled with unusual care for keystrokes — no values, no key codes, textareas only —
but the device fingerprint around it has no consent surface (F36).

## 17. Docs vs. reality

`notes/api-docs-vs-reality.md` scores twelve documented claims against measurement: **nine are
contradicted** (F37). The two that matter commercially are the `429` — documented as "free daily
limit", measured as `overloaded_error` with a Portuguese upstream-congestion body — and the `402`
add-on gate, which never fires for a key bound to no account. Also false as written: "the key never
leaves your browser" (the server returns it) and "someone else's key will not work" (the key in use
does). The catalogue itself is open while inference is gated (F38), and it ships internal deployment
counters (F39).

## 18. The fourth surface, and a standard-library block

`notes/gemini-surface.md` — `/v1beta` tested for the first time (5 requests, `evidence/13`).
`countTokens` exists and **ignores the system prompt entirely**: a 4 000-character
`systemInstruction` changes the total by 0, which is F17 confirmed independently on a second surface.
`streamGenerateContent` returns two frames — all content, then `STOP` — so F10 now holds on all four
dialects (F42). Tool calling works and returns an Anthropic `toolu_…` id inside a Gemini envelope
(F43).

And a small one with a sharp edge: Cloudflare answers `Python-urllib/3.13` — the default UA of
`urllib.request` — with `403 "error code: 1010"`, a 17-byte non-JSON body that appears nowhere in the
documented error table, while every other client UA gets 200 (F40). "Any SDK works, no workaround"
holds for all of them except the one in the Python standard library.

## 19. Used as a real backend (practical validation)

The endpoint was exercised the way a customer would use it rather than the way a prober would:
as the reasoning step of a working local voice assistant
(`~/Desktop/work/homespeaker/` — Google Home speaker as output, `claude-sonnet-5` as brain).

What that added:

- **Integration works.** `POST /v1/messages` from a bare `urllib` client, one call per utterance,
  ~3 s for a three-sentence French reply. No SDK needed, no streaming needed.
- **F16 holds in production use.** Pinning thinking `off` took wall-clock from 6.4–7.0 s to
  4.2–4.5 s — the same lever measured in `evidence/10`, now on the critical path of a real loop.
- **F45 (new).** The default `Python-urllib/3.15` UA is rejected with a bare `403` while `curl`
  and urllib-with-custom-UA succeed. A first-time integrator gets an opaque 403 that is
  indistinguishable from the IP allowlist (F5) or a quota error. This is F40 seen from the
  client side, and it is the single most likely reason a developer gives up on this API.
- **F17 seen from outside.** The proxy's injected prompt is invisible in billing; only the
  operator's own accounting notices it.

Detail in `notes/findings.md` (F15–F19 now written up, plus F45).
