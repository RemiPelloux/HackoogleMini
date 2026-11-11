# Weak-point analysis of the GhostCLI client code (REA, static)

REA run: `analyze-javascript-application` over 18 client sources of `https://ghostcli.cloud`
(`shipped-artifact` authority — public bundle only, nothing executed server-side).

```
evidence_id  ev_00feb537…c99f        provider  rea 6.8.0 (internal JS analyzer)
artifact     target/web  sha256 c38bee8e60…68156
statistics   278 691 AST nodes · 494 modules · 1 873 findings · 0 parse failures · 1 058 940 bytes
routes view  12 client routes (evidence/11-javascript-routes.json)
coverage     complete-within-view (1090/1090), 60 files outside scope, 51 027 semantic unknowns
```

## 1. Client routes recovered cold (not in `robots.txt`)

`/admin` · `/afiliados` · `/register` · `/termos` — plus the known `/chat`, `/dashboard`,
`/checkout`, `/invoices`, `/appeal`, `/docs`, `/login`, `/forgot-password`.
`/admin` and `/afiliados` are Portuguese-labelled internal pages the sitemap never mentions.

## 2. Real weak points, in order of what a triage team would care about

| # | Weak point | Where | Why it matters | Status |
|---|---|---|---|---|
| W1 | **Tenant id taken straight from the client for every key operation** — `fetch(\`/api/keys?id=${e}\`, {method:"DELETE"})`, `fetch(\`/api/keys/ips?keyId=${e}\`)`, `…/api/keys/ips?id=${e.id}`, {method:"DELETE"}` | dashboard chunk | Three handlers where the only thing tying a key to its owner is a server-side `WHERE user_id =`. Keys are integers (`/api/me` → `id: 5599`), so guessing is trivial. This is *the* classic IDOR here and it is the one thing a program would pay for. | **not tested** |
| W2 | **Admin surface is client-gated** — `x.isAdmin && p.push({href:"/admin",label:"Admin"})` and `"enterprise"===plan` feature flags, all derived from `me.user` | dashboard chunk | The nav link is hidden by JavaScript, so `/admin` must re-check on the server *and* on every `/api/*` handler it calls. Same for the `enterprise` panel: hiding a button is not authorization. `/api/me` returns `isAdmin` to any logged-in client, which also hands an attacker a targeting signal. | **not tested** |
| W3 | **File upload whitelist is client-side only** — `accept:".png,.jpg,…,py,.js,.ts,.rs,.go,.c,…"` then `new FormData(); append("file", e); POST /api/chat/upload` | chat chunk | `.py/.js/.go/.c` in an upload list means the server stores executable-looking sources. Server-side type/size limits, storage isolation and attachment serving headers are unverified — a stored-XSS-prone combination if an upload URL is ever rendered publicly. | **not tested** |
| W4 | **Syntax-highlight HTML is built with `dangerouslySetInnerHTML`** | docs chunk | LLM/markdown content → tokenizer → raw HTML. The escaper is present (`.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")`), so this looks correct — but it is the highest-consequence sink in the app and there is no DOMPurify pass behind it. One bad refactor in that tokenizer = XSS with a session cookie. | **escaped, keep an eye on it** |
| W5 | **`?keyId=` in a GET query string** | dashboard chunk | tRPC/REST ids in query strings land in logs, Referer and browser history. Even with correct ownership checks, a key id is a durable identifier for account enumeration. | observation |
| W6 | **Plan/quota is display logic, server enforcement unknown** — `l(e,r)`, `R3[plan]`, `"Ilimitado"/"Unlimited"` strings, `usage.totalMessages` | dashboard chunk | All plan maths happens in the browser; the only server-side gate confirmed is the `403` IP allowlist. Whether `/v1/*` independently re-checks plan/entitlement is exactly what F15 suggests it might not. | **F15 already shows a hole** |
| W7 | `robots.txt` enumerates the whole private area (`/api/`, `/key`, `/quota`, `/invoices`, `/appeal`, …) | public | Free target list for anyone doing recon. Cosmetic, but it is how §1 was found in one request. | confirmed |

## 3. What is actually in good shape (report it, don't "fix" it)

- **No open redirect on login.** `new URLSearchParams(location.search).get("next")` is validated
  with `/^\/(?![/\\])/` — rejects `//evil.com` and `/\evil.com`, the two classic bypasses. Correct.
- **No secrets in the bundle.** Full scan for `sk-`, `pk_live`, `whsec_`, `AKIA`, `AIza`, `ghp_`,
  JWTs: zero hits across 32 files.
- **No client-side token storage.** `localStorage`/`sessionStorage` are never used for auth or
  roles; the session lives in an `HttpOnly; Secure; SameSite=Lax` cookie.
- **Cache hygiene.** Sensitive reads use `{cache:"no-store"}` (`/api/keys`, `/api/usage`,
  `/api/keys/ips`); `/dashboard` is served `private, no-store` with a real CSP, HSTS 1 y,
  `X-Frame-Options: SAMEORIGIN` + `frame-ancestors 'self'`.
- **Form hygiene.** `autoComplete:"email"` / `"current-password"`, `type:"password"`, `required`.

## 4. Honest limits of this analysis

Minified Next.js output, 51 027 semantic unknowns, 60 files outside the selection, no source maps
served (`.map` absent, verified). Static reading cannot prove an authorization check exists — only
that the client does not perform one. Every "not tested" row above stays a hypothesis until the
vendor, or an authorized tester with a second test account, answers W1/W2/W3.

## 5. If this becomes a real engagement

Two test users, one server-side log window, and permission to send 3–4 requests per hypothesis:
W1 and W2 are answerable in under an hour and would be the paid findings. W4 needs a fuzz pass on
the highlighter. Until then this document is a prioritized map, not a PoC.
