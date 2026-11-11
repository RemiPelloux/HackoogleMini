# GhostCLI — infrastructure & provenance (passive OSINT)

Public records only: DNS, WHOIS, CT/TLS certificate, HTTP headers, and the app's own CSP.
No scanning, no subdomain brute force, no requests to the Cloud Run / AWS hosts listed below.

## 1. The timeline is the headline

| event | timestamp (UTC) |
|---|---|
| domain **created** at GoDaddy | **2026-10-09 11:35** |
| Let's Encrypt cert issued (wildcard) | 2026-10-09 10:45 |
| domain last updated | 2026-10-14 11:35 |
| expiry | 2027-10-09 |
| today | 2026-10-27 |

**The service is 18 days old.** Everything in this workspace — "Enterprise $130/mo", "1M token
context", "98.89 % 30-day uptime" — is being sold by a domain registered two and a half weeks ago.
That uptime figure is mathematically impossible on an 18-day-old domain, which means it is
synthetic. Re-read F8 with that in mind.

Registry status: all four `client*Prohibited` locks + `clientTransferProhibited`. DNSSEC unsigned.

## 2. DNS

```
A     104.21.28.61   172.67.170.102          (Cloudflare anycast)
AAAA  2606:4700:3036::6815:1c3d
      2606:4700:3037::ac43:aa66              (Cloudflare)
NS    june.ns.cloudflare.com  emerson.ns.cloudflare.com
MX    — none —
TXT   v=spf1 include:_spf.mailersend.net ~all
TXT   google-site-verification=ge_V4kp0GJVKl2pEbBjnzEspvIwwY2NJZaBxB3DavBc
CAA   — none —
_dmarc — none —            www — none —            CAA — none —
```

- **No MX record at all.** The domain cannot receive email. Support, abuse, DMCA — nothing arrives.
- **No DMARC, SPF is `~all` (softfail), no CAA.** Anyone can spoof `@ghostcli.cloud` in a From
  header and most receivers will accept it. For a service that emails **authorization codes for API
  key IPs**, that is not cosmetic.
- Mail is outbound only, through **MailerSend** (`_spf.mailersend.net`) — that is the pipe the
  allowlist codes travel on.

## 3. TLS

```
issuer  Let's Encrypt CN=YE1
subject CN=ghostcli.cloud
SAN     DNS:*.ghostcli.cloud, DNS:ghostcli.cloud
valid   Oct  9 10:45:20 2026 → Jan  7 10:45:19 2027
```

Wildcard, Cloudflare-issued, auto-renewed. A wildcard means subdomains exist behind it and the
certificate will never tell you which — the only cheap way to enumerate them is brute force, which
I did not do (crt.sh was unreachable, so CT gave nothing either).

## 4. The chain, from browser to model

```
browser
  └─ Cloudflare (server: cloudflare, cf-ray …-MRS, alt-svc h3, NEL reporting)
      └─ Next.js app router (x-powered-by: Next.js, vary: rsc/next-router-state-tree)
          ├─ Cloud Run   mpc2-prod-29-is5qnl632q-uc.a.run.app      ← "mpc2", 29th prod revision
          ├─ AWS         5z-2b6b76…ecs.us-east-1.on.aws             ← us-east-1 ECS endpoint
          ├─ ipapi.co / api.ipify.org / api6.ipify.org              ← IP + IPv6 discovery for the key gate
          ├─ MailerSend                                              ← allowlist codes
          ├─ Cloudflare Insights + Facebook pixel + utmify.com.br     ← ad attribution
          └─ jsDelivr (CDN for scripts)
```

Read the CSP as a confession of architecture: `connect-src` names the two backend hosts, and
`mpc2-prod-29` says this is the 29th production revision of a project called MPC2. All of it sits
behind Cloudflare, so the origin IP is never exposed — which is also why the app can be 18 days old
and still look infrastructurally mature.

**`utmify.com.br` is the tell.** UTMify is a Brazilian ad-attribution platform for infoproduct
sellers. Combined with the pt-BR UI, the Portuguese `429` body ("O upstream está congestionado"),
the BRL/USD toggle and `/afiliados`, the operator is Brazilian and this is run as an
infoproduct — which explains the pricing psychology ($31.10, not $31) and the affiliate program.

## 5. How can this exist at all — the unit economics

`Unlimited messages` + Claude Opus-class models for **$31.10/month** is not purchasable at API list
price. One long agentic session at list rates costs more than the subscription. So the capacity
cannot be API-billed. Everything measured in this workspace is consistent with **pooled
subscription seats resold through a proxy**:

| observation | pooled-seat explanation |
|---|---|
| 1.9–13.8 tok/s, Opus slowest (F11) | shared, rate-shaped capacity — not dedicated API throughput |
| streaming fully buffered, 1 delta (F10) | the proxy collects the upstream answer, then re-emits it |
| `429` "upstream congestionado" (F18) | the shared seat hit its rolling window |
| ~60 s then `502` for `z-ai/glm-5.3` (F12) | upstream route for the hidden model is broken/absent |
| `priority: 103/104` tiering (F1) | parallel pools — `[1m]` = a faster queue than the default |
| `base_instructions` leaked in `/v1/models` (F1) | the proxy injects its own system prompt — and does not bill it (F17) |
| Haiku ids silently answering as Sonnet 5 (F2) | one cheap upstream can serve every advertised name |

That is the answer to "how can this exist": it exists by arbitraging somebody else's subscription
terms, which is why it is anonymous, 18 days old, has no MX, no DMARC, no security.txt, no company
entity, and a `free` plan for the account whose key you are using. The business is not a hosting
company selling compute; it is a reseller of seat quotas, one upstream policy change from
disappearing — and the paid plan with it.

## 6. What that means for you, practically

- **Do not pay $130 for Enterprise.** On a domain this age with no legal entity, no inbound email
  and no security contact, a chargeback is your only remedy and there is nobody to charge back to.
- **The `gcli_` key you hold is not tied to your account** (F15). It can vanish, be rotated, or be
  revoked by its real owner without notice, and your prompts transit a proxy that already
  under-reports usage and buffers responses (F17, F10).
- **No security contact exists** — `/.well-known/security.txt` → 404, no MX. The only channel for
  your findings is whatever the private program gave you, which is another reason to get the
  program's asset list and a named contact in writing before you do anything else.

## 7. What I did not do

No subdomain brute force, no DNS zone transfer attempt, no port scan, no request to the Cloud Run or
ECS hosts named in the CSP, no CT-database scraping beyond one crt.sh call that was refused. This
document is DNS + WHOIS + one TLS handshake + headers the site sends every visitor.
