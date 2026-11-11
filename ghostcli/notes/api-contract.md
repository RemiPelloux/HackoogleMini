# GhostCLI — client API contract and trust boundary (static)

Extracted from 32 client sources (`target/web/chunks`, `target/web/dashboard/chunks`).
Evidence: `evidence/12-api-contract.json`. Nothing here was sent to the server.

## 1. The contract as the client implements it

| endpoint | methods | client-supplied input | server response the UI trusts |
|---|---|---|---|
| `/api/auth/login` | POST | `email`, `password`, **`capToken`** | `banned`, `reason` (`abuse`/`tos`) |
| `/api/auth/logout` | POST | — | — |
| `/api/me` | GET | — | `user{id,plan,isAdmin}`, `api{active}`, `usage` |
| `/api/config` | GET | — | `paymentMethods`, `country` |
| `/api/plan` | POST | **`plan`** (UI sends `"free"`) | error text |
| `/api/subscription` | POST | **`action`** | error text |
| `/api/usage` | GET | — | `daily[]`, `byModel[]`, `marketUsdTotal` |
| `/api/keys` | GET, POST | `name` (create) | `keys[]`, `max`, `key` |
| `/api/keys?id=` | DELETE | **`id`** | `keys[]` |
| `/api/keys/ips` | POST | **`keyId`** + IP state | `ips[]` |
| `/api/keys/ips?keyId=` | GET | **`keyId`** | `ips[]`, `currentIp`, `currentNetwork`, `limite`, `teto` |
| `/api/keys/ips?id=` | DELETE | **`id`** | `ips[]` |
| `/api/chats` | GET, POST | — | `chats[]` |
| `/api/chats/{id}` | GET, PATCH, DELETE | **`id`**, `pinned`, `model` | `messages[]` |
| `/api/chat` | POST | **`chatId`**, `content`, client-built auth headers | 402 quota, 403 locked-model, SSE body |
| `/api/chat/upload` | POST | multipart `file` | `name`, `preview`, `thumb` |
| `/api/affiliate` | GET, POST | **`code`** | `code`, `commissions`, `total`, `referrals` |
| `/api/pay/whop/check` | POST | **`reference`** (taken from `?ref=` in the URL) | **`{paid: true}`** |
| `/api/uptime` | GET | — | `windows`, `days` |

## 2. Trust boundary — what the client decides and the server must re-decide

Every id in this app travels as a client-supplied value: `keyId`, `id`, `chatId`, `reference`.
Seven inputs, in the order I would want them verified:

1. **`keyId` on `/api/keys/ips`** (all three verbs). One missing `AND user_id =` is a full IDOR over
   other customers' allowlists.
2. **`id` on `/api/keys` DELETE and `/api/chats/{id}`** — same shape, destructive verb.
3. **`chatId` on `POST /api/chat`** — appending a message into a stranger's conversation.
4. **`reference` on `POST /api/pay/whop/check`** — the UI takes `?ref=` from the URL, posts it, and
   shows paid if the answer says `{paid:true}`. If that decision is not derived from Whop's
   *signed* webhook or a server-to-server lookup, a subscription is a URL parameter. This is the
   highest-consequence hypothesis in the whole app, above the IDOR.
5. **`plan` on `POST /api/plan`** — the UI only ever sends `"free"`. The server must reject
   `"enterprise"` from the same endpoint, i.e. downgrade only.
6. **`ip` inside `POST /api/keys/ips`** — see the positive note below.
7. **`file` on `/api/chat/upload`** — `accept` is a UI hint; `.py/.js/.go/.c` in it means the server
   must do its own typing, sizing and serving.

## 3. Evidence in the client that some of this is already handled

- **`capToken` on login** — a CAPTCHA token is wired in, so brute force is at least attempted to be
  mitigated (server-side verification unverified).
- **`402` and `403` are handled distinctly** in the chat path — "quota reached" vs "locked model".
  Plan enforcement therefore exists in the chat handler. That contrast is what makes F15 (an
  unentitled key still inferring on `/v1/messages`) look like a gap on the API path, not a policy.
- **`GET /api/keys/ips` returns `currentIp` and `currentNetwork`** computed by the server. A server
  that already knows your address has no reason to accept one from the body — this is weak evidence
  in favour of the allowlist being recorded server-side. Still a hypothesis, but a cheerful one.
- `cache:"no-store"` on every sensitive read; API errors surface only as `errorCode` keys.

## 4. What is still unknown, and cannot be settled from here

Whether each handler above runs its ownership/entitlement check. The client cannot tell you; only a
second account (or the vendor's logs) can. I am not going to guess integer ids on a live service to
find out — that reads other people's data whether or not the intent was good.
