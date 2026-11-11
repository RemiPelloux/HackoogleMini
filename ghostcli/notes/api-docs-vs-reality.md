# GhostCLI — what the docs promise vs what the API does

Source of claims: `/docs` (captured at `target/web/dashboard/docs.html`). Source of measurements:
`evidence/07`, `08`, `09`, `10`, plus the session's live observations. Every row is a claim a
customer can quote back at the vendor.

| # | documented | measured | verdict |
|---|---|---|---|
| 1 | "with streaming: plain text arrives token by token and only the span of a call is held back until it closes" | **the whole answer arrives in one `content_block_delta`** — 1 delta on all five models, first delta at 6.05 s (sonnet-5) / 18.11 s (astra) containing all 229 bytes | **contradicted** (F10) |
| 2 | `429` → "Free daily limit reached — 5 messages/day ceiling of the free model" | live `429 overloaded_error`, body in Portuguese: *"O upstream está congestionado"*, and one 65 s stall | **undocumented error class** (F18) |
| 3 | "These endpoints require the API access add-on… Without it the response is `402`" | the supplied key infers fine while the account reports `api.active: false`, `plan: "free"`, `/api/keys → {"keys": [], "max": 0}` | **gate not applied to this key** (F15) |
| 4 | `403` → "IP not authorized" | one identical `POST /v1/messages` went `403 permission_error` → `200` with no client change (owner edited the allowlist) | **consistent** |
| 5 | "The **4 best models** in the world" | catalog lists **5** real models, one of them (`z-ai/glm-5.3`) hidden from the UI and sold as `gpt-5.6-sol` | **count and inventory wrong** (F1/F3) |
| 6 | "**1M token context**" | only the `[1m]` variants carry 1M; `[1m]` on any `claude-*` id is accepted then **silently stripped** to 256k. Their own Claude Code snippet sets `CLAUDE_CODE_DISABLE_1M_CONTEXT = "1"` | **advertised, then disabled in their own setup** (F2) |
| 7 | "**Unlimited** messages… **no per-token billing**" | free tier is capped at 5 messages/day (their own error table); `/api/usage` computes `byModel[].marketUsd` and `marketUsdTotal` per key | **internally metered, publicly "unlimited"** |
| 8 | "Generated in your browser — the key **never leaves it**" | `POST /api/keys {name}` returns `{key}` **from the server**; the dashboard lists keys from `GET /api/keys`; and the key in use is not in that list at all | **false claim** (F15) |
| 9 | "Verified end to end with both real CLIs in a full cycle" | `z-ai/glm-5.3`, its `[1m]` variant and the `gpt-5.6-sol` alias **502 after 57–67 s on all three surfaces**; image input 502s on all three dialects | **contradicted** (F12/F13) |
| 10 | "someone else's **key will not work** and should not be reused" | the key we hold is not attached to the account using it, and works | **contradicted by their own docs** (F15) |
| 11 | catalog/meta endpoints "require the API access add-on" | `GET /v1/models` and `GET /v1beta/models` return the **full catalogue with no key at all**, including `base_instructions` | **no auth, no add-on** (F1) |
| 12 | `403`/`404` → "Same cause as the 404 — the message misleads" | they document that their own error messages mislead, and ship them anyway | **known and accepted** |

## The two rows that are worth money

**Row 2** — a `429` that is *not* the documented one, emitting the upstream provider's congestion
text in Portuguese. It is a direct leak that capacity is pooled and contended, and it gives a paying
customer a screenshot where the product says "the upstream is congested" instead of "your plan
limit". Ties F18 to F29.

**Row 3** — the documented `402` gate does not fire for a key that verifies against no account.
Combined with row 10 ("someone else's key will not work"), the vendor states a control it does not
implement.

## Minor, but free to fix

- Docs typo: `claude --model claude-fable- 5.1` (stray space) — a copy-paste failure for every reader.
- Gemini descriptions in `/v1beta/models` are **Portuguese marketing copy** ("O cavalo de batalha do
  código agêntico…"), i.e. hand-written operator text, not upstream metadata — one more confirmation
  of who runs this and that the catalogue is manually curated.
- `version: "001"` on every Gemini model, `priority: 103/104` on the internal catalogue: internal
  deployment counters exposed in a public response.

## Behaviour notes gathered while checking

- Catalog routes (`/v1/models`, `/v1/models/{id}`, `/v1beta/models`) are fully open; every inference
  route is key-gated. The authorization boundary is on the wrong side of the catalogue.
- Error taxonomy observed live: `403 permission_error` (IP), `429 overloaded_error` (upstream),
  `502` (dead model, vision), `404 unknown_route` (single-segment model path). `402` never appeared
  for this key, though the docs make it the headline gate.
- Model descriptions are localized pt-BR and inconsistent in tone between models — consistent with
  hand-editing, which is also why `"4 best models"` and a five-model catalogue coexist.
