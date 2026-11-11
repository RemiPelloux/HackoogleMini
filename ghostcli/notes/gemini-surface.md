# The fourth surface: `/v1beta` (Gemini dialect)

Never tested until now. Script `scripts/gemini-surface.py`, evidence `evidence/13-gemini-surface.json`,
five requests against an authorized key.

| check | documented | measured |
|---|---|---|
| `countTokens` exists | listed in `supportedGenerationMethods` | **200**, 252 ms |
| `countTokens` counts the system prompt | implied | **no** — 4 000-char `systemInstruction` changes the total by **0** (12 → 12) |
| `streamGenerateContent` | "token by token" | **200**, but **2 frames**: frame 0 carries all 246 chars, frame 1 is `STOP` + usage |
| `?key=` auth "matching Google SDK conventions" | supported | **works** |
| tool calling → `functionCall` | documented | **works** — returns `functionCall{name:"get_weather", args:{city:"Paris"}}` |
| token counts are usable | — | `countTokens` 12 for "Say OK."; `promptTokenCount` 18 for a 7-token prompt; **inconsistent between endpoints** |

## What each result settles

**F17 now has an independent confirmation on a second surface.** A 4 000-character system
instruction is invisible to the token counter, exactly as it was invisible to `usage.input_tokens` on
`/v1/messages`. The proxy injects its own system prompt after metering. Not a bug in one counter — a
property of the pipeline.

**F10 holds on the fourth dialect.** Two SSE frames, one content frame. Whatever "streaming" means
here, it is not incremental delivery, and it is now consistent across Anthropic, OpenAI Chat,
Responses and Gemini shapes.

**The Gemini shape is a costume.** `functionCall` comes back with `id: "toolu_1793096724411_1"` — an
Anthropic tool-use id, in a Gemini envelope, with `modelVersion: "claude-sonnet-5"` and
`responseId: "gem_…"`. One upstream, four translations.

## F40 — Cloudflare bans the standard-library Python client

`urllib.request` sends `Python-urllib/3.13` by default, and that UA gets:

```
HTTP 403   17 bytes   "error code: 1010"
```

`error code: 1010` is a **Cloudflare** browser-integrity block, not a GhostCLI error — it is not in
their error table, returns no JSON, and appears on both `/v1beta/models` and the inference routes.
`python-requests`, `curl/8.5`, `Anthropic/Python`, `OpenAI/Python`, `google-genai-sdk` and a browser
UA all return 200. So the documented promise "any SDK works, no plugin, no workaround" holds for
every client except the one in the Python standard library — and the failure mode is a blank page
instead of an API error.
