# GhostCLI — Final Reconnaissance & Security Summary

## 1. Executive Summary
GhostCLI is a Brazilian infoproduct reselling pooled AI capacity through a proxy. The service is 18 days old, lacks basic infrastructure hygiene (no MX, no DMARC, no security.txt), and uses a self-hosted, unminified CAPTCHA (FCaptcha 1.21.0) that fails open under network stress. While the API offers four dialects (Anthropic, OpenAI, Gemini, Responses), it suffers from significant integrity gaps: token counting ignores system prompts, streaming is fully buffered, and documentation contradicts measured behavior in 9 of 12 claims.

## 2. Key Findings (Top 5)
*   **GH-02 (High):** Payment confirmation relies on a client-supplied `?ref=` URL parameter.
*   **GH-01 (Medium):** Unauthenticated `/v1/models` leaks internal system prompts and hidden inventory.
*   **GH-06 (Medium):** API keys are not bound to the account using them, decoupling entitlement from identity.
*   **F33/F34 (Medium):** The anti-bot layer weights `navigator.webdriver` at only half the failure threshold and fails open to unsigned tokens when the server is unreachable.
*   **F41 (Medium):** Token counters (`countTokens` and `usage`) ignore the injected system prompt, leading to severe under-counting.

## 3. Infrastructure Profile
*   **Domain:** `ghostcli.cloud` (GoDaddy, registered 2026-10-09).
*   **Hosting:** Cloudflare → Next.js → Cloud Run (`mpc2-prod-29`) + AWS ECS.
*   **Attribution:** `utmify.com.br` (Brazilian ad-tracking).
*   **Anti-Bot:** FCaptcha 1.21.0 (MIT, self-hosted at `/gc`).

## 4. Deliverables
*   `REPORT.md`: Full 18-section technical report.
*   `notes/submission.md`: Fileable HackerOne-style draft (GH-01 to GH-10).
*   `evidence/01-13.json`: Raw data supporting all latency and contract measurements.
*   `~/Downloads/ghostcli-gc.js`: The complete 122 KB captcha source for offline review.

## 5. Recommendation
Submit `notes/submission.md` to the private program. Request authorized test accounts to validate the IDOR and payment bypass hypotheses (F25/F26) without crossing ethical boundaries. Do not pay for an "Enterprise" plan on a domain with no legal entity or inbound email support.
