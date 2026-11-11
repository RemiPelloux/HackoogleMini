# Tailscale v1.104.1 — vulnerability reports (for responsible disclosure)

Source-primary review against upstream v1.104.1 (commit `9a522a9`), logic-
identical to the installed Arch binary (no distro patches). Submit via
HackerOne / security@tailscale.com. Nothing here has been disclosed publicly.

| Folder | Finding | Severity | PoC | Upstream |
|--------|---------|----------|-----|----------|
| `taildrive-symlink-escape/` | Taildrive WebDAV follows symlinks out of a share root → arbitrary file read/write as the serving user **(LIVE-confirmed on 2 real nodes 2026-10-25)** | High | runnable Go PoC vs the real vendored `tailscale/xnet/webdav` (read+write escape shown) | unfixed |
| `webclient-rebind-control-repoint/` | `tailscale web` login mode lacks the anti-DNS-rebinding/Host defense manage mode has → CSRF repoint to attacker control server → DNS MITM (default) up to root RCE | High → **Critical** ceiling | logic PoC of the gate + attacker `rebind.html` + VM repro steps | unfixed |
| `funnel-underscore-identity-header/` | Funnel strips identity headers only in dash-case; `Tailscale_User_Login` (underscore) reaches the backend → internet identity spoof to a serve backend | High | runtime PoC through real `httputil.ReverseProxy` → CGI backend sees spoofed `HTTP_TAILSCALE_USER_LOGIN` | unfixed |
| `relay-callmemaybevia-reflection/` | `CallMeMaybeVia` has no `ClientDisco`/`AddrPorts` validation → hostile peer makes the node emit UDP to arbitrary addresses (reflection) + handshake-goroutine DoS; default-on | High | complete source-path analysis (no runtime 2-peer PoC) | unfixed |

Each folder: `report.md` (disclosure-ready) + `poc/`.

Before submitting, check Tailscale's existing advisories/HackerOne for
duplicates, and fill in your reporter identity in each report header.

Full investigation context: `../notes/findings.md`, `../notes/attack-surface.md`,
raw evidence in `../evidence/`.
