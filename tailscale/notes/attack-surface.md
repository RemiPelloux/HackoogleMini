# Tailscale v1.104.1 — attack-surface map & vuln-hunt ledger

Goal: find responsibly-disclosable vulnerabilities in Tailscale for the official
program (HackerOne / security@tailscale.com). Source-primary review against
`target/tailscale-src` @ v1.104.1 (commit `9a522a9`), which is logic-identical to
the installed binary (no distro patches — see findings.md). REA/Ghidra used to
confirm the shipped artifact where source doesn't settle it.

## Trust boundaries (attacker vantage points)

1. **Local host, non-root user** → LocalAPI (unix socket `/run/tailscale/`),
   web client `127.0.0.1:5252`, debug endpoints. Threat: local priv-esc,
   DNS-rebind from a browser, CSRF.
2. **Other tailnet peer** (semi-trusted, may be a compromised/hostile node) →
   peerapi (on the tailscale0 IP), Taildrop receive, Tailscale SSH, DERP relay
   framing. Threat: SSRF, path traversal, authz/ACL bypass, RCE, info leak.
3. **Network / off-tailnet** → DERP, DNS responses (MagicDNS upstream),
   NAT traversal (STUN/netcheck), WireGuard handshake, UPnP/PCP/PMP. Threat:
   remote panic/DoS, cache poisoning, spoofing.
4. **Control plane** (coordination server; normally trusted, but worth modeling
   a malicious/MITM control) → controlclient message parsing, netmap, ACLs.

## Historical CVE classes (where to pattern-match)

- CVE-2022-41924: LocalAPI reachable via DNS-rebind on Windows → RCE. (Check
  `validHost`, Referer/Origin gating — looks hardened in v1.104.1.)
- CVE-2022-41925: peerapi SSRF (request to arbitrary host).
- CVE-2022-41923: traffic routed to wrong user / ACL mis-application.
- Taildrop path handling (filename → filesystem path).
- Tailscale SSH policy evaluation / session authz.

## Entry points located (file:line)

- LocalAPI handler table: `ipn/localapi/localapi.go:71` (map `handler`),
  gating in `ServeHTTP` :231 (`validHost` :… Referer/Origin reject),
  `validHost` anti-rebind check present. Per-handler `PermitRead/PermitWrite`.
- peerapi: `ipn/ipnlocal/peerapi.go`
- Taildrop: `taildrop/`
- Tailscale SSH: `ssh/tailssh/`
- DNS: `net/dns/`, resolver `net/dns/resolver/`
- DERP: `derp/`
- netstack / packet forwarding: `wgengine/netstack/`, filter `wgengine/filter/`
- control client: `control/controlclient/`

## Review ledger

| # | Surface | Scope | Status | Candidate findings |
|---|---------|-------|--------|--------------------|
| A | Local control | localapi + client/web webclient | DONE | **WEB /api/data over-disclosure (ev06, confirmed)**; login-mode rebinding→/api/up (ev07); ungated serveDial & localapi handlers (ev07, local); /metrics unauth. localapi validHost/perm gating itself sound. |
| B | Peer-facing | peerapi + taildrop | DONE | **Taildrop nextFilename panic (ev04, RUNTIME-CONFIRMED, unfixed upstream)**. Path traversal + CVE-2022-41925 SSRF mitigation both solid. |
| C | Tailscale SSH | ssh/tailssh | DONE — clean (hot zone but hardened) | SFTP-skips-recording (already fixed upstream 729cd431b = known); authz/priv-drop/check-URL SSRF all fail-closed. |
| D | DNS/MagicDNS | net/dns, resolver | DONE — clean | Forwarder never parses upstream records (hands bytes to OS) → no malformed-response panic/OOB class. getTxID reduced to 16-bit id (no question match) + Windows truncation path skips src check (forwarder.go:896) = documented, intentional, ephemeral-port-gated hardening tradeoffs, NOT findings. DoS notes: uncapped DoH body read (dohclient.go:87), per-query goroutine on TCP 100.100.100.100:53. ExitDNS peer SSRF is ACL-gated (no bypass found). |
| E | DERP + control | derp, control/controlclient | DONE — clean (hardened+fuzzed) | DERP relayed Source key unauth (by-design, payload still crypto-auth'd); MapResponse 256MiB/1GiB caps are DoS defense-in-depth (control is trusted). FOLLOW-UP: magicsock addDerpPeerRoute unbounded growth per conn (attacker enumerates keys) — DoS, needs check. |
| F | netstack/filter | wgengine/netstack, wgengine/filter | DONE | **matchIPsOnly SrcCaps branch ignores Dsts → ICMP ACL-scope bypass (ev05, confirmed by inspection, unfixed)**; filter.go:381 dead-condition typo (fail-closed, no impact). Fragment/DNAT/loopback guards sound. |

## Lead: post-v1.104.1 security fixes (bugs PRESENT in our binary)

`git log v1.104.1..origin/main` shows a hardening batch (`tailscale/corp#50380`),
**11 of 14 commits in `ssh/tailssh`** — Tailscale SSH was audited post-release,
and v1.104.1 predates all of it. See evidence/20261025-03. These are fixed
upstream (so known / likely not bounty-eligible alone); the value is checking for
**incomplete fixes** and the **same pattern unfixed elsewhere**. Highlights
present in 1.104.1: SSH env injection incl. `GLIBC_TUNABLES` (CVE-2023-4911
class), acceptEnv non-linear matching (ReDoS), `isRootUser` uid=0 gaps,
serve `Tailscale-App-Capabilities` leak across h2 streams, `util/osuser` argv/
passwd parsing, `util/cmpver` ParseUint panic.

Each candidate finding must cite file:line, give a concrete attacker-controlled
input → bad outcome scenario, and state confidence. Verify before claiming;
never fabricate. Confirmed issues get their own evidence file + a disclosure
writeup, not posted anywhere until reviewed with the user.
