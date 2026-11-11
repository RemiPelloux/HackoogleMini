# Login-mode web client lacks DNS-rebinding/Host defense → control-server repoint (ceiling: root RCE)

**Component:** `client/web` (the `tailscale web` login/readonly server)
**Affected version:** Tailscale v1.104.1 (confirmed), and current `main` at
review time (unfixed — no post-v1.104.1 changes to `client/web`)
**Reporter:** (your name / HackerOne handle)
**Severity:** chain; entry bug is a DNS-rebinding CSRF. Realistic default-config
impact **High** (full DNS interception); ceiling **Critical** (root RCE) when the
victim enabled `--ssh` or `RemoteConfig`. CVSS:3.1 for the RCE ceiling ≈
`AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H` (~8–9); the entry defect alone ≈ High.

---

## Summary

`tailscale web` has two modes. **Manage mode** (served inside tailscaled on the
node's Tailscale IP, port 5252) is protected against DNS rebinding by
`requireTailscaleIP` (a strict Host-header allowlist) plus CSP and
`X-Frame-Options`. **Login/readonly mode** (`tailscale web`, default
`localhost:8088`) applies **none** of these: `requireTailscaleIP` and the
security headers are gated on `s.mode == ManageServerMode`, and login-mode
`authorizeRequest` returns `true` unconditionally (no session auth). The only
protection left on a state-changing request is `csrfProtect`, which accepts any
**same-origin** request.

A classic DNS-rebinding attack therefore lets a malicious web page reach
`POST /api/up` on the victim's local login server and **repoint the node to an
attacker-controlled coordination (control) server**, supplying an attacker
`ControlURL` and `AuthKey`. Tailscale's security model treats the control server
as trusted, so a repointed node yields, at minimum, full DNS-level traffic
interception (on by default), and — if the victim had Tailscale SSH or
RemoteConfig enabled — an interactive **root shell (RCE)**.

This is the same bug class as **CVE-2022-41924** (LocalAPI reachable via DNS
rebinding). That class was fixed for the LocalAPI and the manage-mode web
client, but the login-mode web client was left without the equivalent
server-side defense.

## Root cause

```go
// client/web/web.go  serve()
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
    if s.mode == ManageServerMode {
        if !s.requireTailscaleIP(w, r) {   // anti-DNS-rebinding Host allowlist
            return                          // ... MANAGE MODE ONLY (web.go:335)
        }
        ...
        // CSP / X-Frame-Options also set only here (web.go:348-357)
    }
    ...
}

// authorizeRequest(): login/readonly mode (non-Synology/QNAP) =>
//   default: return true      // no session, no auth  (web.go:507-514)

// csrfProtect(): GET/HEAD/OPTIONS exempt; else Sec-Fetch-Site: same-origin passes,
//   or (header absent) Origin host == Host host passes.  (web.go:241-299)

// serveLoginAPI(): routes POST /api/up -> serveTailscaleUp with no session (web.go:519-525)
```

Because login mode performs **no Host validation**, a page served from
`http://attacker.example:8088/` that rebinds `attacker.example` to `127.0.0.1`
issues a request that is same-origin (`attacker.example:8088` → `attacker.example:8088`),
so `csrfProtect` passes and `serveTailscaleUp` runs.

## What `/api/up` does (the repoint)

```go
// client/web/web.go serveTailscaleUp -> tailscaleUp
go func() {
    if !isRunning {                                   // web.go:1173
        ipnOptions := ipn.Options{AuthKey: opt.AuthKey}
        if opt.ControlURL != "" {
            s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
                Prefs:         ipn.Prefs{ControlURL: opt.ControlURL},
                ControlURLSet: true,
            })                                         // web.go:1176-1181
        }
        s.lc.Start(ctx, ipnOptions)                    // starts with attacker AuthKey
    }
    if opt.Reauthenticate { s.lc.StartLoginInteractive(ctx) }
}()
```

`ControlURL` and `AuthKey` are attacker-supplied JSON fields
(`tailscaleUpOptions`, decoded at `web.go:1237`).

**Reachability constraint (confirmed):** the `ControlURL` edit is inside
`if !isRunning`, so a **Running** node is immune (the first switch returns early
for the Running state and `ControlURL` is never set). The repoint works on a
**non-running** node (NeedsLogin / NoState / Stopped-with-`Reauthenticate:true`)
— which is exactly the state when someone runs `tailscale web` to log in. The
most reliable body is `{"Reauthenticate":true,"ControlURL":"…","AuthKey":"…"}`.

## Impact ceiling once repointed

A malicious control server authors the node's entire netmap/policy and can
invoke every control→node (c2n) handler (dispatched with no auth beyond "arrived
over Noise from control", `ipn/ipnlocal/c2n.go:133`). Ranked:

1. **Root RCE (CRITICAL) — if victim enabled `--ssh`.** `nm.SSHPolicy` is taken
   from the control netmap with **no signature** (`ssh/tailssh/tailssh.go:606`),
   gated only by the local `RunSSH` pref. A rule
   `{principals:[{any:true}], sshUsers:{"*":"root"}, action:{accept:true}}`
   grants the attacker node an interactive **root** shell via the incubator.
2. **Full takeover (CRITICAL) — if victim enabled `RemoteConfig` (default off).**
   `feature/remoteconfig` proxies into LocalAPI with `PermitRead+PermitWrite`
   (`remoteconfig.go:86`); control can `PATCH` prefs to set `RunSSH=true` itself,
   then do (1).
3. **Full DNS interception (HIGH) — default-on.** `--accept-dns`/`CorpDNS`
   defaults true (`ipn/prefs.go:747`); control sets `DNSConfig.Resolvers` to an
   attacker resolver, overriding resolution for **all** names
   (`net/dns/manager.go:378`, `resolved.go:322`) → MITM of all name resolution.
   (No attacker-controlled file write: resolv.conf lines are FQDN-validated.)

**Not reachable** (good): full-tunnel exit-node / subnet-route L3 MITM requires a
pre-existing **user** pref (`ExitNodeID`/`RouteAll`, `routemanager.go:827`); it is
not auto-accepted from the netmap. **Auto-update→RCE is blocked** by
`clientupdate/distsign` pinned-root signature verification (a repointed control
cannot serve a validly-signed binary).

## Proof of concept

- `poc/gate_logic_poc.go` — reproduces the exact `csrfProtect` + login-mode
  `authorizeRequest` gate. Output (`poc/gate-logic-output.txt`):
  ```
  legit localhost POST (same-origin)        Host=localhost:8088 -> ACCEPTED (repoint reaches serveTailscaleUp)
  DNS-REBOUND page: evil.com -> 127.0.0.1   Host=evil.com:8088  -> ACCEPTED (repoint reaches serveTailscaleUp)
  DNS-REBOUND, no Sec-Fetch, Origin==Host   Host=evil.com:8088  -> ACCEPTED (repoint reaches serveTailscaleUp)
  plain cross-site CSRF (no rebinding)      Host=localhost:8088 -> REJECTED
  ```
- `poc/rebind.html` — attacker page performing the rebind + `POST /api/up`.
- `poc/repro.md` — end-to-end steps (disposable VM): (A) prove the server-side
  defect with a forged-Host `curl`, (B) the DNS-rebinding repoint, (C) the root
  SSH-policy ceiling with headscale/`cmd/testcontrol`.
- `poc/mock_control_note.md` — attacker control-server notes + the root
  `SSHPolicy`.

> Caveat stated honestly: modern browsers' Private Network Access protections
> may block a public page from fetching a loopback origin; this reduces the
> rebinding step's real-world reliability but does not fix the missing
> server-side defense (manage mode and the LocalAPI both still enforce it).

## Remediation

Apply the manage-mode protections to login/readonly mode: call
`requireTailscaleIP` (or, for a localhost listener, a strict `Host` allowlist of
`localhost`/loopback) and set CSP + `X-Frame-Options` for all modes; and/or
require a synthesized CSRF token (not just `Sec-Fetch-Site`/`Origin`) for
`POST /api/up`. Consider refusing `ControlURL`/`AuthKey` changes from the
web `/api/up` path entirely.

## References
- `client/web/web.go`: `serve` (:334), `requireTailscaleIP` (:389, manage-only
  call at :335), `csrfProtect` (:241), `authorizeRequest` (:473),
  `serveLoginAPI` (:519), `serveTailscaleUp`/`tailscaleUp` (:1136-1213)
- `ssh/tailssh/tailssh.go:606` (SSHPolicy from netmap), `feature/remoteconfig`,
  `net/dns/manager.go:378`, `clientupdate/distsign` (update blocked)
- Prior art: CVE-2022-41924 (LocalAPI DNS-rebinding), CVE-2022-41925

## Disclosure
Reported privately to Tailscale (HackerOne / security@tailscale.com). No public
disclosure until a fix ships / per program policy.
