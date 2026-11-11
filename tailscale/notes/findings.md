# tailscale: findings

## Question

Initial REA pass on the locally-installed Tailscale binaries (Arch package
`tailscale 1.104.1-1`): establish artifact identity, build provenance, and the
dependency surface as a baseline for deeper feature investigation.

## Target

| Field    | Value |
| -------- | ----- |
| Artifacts | `target/tailscaled` (daemon), `target/tailscale` (CLI) — copied from `/usr/bin` |
| SHA-256 (tailscaled) | `c2c311f11e35296498128c5fb563fc2e3bb1d92de3a6419e862a394e1b469467` |
| SHA-256 (tailscale)  | `e4c753ebff48894f7eb6116dd810fd1d0dd10c510a1917950997e9b5d7a7eb01` |
| Platform | Linux ELF 64-bit PIE, x86-64 (GOAMD64=v1), dynamically linked, stripped |
| Version  | `v1.104.1+dirty` (Arch pkg `1.104.1-1`, packager Lukas Fleischer) |

## Findings

- **tailscaled is a Go program built with `go1.27.1-X:nodwarf5`**, module
  `tailscale.com/cmd/tailscaled`, main module `tailscale.com v1.104.1+dirty`.
  Built `-buildmode=pie`, `-compiler=gc`, `CGO_ENABLED=1`, `GOOS=linux`,
  `GOARCH=amd64`, `GOAMD64=v1`, `GOEXPERIMENT=nodwarf5`.
  — evidence/20261025-01-inspect_go_binary-tailscaled.json (ev_b292a9e4…)

- **The binary is upstream v1.104.1 + `go mod vendor`, with NO distro code
  patches.** The two embedded hashes identify the *same* release, not two
  commits: `7f4efe814ff14b064eb080344389ceb9ea2d37ac` is the **annotated tag
  object** `v1.104.1` (what `-X version.gitCommitStamp=$(git rev-parse v1.104.1)`
  resolves to, and what `tailscale version` prints), while
  `9a522a9786c97eb7910c01ccb7bd66557b04c910` is the **commit** that tag points
  to (`vcs.revision`, confirmed: `git rev-list -n1 v1.104.1` == this).
  `vcs.modified=true` / `+dirty` comes solely from `go mod vendor` adding
  `vendor/` to the checked-out tag tree. The Arch PKGBUILD's `source=()` has no
  patch files and `prepare()` only vendors — so **upstream v1.104.1 source is an
  exact logic match for this binary's Go code**.
  — evidence/20261025-02-arch-pkgbuild.json

- **CGO build used Arch's hardened toolchain flags** (makepkg defaults):
  `_FORTIFY_SOURCE=3`, `-fstack-clash-protection`, `-fcf-protection`, linker
  `-z relro -z now`, `pack-relative-relocs`. Build tag is `xversion` only — a
  default feature set, no extra feature tags. — evidence 01 + 02.

- **Dependency surface (71 modules)** confirms the expected Tailscale
  architecture: `github.com/tailscale/wireguard-go` (userspace WireGuard),
  `gvisor.dev/gvisor` (userspace netstack for subnet routing / userspace mode),
  `golang.org/x/crypto v0.57.0` + `filippo.io/edwards25519` +
  `hdevalence/ed25519consensus` (key crypto), `github.com/google/go-tpm`
  (TPM-sealed identity), `coder/websocket` (DERP/control over WS), netlink/
  nftables/iptables stack (Linux routing & firewall), `aws-sdk-go-v2`
  (ssm/sso/sts — SSM console / AWS integrations), and
  `tailscale/web-client-prebuilt` (embedded web UI). — same evidence.

## Unknowns and limitations

- Go build metadata is observed file content, not proof of compiler identity,
  dependency authenticity, or any runtime behavior.
- `inspect_go_binary` recovers only build info — no function names, type
  metadata, or decompiled code. Both binaries are **stripped** ELFs; deeper
  work needs a Ghidra native session (`open_binary`) or runtime observation.
- The `tailscale` CLI binary's Go build info has not yet been read (identity/
  hash recorded only).

## Reconstruction plan

None requested yet — this is a baseline identity/provenance pass. Candidate
next steps when a concrete feature question is chosen:
- `open_binary` (Ghidra) on `tailscaled` for symbol/function recovery, or
- static string/segment survey, or
- runtime observation of a specific subsystem (netstack, DERP, control auth).

---

## Vuln hunt — candidate findings (v1.104.1, all upstream-UNFIXED unless noted)

Six parallel source audits (one per surface) + post-tag git analysis. Full
per-finding detail in `evidence/20261025-04..07`. Nothing has been reported to
Tailscale; these are for review first.

### Strongest candidates (novel, confirmed, unfixed upstream)

1. **Taildrop `nextFilename` panic** — `feature/taildrop/taildrop.go:287`.
   A file-sharing-capable peer sends a Taildrop file named `x (1) (` (passes
   `validateBaseName`), then re-sends the same name at a different size →
   dedup calls `nextFilename` → `name[7:6]` slice-bounds panic. **Runtime-
   confirmed** (`scripts/repro-taildrop-nextfilename/`). Contained by net/http
   per-connection panic recovery → failed transfer + logged panic, not a daemon
   crash. Severity Low. ev04.

2. **ICMP ACL-scope bypass** — `wgengine/filter/match.go:74-82`. The
   `matchIPsOnly` capability branch returns Accept on any `SrcCaps`/`hasCap`
   hit **without checking that rule's `Dsts`** (the non-cap branch and the
   TCP/UDP `match()` both scope by dst). A peer holding a capability used in
   *any* `SrcCaps` rule can ICMP every IP in `localNets` — on a subnet
   router/exit node that's the whole advertised subnet → recon beyond the
   rule's intended scope. Confirmed by inspection; runtime unit test described
   in ev05. Severity Low-Med.

3. **Web client `/api/data` over-disclosure** — `client/web/web.go`
   `authorizeRequest` + `serveGetNodeData`. Manage-mode `GET /api/data` is
   authorized before the ownership/session check, and the payload is never
   redacted, so a non-owner / **tagged** tailnet peer that ACLs let reach
   `:5252` reads the owner `UserProfile`, `ControlAdminURL`, and (on Unraid)
   `UNRAID_CSRF_TOKEN`. Confirmed by inspection. Severity Medium (info
   disclosure; needs web client enabled + ACL reachability). ev06.

### Secondary candidates (ev07)

- `tailscale web` login/readonly mode has **no anti-DNS-rebinding/Host guard**
  (only manage mode does) → same-origin-rebinding CSRF to `POST /api/up`
  (reauth, read auth URL, or on a stopped node point it at an attacker control
  server). Precondition: user ran `tailscale web`. Medium; real-world gated by
  browser Private-Network-Access.
- Ungated localapi handlers (`serveDial` TCP-over-tailnet proxy, `servePing`,
  `serveUploadClientMetrics`, `serveDERPMap`, debug bus) lack
  `PermitRead/PermitWrite` → local defense-in-depth gap for a non-operator
  user with socket access (not remotely reachable).

### Checked and sound (negatives)

- SSH (`ssh/tailssh`): authz, principal matching, privilege-drop order, and the
  HoldAndDelegate "check" URL (dials control over Noise regardless of URL host —
  no SSRF) all fail closed. Its one gate gap (SFTP skips recording) is already
  fixed upstream (`729cd431b`) = known.
- DNS: in-process forwarder never parses upstream records → no malformed-
  response memory bug; ExitDNS peer queries are ACL-gated.
- DERP/control: frame + MapResponse parsers cap lengths and bounds-check; DERP
  client is fuzzed. Caps on control responses are defense-in-depth (control is
  trusted).
- netstack: inbound DNAT/loopback/4via6 paths are ACL-gated with explicit RST
  guards naming the SSRF/loopback risks; fragment handling blocks RFC-1858
  overlap smuggling.

### Follow-ups not yet done

- `magicsock` `addDerpPeerRoute` unbounded per-connection growth (DoS) — raised
  by the DERP audit, outside its scope.
- Runtime unit test to make finding #2 airtight.
- Optional: REA/Ghidra confirmation that the shipped binary's Taildrop code
  matches source (expected identical; distro = upstream + vendor).

---

## HIGH / CRITICAL focus (round 2)

Refocused per user: only High/Critical or chains to them. Update→RCE path was
ruled out (distsign pinned roots, ev08); pre-auth/on-LAN parsers ruled out
(ev09).

### CHAIN — login-mode web client → control-server repoint (ceiling: CRITICAL root RCE) · ev11
Root cause: the anti-DNS-rebinding guard (`requireTailscaleIP`) + CSP/XFO run
**only in manage mode**; `tailscale web` login mode (default `localhost:8088`)
has none, and `POST /api/up` there needs no session — only `csrfProtect`, which
a same-origin DNS-rebound page satisfies. This is the CVE-2022-41924 class,
fixed for manage mode but absent in login mode.
- Repoint works only on a **non-running** node (`if !isRunning`), i.e. exactly
  the state during a `tailscale web` login; attacker sends
  `{"Reauthenticate":true,"ControlURL":"https://attacker","AuthKey":"…"}`.
- Ceiling once repointed (malicious control server):
  - **Default-on:** full **DNS interception** (`--accept-dns` defaults true) →
    MITM of all name resolution. **HIGH.**
  - **If `--ssh` enabled:** control authors an unsigned root `SSHPolicy` →
    interactive **root shell = RCE. CRITICAL.**
  - **If `RemoteConfig` enabled (default off):** r/w LocalAPI proxy → turn SSH
    on itself → root RCE. **CRITICAL.**
  - Exit-node/subnet L3 MITM is *not* reachable without a user pref (good).
- Preconditions: `tailscale web` login running + non-running node + browser
  allows public→loopback rebinding (modern Private-Network-Access may block).

### HIGH — Taildrive WebDAV symlink escape · ev10
Vendored `tailscale/xnet/webdav.Dir` (pinned `8497ac4dab2e`, confirmed by
fetching the fork) blocks `..` but does **not** confine symlinks (`resolve()` =
`filepath.Join`+`slashClean` then `os.OpenFile`; no `O_NOFOLLOW`/`openat2`/
`EvalSymlinks`). A tailnet peer granted a Taildrive share (ro suffices for read,
rw for write) that contains a symlink pointing outside the share root reads/
writes the target **as the serving (unprivileged, per-user) account** — escaping
the share-root and read-only-to-one-folder boundaries. Attacker can't *create*
the symlink over WebDAV, so one must pre-exist in the shared tree (common when
sharing a home/project dir). Unfixed upstream.

### Additional High/Critical negatives (ruled out)
- Auto-update via malicious control: **blocked** by distsign pinned-root
  signature verification (ev08).
- Unauth/on-LAN parsers (portmapper/STUN/PCP/NAT-PMP/geneve/disco): bounds-
  checked + crypto-gated; only a Medium UPnP control-URL SSRF, real XML/SOAP
  parsing is in out-of-tree goupnp (ev09).
- serve/funnel: no attacker-chosen backend; proxy-to-tailscaled-socket refused;
  identity headers stripped (Taildrive agent).
- Tailscale SSH *direct* path (not via repoint): authz/priv-drop/check-URL all
  fail closed.

### Status
Strongest reportable: the **web-login rebinding → control repoint chain** (root
cause is a missing, already-known-class server-side defense; critical ceiling)
and the **Taildrive symlink escape** (High, confirmed). Both unfixed upstream.

---

## Round 3 — deeper High/Critical hunt (TKA, disco, UDP relay, Funnel)

Send-ready (verified, clean):
- **Funnel underscore identity-header passthrough (HIGH)** — ev13. Identity headers Del'd only in dash case; `Tailscale_User_Login` (underscore) survives and is forwarded on the funnel path (where the real dash header is absent), spoofing identity at backends that conflate `_`/`-` (CGI/PHP/FastCGI). Verified with Go's canonicalization.
- **CallMeMaybeVia reflection/amplification + client DoS (HIGH)** — ev14. No `ClientDisco`-membership check and no `AddrPorts` cap; victim emits a Bind to every attacker-supplied AddrPort → DDoS reflection to arbitrary internet IPs + client resource exhaustion. Default-on (relayClientEnabled; relayCapable self-advertised).

Promising but need runtime PoC before sending:
- **TKA delta-path unsigned-peer filter bypass (HIGH if confirmed)** — ev15. Delta `PeersChanged` path skips the unlocked-nodes packet-filter fail-closed guard, so a malicious control can inject a data-plane-reachable `UnsignedPeerAPIOnly` peer (AllowedIPs still stripped to its own addr). TKA crypto core verified SOUND. Needs integration test.
- **Disco key-check inversion (uncertain)** — ev16. `unambiguousNodeKeyOfPingLocked` UDP branch uses `!knownKey` vs the DERP sibling's `knownKey`; a hostile member could poison receive-path epAddr→nodekey mapping. origin/main is byte-identical (no upstream fix), branch also covers a benign bootstrap case, impact capped by WG crypto. NOT send-ready.

Lower / noted:
- Relay server alloc exhaustion (MEDIUM, ACL-gated) — ev17.
- serve/Funnel static-dir symlink read (candidate, internet-facing sibling of Taildrive) — ev12.

Negatives: TKA signature/AUM crypto core is sound (forgery needs trusted key material); disco wire parsers are uniformly length-bounded; relay 3-way bind handshake is source-bound MAC + disco-sealed (no off-path reflection via server).

- **Taildrive symlink escape: LIVE-confirmed on real hardware (2026-10-25)** — tkm(1.104.1) shared a dir; pi5 read files outside the share root via symlinks (secret + /etc/hostname). See evidence/20261025-18.
