# Taildrive WebDAV symlink escape — arbitrary file read/write outside a share root

**Component:** `drive/driveimpl` (Taildrive / `tailscale drive`) + vendored
`github.com/tailscale/xnet/webdav`
**Affected version:** Tailscale v1.104.1 (confirmed), and current `main` at review
time (unfixed)
**Reporter:** (your name / HackerOne handle)
**Severity:** High impact (confidentiality + integrity); **CVSS:3.1
`AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` ≈ 6.5**. See *Severity & preconditions*.

---

## Summary

Taildrive serves each shared directory with
`github.com/tailscale/xnet/webdav`'s `webdav.Dir`
(`drive/driveimpl/fileserver.go:104`). `webdav.Dir` confines `..` path
traversal but does **not** confine symbolic links: it resolves a request path
with `filepath.Join` + `slashClean` and then calls `os.OpenFile`, which follows
any symlink in the resulting path. A tailnet peer who has been granted access to
a share (read-only is enough to read; read-write to write) can therefore read —
and with a `rw` grant, overwrite — any file **outside** the share root that a
symlink inside the shared tree points to, as the account serving the share.

This breaks the two guarantees a Taildrive share is supposed to provide: the
share-root boundary, and the read-only-to-a-single-folder restriction.

## Affected code

- Taildrive constructs the WebDAV filesystem with no symlink confinement:
  ```go
  // drive/driveimpl/fileserver.go:104
  s.shareHandlers[share] = &webdav.Handler{
      FileSystem: &birthTimingFS{&normalizingFS{webdav.Dir(path)}},
      LockSystem: webdav.NewMemLS(),
  }
  ```
  `normalizingFS` (`drive/driveimpl/normfs.go`) and `birthTimingFS`
  (`drive/driveimpl/birthtiming.go`) add Unicode-normalisation and birth-time
  behaviour only; neither adds symlink confinement.

- The vendored library (`github.com/tailscale/xnet` pinned at
  `v0.0.0-20240729143630-8497ac4dab2e` in `go.mod`) — confirmed by fetching the
  fork at that commit:
  ```go
  // webdav/file.go
  func (d Dir) resolve(name string) string {
      if filepath.Separator != '/' && strings.IndexRune(name, filepath.Separator) >= 0 ||
          strings.Contains(name, "\x00") {
          return ""
      }
      dir := string(d)
      if dir == "" { dir = "." }
      return filepath.Join(dir, filepath.FromSlash(slashClean(name)))   // blocks "..", not symlinks
  }
  func (d Dir) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error) {
      if name = d.resolve(name); name == "" { return nil, os.ErrNotExist }
      f, err := os.OpenFile(name, flag, perm)                           // follows symlinks
      ...
  }
  ```
  There is no `Lstat`, `O_NOFOLLOW`, `openat2(RESOLVE_BENEATH)`, or
  `EvalSymlinks` containment anywhere in the fork's `webdav` package.

## Request path (how a peer reaches it)

1. Peer → peerapi `GET/PUT /v0/drive/<share>/<path>`
   (`ipn/ipnlocal/peerapi_drive.go:88`). Peer identity is WireGuard-authenticated
   via `WhoIs` (`ipn/ipnlocal/peerapi.go:222`); the Taildrive grant comes from the
   control netmap (`peercap.Taildrive`, `peerapi.go:642`) and is **not** forgeable
   — the attacker is a legitimately-granted but hostile (or compromised) peer.
2. → `ServeHTTPWithPerms` (`drive/driveimpl/remote_impl.go:202`): checks the
   grant (`rw` required for write methods; `PermissionNone` shares filtered out).
3. → compositedav reverse-proxy → the per-share `webdav.Handler` above →
   `webdav.Dir(sharePath).OpenFile(path)` → `os.OpenFile` follows the symlink.

The `..` path component is cleaned at every hop
(`shared.CleanAndSplit`, `drive/driveimpl/shared/pathutil.go:28`) — so classic
traversal is correctly blocked. Symlinks bypass all of that because the cleaned
path still resolves, as a real filesystem path, through the symlink.

## Proof of concept

`poc/poc_test_webdav_symlink.go` exercises the **exact vendored library** the
shipped binary uses. It creates a share root, a secret file outside it, and a
symlink inside the share pointing at the secret — then performs the same
`webdav.Dir(share).OpenFile("/link")` call Taildrive makes.

```
$ cd poc && go run .
[READ ESCAPE] GET /link returned out-of-root file:
  "TOP-SECRET: this file is OUTSIDE the share root\n"
[CONTROL] '..' traversal correctly blocked: open /tmp/taildrive-share-.../etc/hostname: no such file or directory
[WRITE ESCAPE] out-of-root file now contains:
  "OVERWRITTEN by a WebDAV peer through the symlink\n"
```

Read escape and write escape both succeed against the real `tailscale/xnet`
fork; `..` traversal is blocked, demonstrating the gap is specifically symlink
confinement. (`poc/run-output.txt` captures a run.)

### End-to-end reproduction on a live tailnet
1. On node **V**: `tailscale drive share projects /home/alice/projects` and
   grant node **A** access (`ro` is sufficient for the read case) via an ACL
   `grants` entry with a `tailscale.com/cap/drive` capability for that share.
2. Ensure the shared tree contains a symlink pointing outside it — e.g. a
   checkout with `node_modules`/config symlinks, or `ln -s /etc/passwd
   /home/alice/projects/notes` (common in real home/project directories).
3. From node **A**: `curl` the Taildrive endpoint for that path (via the peer's
   Taildrive mount, or directly against peerapi `/v0/drive/projects/notes`).
   The response is the out-of-root target's contents.

## Live confirmation (real tailscaled, two nodes)

Reproduced end-to-end on real hardware on 2026-10-25:
- Sharer **tkm** (tailscale **1.104.1**) shared `/tmp/td-poc/share` as `poc`; the
  share contained `link_to_secret -> /tmp/td-poc/secret/secret.txt` and
  `link_to_etc_hostname -> /etc/hostname`, both pointing outside the share root.
- Reader **pi5** (a Raspberry Pi, tailscale 1.102.2), granted Taildrive access,
  read via its local WebDAV: `curl http://100.100.100.100:8080/<tailnet>/tkm/poc/<path>`:
  - `normal.txt` (control) → `normal file in share`
  - `link_to_secret` → `SECRET-OUTSIDE-SHARE … the share boundary was escaped`
  - `link_to_etc_hostname` → `tkm`  (the sharer's `/etc/hostname`)

The peer read files **outside** the shared directory through symlinks inside it,
confirming the source-traced peerapi `/v0/drive` → `webdav.Dir.OpenFile` path on
real tailscaled, not just the library-level PoC above.

## Impact

- **Confidentiality:** a share-granted peer reads any file the serving account
  can read, outside the shared folder (SSH keys, `/etc/passwd`, other users'
  data, app secrets) via any symlink present in the shared tree.
- **Integrity:** with a `rw` grant, the peer overwrites those out-of-root files
  through the symlink.
- Escapes both the share-root boundary and the "read-only, one folder" intent
  an operator relies on when sharing.

The serving process runs as the **sharing user**, not root (on unix Taildrive
drops to the per-user `serve-taildrive` subprocess via su/sudo and refuses to
run as root — `drive/driveimpl/remote_impl.go:327`), so this is not direct root
compromise, but it is a full file-level boundary escape for that user.

## Severity & preconditions

- Attacker must be a peer **granted** the share (ACL-controlled; a hostile or
  compromised authorised peer, or a shared-to node).
- A symlink pointing outside the share must **already exist** in the shared
  tree. The attacker cannot create one over WebDAV (no symlink verb: `PUT`
  writes a regular file, `MKCOL` a directory). This is the main severity
  limiter and the reason for `AC:H` / `PR:L`.
- Realistic whenever a home directory, source checkout, or `/var/www`-style tree
  is shared — symlinks to outside those trees are common.

## Remediation

Confine symlink resolution to the share root. Options:
- open files with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on Linux (and
  the equivalent on other platforms), or
- after `resolve`, `filepath.EvalSymlinks` the result and verify it is still
  within the share root before `os.OpenFile`, or
- add a confining `FileSystem` wrapper in `drive/driveimpl` rather than relying
  on `webdav.Dir`.

## References
- `drive/driveimpl/fileserver.go:104`
- `github.com/tailscale/xnet/webdav/file.go` (`Dir.resolve`, `Dir.OpenFile`) @ `8497ac4dab2e`
- `ipn/ipnlocal/peerapi_drive.go:88`, `drive/driveimpl/remote_impl.go:202`

## Disclosure
Reported privately to Tailscale (HackerOne / security@tailscale.com). No public
disclosure until a fix ships / per program policy.
