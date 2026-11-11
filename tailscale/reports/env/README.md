# Executable PoC environment

Pick the lightest path that works for you.

## Option 0 — bubblewrap sandbox + static binaries (EASIEST, no Docker/daemon/root)
Prebuilt static binaries in `env/bin/` run inside a rootless `bwrap` sandbox
(no network, tmpfs-only root). Verified working on this host.
```
reports/env/run_sandbox.sh          # runs both PoCs, sandboxed
reports/env/build.sh                # rebuild the static binaries (needs Go >=1.27)
```
Needs only `bubblewrap` (`bwrap`), already present here (Arch: `pacman -S bubblewrap`).

## Option 1 — local, no sandbox
Runs the PoCs with the mise Go directly (first run fetches `tailscale/xnet`).
```
reports/env/run_local.sh
```

## Option 2 — Docker (portable, but needs the daemon)
```
sudo systemctl start docker
cd reports && docker build -f env/Dockerfile -t ts-pocs . && docker run --rm ts-pocs
```

All three produce the same result:
- Taildrive: `[READ ESCAPE]` + `[WRITE ESCAPE]` out of the share root, `..` blocked
  — against the REAL vendored `tailscale/xnet/webdav`.
- Web chain: login-mode gate ACCEPTS rebound/same-origin `POST /api/up`, REJECTS
  plain cross-site.

Live-tailnet reproduction (two nodes + attacker control + DNS rebinding):
`../webclient-rebind-control-repoint/poc/repro.md` (disposable VM only).

---
### Note on `open0day`
`open0day`'s `lift`/`analyze` run inside Docker OCI images (`open0day/lifter`,
`open0day/wsolver`) — a bwrap/unshare sandbox cannot substitute those, so that
pipeline needs Docker (or rootless Docker / podman). `scan-src` (no Docker) was
run on the source tree: 0 candidates (expected for a Go codebase). Prepared
runner for when Docker is available: `env/run_open0day.sh`.
