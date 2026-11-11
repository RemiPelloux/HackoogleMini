<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:0d1117&height=220&section=header&text=REA%20Lab&fontSize=90&fontColor=58a6ff&animation=twinkling&fontAlignY=38&desc=Reverse%20Engineering%20Investigations%20%E2%80%94%20Claude%20%2B%20MCP&descAlignY=58&descSize=20&descColor=8b949e" width="100%" />

  <a href="https://git.io/typing-svg">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=15&duration=2800&pause=1200&color=58A6FF&center=true&vCenter=true&width=640&lines=Binary+analysis+across+firmware%2C+native+%26+web;Chrome%2F92+CVE-2021-30563+exploitation+research;Cast+protocol+MITM+%2B+DNS+injection+chain;Tailscale+%E2%80%94+zero+Arch+patches+confirmed;GhostCLI+%E2%80%94+5+real+models+behind+7+IDs" alt="Typing SVG" />
  </a>

  <br/><br/>

  ![Investigations](https://img.shields.io/badge/investigations-3-58a6ff?style=flat-square&logo=searxng&logoColor=white)
  ![REA](https://img.shields.io/badge/powered%20by-REA%206.8-5c4ee5?style=flat-square)
  ![Claude](https://img.shields.io/badge/agent-Claude%20Code-cc785c?style=flat-square&logo=anthropic&logoColor=white)
  ![License](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)
  ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)
</div>

---

A personal lab for structured reverse-engineering investigations driven by [REA](https://github.com/morluto/rea) — the MCP server that connects Claude Code to Ghidra, IDA, JADX, and runtime instrumentation. Each folder is a self-contained case: target artifacts, raw evidence, analysis notes, and clean-room reconstructions. Work spans embedded Linux firmware, native Go binaries, Cast protocol internals, vulnerability surface mapping, and JavaScript bundle archaeology.

> **Toolchain:** [REA](https://github.com/morluto/rea) · Ghidra 12 · Claude Code (Sonnet / Opus) · Python 3 · Frida

---

## Investigations

| Investigation | Target | Method | Key Finding | Status |
|---|---|---|---|---|
| [🔊 googlehomemini](./googlehomemini/) | Google Home Mini gen 1 — Marvell Armada 1500, fw `3.78.540761` | BLE setup API · Cast MITM · DNS injection · CVE-2021-30563 (Chrome/92 V8) · NAND tooling | No UART/JTAG on H0A; Cast registry MITM via AdGuard DNS rewrite unblocks `cast_shell` exploit chain | 🔬 Active |
| [🔒 tailscale](./tailscale/) | `tailscaled` + `tailscale` v1.104.1 (Arch pkg) | Go binary inspection · build provenance · dependency surface | Zero Arch patches — upstream v1.104.1 is an exact logic match; 71 Go modules mapped (wireguard-go, gvisor, TPM, WireGuard) | ✅ Baseline done |
| [👻 ghostcli](./ghostcli/) | GhostCLI API (`ghostcli.cloud`) | 28 JS bundle chunks · static analysis · live probes | 5 real models behind 7 advertised IDs; full alias map recovered; `z-ai/glm-5.3` vendor hidden | ✅ Report done |

---

## How it works

```mermaid
flowchart LR
    T([Target\nbinary / firmware / API])
    R[REA MCP\nnpx rea-agents setup]
    E[(Evidence\nevidence/*.json)]
    N[Notes\nfindings.md\narchitecture.md]
    RC[Reconstruction\nclean-room impl]

    T --> R
    R --> G[Ghidra / IDA / JADX]
    R --> F[Frida runtime]
    R --> W[Web / ADB / BLE]
    G --> E
    F --> E
    W --> E
    E --> N
    N --> RC
```

Each investigation follows the same layout:

```
<name>/
  target/       artifacts under investigation (binaries, firmware — not in git)
  evidence/     raw REA JSON output, one file per command
  notes/        findings.md · architecture.md · plan docs
  reconstruction/  clean-room implementation derived from notes
  scripts/      recon, analysis, and exploit tooling
```

---

## Quick start

```bash
git clone https://github.com/RemiPelloux/rea-lab
cd rea-lab

# Install REA + wire up to Claude Code
npx rea-agents setup

# Scaffold a new investigation
./new-rea.sh my-target

# Source REA env inside an investigation
source my-target/scripts/rea-env.sh
```

Then open Claude Code in the new folder and start with the `reverse-engineer-anything` skill.

---

## Adding an investigation

1. `./new-rea.sh <name>` — copies `_template/` with the right CLAUDE.md wired in.
2. Put artifacts in `<name>/target/` (never modified, never committed raw).
3. Use `scripts/ev.sh` to run REA commands and save results to `evidence/`.
4. Write conclusions in `notes/findings.md`, citing evidence files.
5. Open a PR — see the [investigation proposal template](.github/ISSUE_TEMPLATE/new-investigation.yml).

---

## Sponsor

If this work saves you time or sparks an idea, consider supporting it.

<div align="center">
  <a href="https://github.com/sponsors/RemiPelloux">
    <img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?style=for-the-badge&logo=github-sponsors&logoColor=white" alt="Sponsor on GitHub" />
  </a>
  &nbsp;
  <a href="https://ko-fi.com/RemiPelloux">
    <img src="https://img.shields.io/badge/Ko--fi-Support-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Support on Ko-fi" />
  </a>
</div>

---

<div align="center">
  <sub>Built with <a href="https://github.com/morluto/rea">REA</a> · Driven by <a href="https://claude.ai/code">Claude Code</a> · MIT License</sub>
  <br/>
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:0d1117&height=100&section=footer" width="100%" />
</div>
