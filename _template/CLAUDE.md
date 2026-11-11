# REA investigation: {{NAME}}

Created {{DATE}}. This folder is one reverse-engineering investigation run with REA
(Reverse Engineer Anything, `rea` CLI + `rea` MCP server, skill `reverse-engineer-anything`).

## Layout

| Path              | Contents                                                              |
| ----------------- | --------------------------------------------------------------------- |
| `target/`         | The artifacts under investigation (binaries, APKs, ASARs, firmware…)  |
| `evidence/`       | Raw REA JSON output, one file per command (`<step>-<command>.json`)   |
| `notes/findings.md` | Conclusions, each linked to the evidence file that supports it      |
| `reconstruction/` | Our own implementation of the feature, if one is requested            |
| `scripts/`        | Helper scripts for this investigation                                 |

## How to work here

- Use the `reverse-engineer-anything` skill and the `rea` MCP tools; fall back to the
  `rea` CLI (`source scripts/rea-env.sh` first) when MCP is unavailable.
- Always pass absolute paths to REA (`$PWD/target/...`). Never modify files in `target/`.
- Save every CLI result with `--json` into `evidence/` and cite it in `notes/findings.md`.
  Keep unknowns and REA's stated limitations next to each conclusion.
- Native providers: **Ghidra** is the default (headless, always available).
  **IDA Free** is optional and attached: the user must open the original binary in IDA
  (`ida`), wait for analysis, then press Ctrl+Alt+M to start the MCP plugin on
  127.0.0.1:13337; then use `--provider ida` / `provider_id: "ida"`.
- `reconstruction/` is clean-room output: write it from `notes/findings.md`, never by
  copying decompiled code.
