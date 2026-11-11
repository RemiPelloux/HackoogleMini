# target/

Drop artefacts under investigation here. Never modify them — REA paths must be
absolute and the originals stay byte-identical.

Expected contents as the investigation progresses:

| File | Where it comes from | Used for |
| --- | --- | --- |
| `*.bin` / `*.img` | OTA payload or hardware flash dump | `scripts/fw-analyze.sh` |
| `firmware.bin_extract/**` | produced by REA, keep out of git | Ghidra per-binary work |
| `*.so` / `cast_shell` | extracted from the image | `scripts/ghidra-headless.sh`, `rea analyze` |

Not a target (do not expect USB to work): the Mini's micro-USB is power-only, and
no USB device enumerates. Board-level access is UART/eMMC, not USB.
