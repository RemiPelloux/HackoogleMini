#!/usr/bin/env python3
"""Decode every gzip payload in a BLE GATT dump, including truncated ones.

The Google Home setup service exposes some values capped at exactly 512 bytes,
which is shorter than the gzip stream. `gzip.decompress` refuses those, but
`zlib.decompressobj` returns everything it can inflate before the stream breaks --
and 512 compressed bytes is usually 1-1.5 KB of JSON, which is enough to recover
the device identity, capabilities, MAC and certificate prefix.

Usage: scripts/decode_gatt.py evidence/<dump>.json [more.json ...]
"""
import json
import sys
import zlib


def hexes(obj, path="", acc=None):
    """Collect (path, bytes) for every hex-looking string in a nested structure."""
    if acc is None:
        acc = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hexes(v, f"{path}.{k}" if path else str(k), acc)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hexes(v, f"{path}[{i}]", acc)
    elif isinstance(obj, str):
        s = obj.strip()
        if len(s) >= 16 and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                acc.append((path, bytes.fromhex(s)))
            except ValueError:
                pass
    return acc


def inflate_partial(b):
    """Best-effort inflate; returns (data, complete)."""
    d = zlib.decompressobj(31)  # 31 = gzip wrapper, auto header
    try:
        out = d.decompress(b)
        if d.eof:
            return out, True
        # a truncated stream still yields most of the payload
        return out, False
    except zlib.error:
        return b"", False


def main():
    for dump in sys.argv[1:]:
        print(f"\n########## {dump}")
        doc = json.load(open(dump))
        seen = set()
        for path, raw in hexes(doc):
            if raw[:2] != b"\x1f\x8b":
                if raw and len(raw) >= 4:
                    txt = raw.decode("utf-8", "replace")
                    printable = sum(c.isprintable() for c in txt) / len(txt)
                    if printable > 0.85 and raw not in seen:
                        seen.add(raw)
                        print(f"\n--- {path}  ({len(raw)}B plain) ---")
                        print("   ", txt[:300])
                continue
            if raw in seen:
                continue
            seen.add(raw)
            out, complete = inflate_partial(raw)
            state = "complete" if complete else "TRUNCATED (partial inflate)"
            print(f"\n--- {path}  ({len(raw)}B gz -> {len(out)}B, {state}) ---")
            print(out.decode("utf-8", "replace")[:4000])


if __name__ == "__main__":
    main()
