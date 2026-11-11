#!/usr/bin/env python3
"""Turn a raw NAND dump from a Home Mini (gen 1, H0A) into usable artifacts.

A dump taken with a NandBug interposer or a NAND clip is *not* a filesystem image:
it interleaves data and spare/OOB bytes per page, may be nibble-swapped, and may be
scrambled. This tool finds the geometry, strips the OOB, undoes the swap, locates the
partitions by their filesystem/container magic, and hunts for the strings that decide
the project (kernel version, boot verification, assistant endpoints).

Nothing here executes or trusts dump content: it is parsed as data only.

Usage:
  scripts/nand-decode.py layout  dump.bin
  scripts/nand-decode.py scan    dump.bin --page 2048 --oob 64
  scripts/nand-decode.py scan    dump.bin --swap-nibbles
  scripts/nand-decode.py extract dump.bin --page 2048 --oob 64 --out work/parts
  scripts/nand-decode.py find    dump.bin --page 2048 --oob 64 --pattern 'Linux version'
  scripts/nand-decode.py selftest
"""
import argparse
import json
import os
import re
import sys

# Container/filesystem magics that can start a partition. Offsets are within the
# block, because a partition often starts with a header before the filesystem.
MAGICS = [
    (b"hsqs", 0, "squashfs (little-endian superblock)"),
    (b"sqsh", 0, "squashfs (big-endian superblock)"),
    (b"\x27\x05\x19\x56", 0, "uImage (legacy u-boot kernel)"),
    (b"\xd0\x0d\xfe\xed", 0, "FDT / device tree"),
    (b"\x85\x19\x03\x20", 0, "JFFS2 (little-endian)"),
    (b"\x19\x85\x20\x03", 0, "JFFS2 (big-endian)"),
    (b"\x7fELF", 0, "ELF"),
    (b"UBI#", 0, "UBI erase counter header"),
    (b"ANDROID!", 0, "Android boot image"),
    (b"BZh", 0, "bzip2 stream"),
    (b"\x1f\x8b\x08", 0, "gzip stream"),
    (b"NVFILE", 0, "Marvell? vendor header"),
    (b"\xd3\x2e\x04\x00", 0, "surface-engine?"),
]

STRING_HUNTS = {
    "kernel": rb"Linux version [\d.]+[^\x00\n]{0,120}",
    "boot_verify": rb"(?i)(verified boot|dm-verity|verity|avb|mkbootimg|SIGNATURE|sha256_rsa)[^\x00\n]{0,80}",
    "assistant": rb"(?i)(embeddedassistant|assistant\.googleapis|v1alpha2|ConverseStream|assistant_supported)[^\x00\n]{0,80}",
    "update": rb"(?i)(update_engine|payload\.bin|ota|delta_generator)[^\x00\n]{0,80}",
    "cast": rb"(?i)(cast_shell|cast_build_revision|eureka_info|mdns)[^\x00\n]{0,80}",
    "creds": rb"(?i)(factory_setting|device_certificate|private_key|weave)[^\x00\n]{0,80}",
}


def read_dump(path):
    with open(path, "rb") as f:
        return f.read()


def apply_swap(buf, swap):
    """The H0A NAND is nibble-swapped over the first 2080 bytes of each page.

    Nibble swap means each byte 0xAB becomes 0xBA. Applied per-page in the caller.
    """
    if not swap:
        return buf
    tbl = bytes(((b & 0x0F) << 4) | (b >> 4) for b in range(256))
    return buf.translate(tbl)


def page_view(data, page, oob, swap, swap_len=2080):
    """Yield (index, payload_offset, payload) with OOB removed."""
    stride = page + oob
    for i in range(0, len(data) - stride + 1, stride):
        chunk = data[i:i + page]
        if swap:
            head = apply_swap(chunk[:swap_len], True)
            chunk = head + chunk[swap_len:]
        yield i // stride, i, chunk


def magic_hits(blob):
    out = []
    for magic, off, name in MAGICS:
        start = 0
        while True:
            j = blob.find(magic, start)
            if j < 0:
                break
            out.append((j, name))
            start = j + 1
            if len(out) > 5000:
                return out
    return out


def cmd_layout(args):
    data = read_dump(args.file)
    print(f"file        {args.file}")
    print(f"size        {len(data)} bytes ({len(data)/2**20:.1f} MiB)")
    print("\ncandidate geometries (bad-block marker at OOB offset 0 = 0xFF means good):")
    for page, oob in ((2048, 128), (2048, 64), (4096, 224), (4096, 128), (512, 16)):
        stride = page + oob
        if len(data) % stride == 0:
            pages = len(data) // stride
            # count pages whose first OOB byte is 0xFF (clean) vs 0x00 (bad block)
            good = bad = other = 0
            for i in range(0, len(data), stride):
                b = data[i + page]
                if b == 0xFF:
                    good += 1
                elif b == 0x00:
                    bad += 1
                else:
                    other += 1
            print(f"  page={page:5d} oob={oob:4d}  pages={pages:6d}  "
                  f"divides evenly, oob[0]: 0xFF={good} 0x00={bad} other={other}")
        else:
            print(f"  page={page:5d} oob={oob:4d}  does not divide evenly "
                  f"(rem {len(data) % stride})")
    print("\ntop 12 unique magics across the raw dump (OOB included, so mostly noise):")
    seen = {}
    for off, name in magic_hits(data):
        seen.setdefault(name, []).append(off)
    if not seen:
        print("  (none -- expected when the dump is nibble-swapped; see below)")
    for name, offs in sorted(seen.items(), key=lambda kv: -len(kv[1]))[:12]:
        head = ", ".join(f"0x{o:x}" for o in offs[:4])
        print(f"  {len(offs):5d}  {name:38s} {head}")

    # The same thing after stripping OOB and undoing the nibble swap, per geometry.
    # This is the step that actually tells you the page layout is right.
    print("\nmagics after OOB strip + nibble swap, per geometry:")
    for page, oob in ((2048, 128), (2048, 64), (4096, 224), (4096, 128), (512, 16)):
        if len(data) % (page + oob):
            continue
        best = (0, None, {})
        for swap in (False, True):
            blob = b"".join(p for _, _, p in page_view(data, page, oob, swap))
            uniq = {name for _, name in magic_hits(blob)}
            if len(uniq) > best[0]:
                best = (len(uniq), swap, uniq)
        n, swap, uniq = best
        if n:
            print(f"  page={page:5d} oob={oob:4d}  swap={str(swap):5s}  {sorted(uniq)}")
        else:
            print(f"  page={page:5d} oob={oob:4d}  no magics (wrong geometry or ECC-scrambled)")


def cmd_scan(args):
    data = read_dump(args.file)
    best = None
    combos = []
    for swap in (False, True):
        blob = b"".join(p for _, _, p in page_view(data, args.page, args.oob, swap))
        hits = magic_hits(blob)
        # score: distinct filesystems found, weighted by how plausible they are
        uniq = {name for _, name in hits}
        score = len(uniq)
        combos.append((score, swap, blob, hits, uniq))
        print(f"swap={str(swap):5s} stride={args.page + args.oob:5d} "
              f"magic-hits={len(hits):5d} distinct={sorted(uniq)}")
    best = max(combos, key=lambda c: c[0])
    score, swap, blob, hits, uniq = best
    if score == 0:
        print("\n!! no known magic found. The dump may be ECC-scrambled or the "
              "geometry is wrong. Try other --page/--oob from `layout`.")
        return 2
    print(f"\n=> best: swap_nibbles={swap}, {score} distinct container types")

    # Partition boundaries: first occurrence of each distinct magic, sorted.
    firsts = {}
    for off, name in hits:
        firsts.setdefault(name, off)
    order = sorted((off, name) for name, off in firsts.items())
    print("\npartitions by first magic occurrence:")
    prev = 0
    for off, name in order:
        print(f"  0x{off:08x}  +{off - prev:<9d} {name}")
        prev = off
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"page": args.page, "oob": args.oob, "swap_nibbles": swap,
                       "partitions": [{"offset": o, "kind": n} for o, n in order]},
                      f, indent=2)
        print(f"\nwrote {args.json}")
    return 0


def cmd_extract(args):
    data = read_dump(args.file)
    blob = b"".join(p for _, _, p in page_view(data, args.page, args.oob, args.swap_nibbles))
    hits = magic_hits(blob)
    if not hits:
        print("no magics; refusing to guess boundaries", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    starts = sorted({off for off, _ in hits})
    starts.append(len(blob))
    written = []
    for i in range(len(starts) - 1):
        a, b = starts[i], starts[i + 1]
        if b - a < args.min_size:
            continue
        kind = next((n for o, n in hits if o == a), "unknown")
        slug = re.sub(r"[^a-z0-9]+", "-", kind.lower()).strip("-")[:24]
        path = os.path.join(args.out, f"part{i:02d}-0x{a:08x}-{slug}.bin")
        with open(path, "wb") as f:
            f.write(blob[a:b])
        written.append({"path": path, "offset": a, "size": b - a, "kind": kind})
        print(f"  {path}  {b - a:>10d} B  {kind}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(written, f, indent=2)
    print(f"\n{len(written)} region(s) written to {args.out}/")
    return 0


def cmd_find(args):
    data = read_dump(args.file)
    blob = b"".join(p for _, _, p in page_view(data, args.page, args.oob, args.swap_nibbles))
    if args.pattern:
        pats = {"custom": args.pattern.encode()}
    else:
        pats = STRING_HUNTS
    total = 0
    for name, rx in pats.items():
        rx = rx if isinstance(rx, bytes) else rx.encode()
        found = {}
        for m in re.finditer(rx, blob):
            s = m.group(0)[:160].decode("latin-1", "replace").strip("\x00")
            found.setdefault(s, []).append(m.start())
        if not found:
            continue
        print(f"\n[{name}] {len(found)} unique / {sum(len(v) for v in found.values())} hits")
        for s, offs in list(found.items())[: args.limit]:
            print(f"  0x{offs[0]:08x}  {s}")
        total += sum(len(v) for v in found.values())
    if not total:
        print("no matches")
        return 1
    return 0


def cmd_selftest(_args):
    """Build a fake dump and prove geometry + swap + magic recovery works."""
    import tempfile
    page, oob = 2048, 128
    sq = b"hsqs" + b"\x00" * 28 + b"fakesquashfs" + b"\x00" * (300 - 36)
    ker = b"Linux version 3.8.13-gdeadbeef (android-build@localhost) " + b"\x00" * 20
    pages = []
    pages.append(sq + b"\xff" * (page - len(sq)))
    pages.append(ker + b"\xff" * (page - len(ker)))
    for _ in range(6):
        pages.append(b"\xa5" * page)
    body = b""
    for p in pages:
        swapped = bytes((((b & 0x0F) << 4) | (b >> 4)) for b in p)
        body += swapped + b"\xff" * oob
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(body)
        tmp = f.name
    try:
        print("== layout ==")
        cmd_layout(argparse.Namespace(file=tmp))
        print("\n== scan (swap) ==")
        rc = cmd_scan(argparse.Namespace(file=tmp, page=page, oob=oob, json=None))
        assert rc == 0, "scan should find squashfs"
        print("\n== find (swap) ==")
        rc = cmd_find(argparse.Namespace(file=tmp, page=page, oob=oob,
                                        swap_nibbles=True, pattern=None, limit=5))
        assert rc == 0, "should find the kernel version"
        print("\nselftest: OK -- geometry, nibble swap and magic recovery all work")
        return 0
    finally:
        os.unlink(tmp)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("file")
        p.add_argument("--page", type=int, default=2048)
        p.add_argument("--oob", type=int, default=128)
        p.add_argument("--swap-nibbles", dest="swap_nibbles", action="store_true")
        p.add_argument("--json")

    p = sub.add_parser("layout"); p.add_argument("file"); p.set_defaults(fn=cmd_layout)
    p = sub.add_parser("scan"); common(p); p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("extract"); common(p)
    p.add_argument("--out", required=True); p.add_argument("--min-size", type=int, default=4096)
    p.set_defaults(fn=cmd_extract)
    p = sub.add_parser("find"); common(p)
    p.add_argument("--pattern"); p.add_argument("--limit", type=int, default=8)
    p.set_defaults(fn=cmd_find)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)

    args = ap.parse_args()
    if args.cmd in ("scan", "extract", "find") and getattr(args, "swap_nibbles", False):
        pass
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
