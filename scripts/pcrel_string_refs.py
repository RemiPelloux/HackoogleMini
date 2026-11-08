#!/usr/bin/env python3
"""Resolve Thumb-2 PC-relative string references (`ldr rX, [pc, #lit]` ... `add rX, pc`)
in an ARM ELF, which Ghidra often leaves unresolved, and print the strings referenced
near the references to a set of anchor strings.

usage: pcrel_string_refs.py <elf> <anchor-regex> [window-bytes]
       pcrel_string_refs.py <elf> range:<lo-hex>-<hi-hex>      (all refs in a code range)

Output: one block per cluster of anchor references:  <code-va>  <string>
VAs are file VAs (Ghidra adds its image base, 0x10000 for these PIEs/.so).
Heuristic: a linear sweep, a register's literal is remembered for 12 halfwords.
"""
import re
import struct
import sys

from elftools.elf.elffile import ELFFile


def main():
    path, rx = sys.argv[1], re.compile(sys.argv[2].encode())
    window = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x300
    data = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"]) for s in elf.iter_segments()
            if s["p_type"] == "PT_LOAD"]
    text = elf.get_section_by_name(".text")
    t0, tn = text["sh_addr"], text["sh_addr"] + text["sh_size"]

    def off(va):
        for v, o, n in segs:
            if v <= va < v + n:
                return va - v + o
        return None

    def cstr(va):
        o = off(va)
        if o is None or (o > 0 and data[o - 1] != 0):   # must start a string
            return None
        e = data.find(b"\0", o, o + 400)
        s = data[o:e] if e > o else b""
        return s if len(s) >= 3 and all(32 <= c < 127 for c in s) else None

    refs = []   # (code_va, string)
    lit = {}    # reg -> (value, halfword index)
    o0 = off(t0)
    n = (tn - t0) // 2
    hw = struct.unpack_from("<%dH" % n, data, o0)
    i = 0
    while i < n:
        h = hw[i]
        a = t0 + 2 * i
        if (h & 0xF800) == 0x4800:                         # ldr rt, [pc, #imm8*4]
            la = ((a + 4) & ~3) + (h & 0xFF) * 4
            lo = off(la)
            if lo is not None:
                lit[(h >> 8) & 7] = (struct.unpack_from("<I", data, lo)[0], i)
        elif h == 0xF8DF and i + 1 < n:                    # ldr.w rt, [pc, #imm12]
            h2 = hw[i + 1]
            la = ((a + 4) & ~3) + (h2 & 0xFFF)
            lo = off(la)
            if lo is not None:
                lit[h2 >> 12] = (struct.unpack_from("<I", data, lo)[0], i)
            i += 2
            continue
        elif (h & 0xFF78) == 0x4478:                       # add rd, pc
            rd = (h & 7) | ((h >> 4) & 8)
            if rd in lit and i - lit[rd][1] <= 12:
                s = cstr((lit[rd][0] + a + 4) & 0xFFFFFFFF)
                if s:
                    refs.append((a, s))
        elif (h & 0xE000) == 0xE000 and (h & 0x1800):      # skip 2nd half of 32-bit insns
            i += 2
            continue
        i += 1

    if sys.argv[2].startswith("range:"):                 # "range:0x78b900-0x78e000"
        lo, hi = (int(x, 16) for x in sys.argv[2][6:].split("-"))
        for a, s in refs:
            if lo <= a <= hi:
                print(f"  {a:#09x}  {s.decode()}")
        return
    anchors = [a for a, s in refs if rx.search(s)]
    clusters = []
    for a in anchors:
        if clusters and a - clusters[-1][1] <= window:
            clusters[-1][1] = a
        else:
            clusters.append([a, a])
    print(f"# {len(refs)} pc-relative string refs, {len(anchors)} anchor refs, {len(clusters)} clusters")
    for lo, hi in clusters:
        print(f"## cluster {lo:#x}-{hi:#x}")
        for a, s in refs:
            if lo - window <= a <= hi + window:
                mark = "*" if rx.search(s) else " "
                print(f"{mark} {a:#09x}  {s.decode()}")


if __name__ == "__main__":
    main()
