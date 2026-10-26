#!/usr/bin/env python3
"""Find the address of a kernel symbol in a raw ARM kernel binary.

Uses two methods:
  1. Search for the symbol name string and nearby ARM branch targets
  2. Pattern-match the function prologue via capstone disassembly

Usage:
  python scripts/find_kernel_sym.py target/kernel.bin call_usermodehelper_fns
  python scripts/find_kernel_sym.py target/kernel.bin call_usermodehelper_fns --load 0xC0008000
"""
import argparse
import re
import struct
import sys

LOAD_DEFAULT = 0xC0008000  # typical H0A kernel load address


def find_by_string(data: bytes, symbol: str, load_addr: int) -> list[int]:
    """Find addresses by searching for the symbol name string + nearby LDR targets."""
    candidates = []
    sym_enc = symbol.encode()
    offset = 0
    while True:
        pos = data.find(sym_enc, offset)
        if pos == -1:
            break
        # Look 512 bytes before/after for a 4-byte aligned address in the kernel range
        region = data[max(0, pos - 512):pos + 512]
        for i in range(0, len(region) - 3, 4):
            val = struct.unpack_from("<I", region, i)[0]
            if 0xC0000000 <= val <= 0xE0000000:
                candidates.append(val)
        offset = pos + 1
    return sorted(set(candidates))


def find_by_kallsyms(data: bytes, symbol: str, load_addr: int) -> list[int]:
    """Parse embedded /proc/kallsyms-style symbol table in the kernel image."""
    sym_enc = symbol.encode()
    results = []
    # kallsyms format: address (4B LE) + type (1B) + name (null-term)
    # Also try the compressed kallsyms format
    for i in range(0, len(data) - len(sym_enc) - 10, 4):
        if data[i + 4 : i + 4 + len(sym_enc)] == sym_enc:
            addr = struct.unpack_from("<I", data, i)[0]
            if 0xC0000000 <= addr <= 0xE0000000:
                results.append(addr)
    return sorted(set(results))


def find_by_disasm(data: bytes, symbol: str, load_addr: int) -> list[int]:
    """Use capstone to scan for likely function entry points near string refs."""
    try:
        import capstone
    except ImportError:
        print("[!] capstone not installed (pip install capstone), skipping disasm method",
              file=sys.stderr)
        return []

    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    cs.detail = True

    # Find string reference addresses
    sym_enc = symbol.encode()
    str_offsets = []
    off = 0
    while True:
        pos = data.find(sym_enc, off)
        if pos == -1:
            break
        str_offsets.append(load_addr + pos)
        off = pos + 1

    if not str_offsets:
        return []

    # Scan 32KB windows around each string for BL/BLX targeting kernel addresses
    candidates = []
    for str_addr in str_offsets:
        scan_start = max(0, str_addr - load_addr - 0x8000)
        scan_end = min(len(data), str_addr - load_addr + 0x8000)
        window = data[scan_start:scan_end]
        for ins in cs.disasm(window, load_addr + scan_start):
            if ins.mnemonic in ("bl", "blx"):
                for op in ins.operands:
                    if hasattr(op, "imm") and 0xC0000000 <= op.imm <= 0xE0000000:
                        candidates.append(op.imm)
    return sorted(set(candidates))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel", help="Path to raw kernel binary")
    ap.add_argument("symbol", help="Symbol name to find")
    ap.add_argument("--load", default=LOAD_DEFAULT, type=lambda x: int(x, 0),
                    help=f"Kernel load address (default: 0x{LOAD_DEFAULT:08X})")
    args = ap.parse_args()

    with open(args.kernel, "rb") as f:
        data = f.read()

    print(f"[*] Kernel: {args.kernel} ({len(data):,} bytes, load=0x{args.load:08X})")
    print(f"[*] Searching for: {args.symbol!r}")
    print()

    results = {}

    r = find_by_kallsyms(data, args.symbol, args.load)
    if r:
        results["kallsyms"] = r
        print(f"[+] kallsyms match:  {[hex(a) for a in r]}")

    r = find_by_string(data, args.symbol, args.load)
    if r:
        results["string+ref"] = r
        print(f"[+] string+ref:      {[hex(a) for a in r]}")

    r = find_by_disasm(data, args.symbol, args.load)
    if r:
        results["disasm BL target"] = r
        print(f"[+] disasm BL:       {[hex(a) for a in r]}")

    if not results:
        print(f"[-] Symbol {args.symbol!r} not found. Try loading the kernel in Ghidra.")
        sys.exit(1)

    # Intersect all non-empty result sets — highest-confidence candidates
    sets = [set(v) for v in results.values()]
    intersection = sets[0].intersection(*sets[1:]) if len(sets) > 1 else sets[0]
    if intersection:
        print(f"\n[★] High-confidence candidates: {sorted([hex(a) for a in intersection])}")
    else:
        all_candidates = sorted(set().union(*sets))
        print(f"\n[?] Candidates (no intersection): {[hex(a) for a in all_candidates]}")
    print()
    print("Use the address in craft_cache.py → KERNEL_CALL_USERMODEHELPER")


if __name__ == "__main__":
    main()
