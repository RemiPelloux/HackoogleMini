#!/usr/bin/env python3
"""Recover protobuf-lite message schemas (field numbers, kinds, cardinality, nested
message types) from the table-driven parser data (TcParseTable) of a 32-bit ARM ELF.

Field NAMES are not recoverable this way (the lite runtime does not ship them); only the
message type names, which sit in ClassData right before each table.

usage: recover_lite_protos.py <elf> [name-regex]     (default regex: ^assistant\\.)
Output: pseudo-.proto, one message per block. Layout assumptions (protobuf >= ~v27,
32-bit pointers) are heuristic; entries that fail sanity checks are marked '?'.
"""
import re, struct, sys

ELF = open(sys.argv[1], "rb").read()
PAT = re.compile(sys.argv[2] if len(sys.argv) > 2 else r"^assistant\.")

# --- VA <-> file offset from PT_LOAD segments
e_phoff, = struct.unpack_from("<I", ELF, 0x1c)
e_phentsize, e_phnum = struct.unpack_from("<HH", ELF, 0x2a)
LOADS = []
for k in range(e_phnum):
    p_type, p_off, p_va, _, p_filesz, _, _, _ = struct.unpack_from("<8I", ELF, e_phoff + k * e_phentsize)
    if p_type == 1: LOADS.append((p_va, p_off, p_filesz))
def va2off(va):
    for v, o, s in LOADS:
        if v <= va < v + s: return va - v + o
def off2va(off):
    for v, o, s in LOADS:
        if o <= off < o + s: return off - o + v

KIND = {0: "none", 1: "varint", 2: "packed_varint", 3: "fixed", 4: "packed_fixed",
        5: "string", 6: "message", 7: "map"}
CARD = {0: "", 1: "optional ", 2: "repeated ", 3: "oneof "}

def type_of(card):
    fk, fc, rep, tv = card & 7, (card >> 4) & 3, (card >> 6) & 7, (card >> 9) & 3
    if fk in (1, 2):
        t = {0: "bool", 2: "int32", 3: "int64"}.get(rep, f"varint{rep}")
        if tv == 1: t = "s" + t
        if tv in (2, 3): t = "enum"
    elif fk in (3, 4):
        t = {2: "fixed32/float", 3: "fixed64/double"}.get(rep, f"fixed{rep}")
    elif fk == 5:
        t = "string" if tv else "bytes|string"
    elif fk == 6:
        t = "group" if rep == 1 else "message"
    elif fk == 7:
        t = "map<?>"
    else:
        t = "?"
    return CARD[fc] + t, fk

def name_before(off):
    """ClassData ends with the NUL-terminated type name; table follows, 4-aligned."""
    j = off - 1
    while j > 0 and ELF[j] == 0 and off - j < 4: j -= 1
    end = j + 1
    while j > 0 and 32 < ELF[j - 1] < 127: j -= 1
    s = ELF[j:end].decode("ascii", "replace")
    return s if re.match(r"^[A-Za-z_][\w.]*\.[\w]+$", s) else None

def decode(table_off):
    try:
        (hb, ext, maxf, fmask, _pad, lut, skip, fe_off, nfe, naux, aux_off) = \
            struct.unpack_from("<HHIBBHIIHHI", ELF, table_off)
    except struct.error:
        return None
    if not (0 < maxf < 1 << 29) or not (0 < nfe <= 2000) or fe_off > 0x40000 or naux > 4000: return None
    if not (lut < fe_off and fe_off % 4 == 0 and (naux == 0 or aux_off >= fe_off + 12 * nfe)): return None
    if sum(1 for i in range(min(32, maxf)) if not (skip >> i) & 1) > nfe: return None
    # field numbers: <=32 from skipmap32, beyond from the lookup table
    nums = [i + 1 for i in range(32) if not (skip >> i) & 1 and i + 1 <= maxf]
    # lookup table (byte offset): {u16 lo, u16 hi -> u32 first fnum, u16 n} + n*{u16 skip, u16 entry}
    p = table_off + lut
    while len(nums) < nfe:
        try:
            lo, hi, nentries = struct.unpack_from("<HHH", ELF, p)
        except struct.error:
            break
        first_fnum = lo | hi << 16
        if first_fnum == 0xFFFFFFFF or nentries == 0 or nentries > 4096: break
        p += 6
        for b in range(nentries):
            skip16, _ = struct.unpack_from("<HH", ELF, p); p += 4
            for bit in range(16):
                if not (skip16 >> bit) & 1: nums.append(first_fnum + b * 16 + bit)
    fields = []
    for k in range(nfe):
        _off, _hasidx, aux_idx, card = struct.unpack_from("<IiHH", ELF, table_off + fe_off + 12 * k)
        t, fk = type_of(card)
        sub = None
        if fk in (6, 7) and aux_idx < naux:
            # aux holds the sub-message default instance (or its table); resolved later
            sub, = struct.unpack_from("<I", ELF, table_off + aux_off + 4 * aux_idx)
        fields.append((nums[k] if k < len(nums) else "?", t, sub, card))
    return maxf, fields

msgs = []
for m in re.finditer(rb"([A-Za-z_][\w]*(?:\.[\w]+)+)\x00{1,4}", ELF):
    name = m.group(1).decode()
    base = (m.start(1) + len(m.group(1)) + 1 + 3) & ~3
    for toff in (base, base + 4):          # ClassData names may carry extra NUL padding
        r = decode(toff)
        if r:
            msgs.append((name, m.start(1), toff, r)); break

# ClassData (just before the name) contains the prototype (default instance) pointer and
# the table pointer; map every 4-aligned word in the 48 bytes before the name -> name.
ptr2name = {}
for name, noff, toff, _ in msgs:
    ptr2name[off2va(toff)] = name
    a = noff & ~3
    for w in range(max(0, a - 48), a, 4):
        v, = struct.unpack_from("<I", ELF, w)
        ptr2name.setdefault(v, name)
tvas = {off2va(t) for _, _, t, _ in msgs}
ambiguous = 0
out = 0
for name, noff, toff, (maxf, fields) in msgs:
    if not PAT.search(name): continue
    out += 1
    print(f"message {name} {{  // table @va {off2va(toff):#x}, max_field {maxf}")
    for num, t, sub, card in fields:
        sn = ptr2name.get(sub) if sub else None
        if sn is None and sub: sn = f"msg_{sub:#x}"
        tn = t.replace("message", sn or "message").replace("map<?>", f"map<{sn}>" if sn else "map<?>")
        print(f"  {tn} f{num} = {num};  // card {card:#06x}")
    print("}")
print(f"// {out} messages ({len(msgs)} tables total)", file=sys.stderr)
