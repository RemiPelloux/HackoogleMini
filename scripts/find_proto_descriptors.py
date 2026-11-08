#!/usr/bin/env python3
"""Find serialized protobuf FileDescriptorProto blobs embedded in a binary (full-runtime
C++ protobuf keeps them for reflection). Prints name, package, and message/service counts.
Lite-runtime binaries have none: only the .proto *names* survive as strings.

usage: find_proto_descriptors.py <binary> [--dump DIR]   (writes <name>.pb blobs)
"""
import os, re, sys

def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1; r |= (c & 0x7F) << s; s += 7
        if c < 0x80: return r, i

def parse(b, i, end):
    """Parse FileDescriptorProto fields from i; stop at first field outside 1..14.
    Returns (fields, end_index)."""
    fields = []
    while i < end:
        try:
            key, j = varint(b, i)
        except IndexError:
            break
        f, w = key >> 3, key & 7
        if not (1 <= f <= 14) or w not in (0, 2):
            break
        if w == 0:
            v, j = varint(b, j); fields.append((f, v)); i = j; continue
        ln, j = varint(b, j)
        if j + ln > end: break
        fields.append((f, b[j:j + ln])); i = j + ln
    return fields, i

def main():
    path = sys.argv[1]; dump = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--dump" else None
    b = open(path, "rb").read()
    seen = 0
    for m in re.finditer(rb"\x0a([\x05-\x7f])([A-Za-z0-9_/.\-]{3,126}\.proto)\x12", b):
        if m.group(1)[0] != len(m.group(2)): continue
        fields, end = parse(b, m.start(), len(b))
        d = {}
        for f, v in fields: d.setdefault(f, []).append(v)
        if 2 not in d: continue
        msgs, svcs = len(d.get(4, [])), len(d.get(6, []))
        if msgs + svcs + len(d.get(5, [])) == 0 and 3 not in d: continue
        seen += 1
        name = d[1][0].decode()
        print(f"{m.start():#010x} {end - m.start():7d}B {name}  pkg={d[2][0].decode()}  msgs={msgs} enums={len(d.get(5, []))} svcs={svcs} deps={len(d.get(3, []))}")
        if dump:
            out = os.path.join(dump, name.replace("/", "__") + ".pb")
            os.makedirs(dump, exist_ok=True); open(out, "wb").write(b[m.start():end])
    print(f"# {seen} descriptors", file=sys.stderr)

main()
