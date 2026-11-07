#!/usr/bin/env python3
"""Human-readable dump of a (sanitized) mitmproxy flow file: index, headers, and a
schema-less protobuf decode of every gRPC / protobuf body.

Runs with mitmproxy's Python, e.g.:

  docker run --rm -v "$PWD:/w" -w /w --entrypoint python3 \
    mirror.gcr.io/mitmproxy/mitmproxy:12.3.1 -I scripts/mitm-decode.py \
    evidence/<name>.flows > evidence/<name>-decoded.txt

Field numbers are wire tags only -- no .proto files are used, so names are not known.
HTML/JS bodies are summarized by size, not printed.
"""
import re
import struct
import sys

from mitmproxy import http, io


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return r, i


def printable(d):
    try:
        t = d.decode()
    except UnicodeDecodeError:
        return None
    return t if t and all(c.isprintable() for c in t) else None


def decode(b, ind=0, depth=0):
    """Return lines, or None if b is not a well-formed protobuf message."""
    out, i, pad = [], 0, " " * ind
    try:
        while i < len(b):
            key, i = varint(b, i)
            f, w = key >> 3, key & 7
            if f == 0:
                return None
            if w == 0:
                v, i = varint(b, i)
                out.append(f"{pad}{f}: {v}")
            elif w == 1:
                raw = b[i:i + 8]
                i += 8
                if len(raw) < 8:
                    return None
                out.append(f"{pad}{f}: fixed64 {raw.hex()} (double {struct.unpack('<d', raw)[0]:g})")
            elif w == 5:
                raw = b[i:i + 4]
                i += 4
                if len(raw) < 4:
                    return None
                out.append(f"{pad}{f}: fixed32 {raw.hex()} (float {struct.unpack('<f', raw)[0]:g})")
            elif w == 2:
                n, i = varint(b, i)
                d = b[i:i + n]
                i += n
                if i > len(b):
                    return None
                sub = decode(d, ind + 2, depth + 1) if n and depth < 16 else None
                t = printable(d)
                if t is not None and (sub is None or re.fullmatch(r"[\w ./:+$@,=()-]+", t)):
                    out.append(f"{pad}{f}: {t[:300]!r}")
                elif sub is not None:
                    out += [f"{pad}{f} {{"] + sub + [f"{pad}}}"]
                else:
                    out.append(f"{pad}{f}: bytes[{n}] {d[:64].hex()}")
            else:
                return None
    except IndexError:
        return None
    return out


def grpc_frames(b):
    i = 0
    while i + 5 <= len(b):
        n = int.from_bytes(b[i + 1:i + 5], "big")
        yield b[i + 5:i + 5 + n]
        i += 5 + n


def body_lines(m):
    if not m.raw_content:
        return ["    <no body>"]
    ct = (m.headers.get("content-type") or "").lower()
    body = m.get_content(strict=False)
    if "html" in ct or "javascript" in ct:
        return [f"    <{ct} body, {len(body)} bytes, not printed>"]
    t = printable(body.replace(b"\n", b" ").replace(b"\r", b" ").replace(b"\t", b" "))
    if t is not None:
        return ["    " + body.decode()[:4000]]
    msgs = list(grpc_frames(body)) if "grpc" in ct else [body]
    out = []
    for j, msg in enumerate(msgs):
        out.append(f"    -- message {j} ({len(msg)} bytes)")
        out += ["    " + line for line in (decode(msg) or [f"<not protobuf> {msg[:64].hex()}"])]
    return out


def main():
    with open(sys.argv[1], "rb") as f:
        flows = [fl for fl in io.FlowReader(f).stream() if isinstance(fl, http.HTTPFlow)]
    t0 = flows[0].request.timestamp_start
    print("# index  (t = seconds after first flow)")
    for n, fl in enumerate(flows):
        r, s = fl.request, fl.response
        st = s.status_code if s else f"ERROR {str(fl.error)[-40:]}"
        gs = s.trailers.get("grpc-status") if s and s.trailers else None
        print(f"{n:3} t+{r.timestamp_start - t0:6.1f}s {r.method:4} {r.pretty_host}{r.path[:90]}"
              f"  -> {st}{f' grpc-status={gs}' if gs else ''}")
    for n, fl in enumerate(flows):
        r, s = fl.request, fl.response
        print(f"\n{'=' * 100}\n[{n}] {r.method} {r.pretty_url}  ({r.http_version})")
        for k, v in r.headers.items():
            print(f"  > {k}: {v[:200]}")
        print("\n".join(body_lines(r)))
        if s:
            print(f"  < {s.status_code} {s.reason}")
            for k, v in s.headers.items():
                print(f"  < {k}: {v[:200]}")
            print("\n".join(body_lines(s)))
            for k, v in (s.trailers or {}).items():
                print(f"  < (trailer) {k}: {v[:200]}")
        if fl.error:
            print(f"  !! {fl.error}")


if __name__ == "__main__":
    main()
