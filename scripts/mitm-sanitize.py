#!/usr/bin/env python3
"""Redact a mitmproxy flow dump of a Home Mini so it can be committed to evidence/.

Runs with mitmproxy's Python (not installed in the venv), e.g. via the image the proxy uses:

  docker run --rm -v "$PWD:/w" -v ~/Downloads/flows:/in/flows:ro -w /w \
    --entrypoint python3 mirror.gcr.io/mitmproxy/mitmproxy:12.3.1 -I \
    scripts/mitm-sanitize.py /in/flows evidence/<name>.flows --drop 0,1,2

What it does
  * drops flows that are not from the device (--drop, and anything whose client sent a
    browser Cookie header) -- those carry the operator's own account session;
  * blanks credential/identity headers (Authorization, API keys, Cast/Nest device certs,
    JWTs, request signatures, cookies, serial and device-id headers) and the binary
    server-side gRPC trailers (load/stats metrics);
  * DISCOVERS device/account identifiers from the capture itself (no secrets are written
    in this file) and replaces every occurrence -- headers, paths, bodies, trailers -- with
    a placeholder of the SAME LENGTH, so protobuf/gRPC length prefixes stay valid and the
    sanitized flows still decode;
  * replaces every UUID (request ids such as X-Speech-RequestId, which Google logs) with a
    fresh random UUID, consistently, and masks opaque server ids and per-user entity lists;
  * shifts ALL absolute time by one random offset (30-365 days, either direction, random
    seconds) that is never printed or stored: flow/connection timestamps, Date/Expires
    headers, Omaha day counters, epoch values in text and inside protobuf varints/fixed64.
    Relative timing between flows is preserved exactly;
  * rewrites client/server addresses to documentation ranges and drops stored TLS
    certificates (their validity dates would bound the capture time);
  * re-scans the result and exits non-zero if any discovered value, token pattern, or
    time value from the original capture window is left.

Same original value -> same placeholder (OAUTH1, OAUTH2, GAIA1 ...), so correlations survive.
"""
import argparse
import email.utils
import re
import secrets
import struct
import sys
import uuid

from mitmproxy import http, io

BLANK_HEADERS = re.compile(
    r"^(authorization|cookie|set-cookie|x-goog-api-key|x-goog-nest-.*|cast-cert.*|"
    r"cast-jwt|cast-signature.*|cast-app-device-id|cast-serial-num|.*-bin)$", re.I)
DATE_HEADERS = ("date", "expires", "last-modified", "if-modified-since")

# token-shaped values: (tag, regex). Applied to every text-ish and protobuf body.
TOKEN_PATTERNS = [
    ("OAUTH", rb"ya29\.[A-Za-z0-9._-]{20,}"),
    ("APIKEY", rb"AIza[0-9A-Za-z_-]{35}"),
    ("JWT", rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),
    ("FCM", rb"[A-Za-z0-9_-]{11}:APA91b[A-Za-z0-9_-]{20,}"),
    ("UTTID", rb"uttid-[0-9a-f]{16}-[0-9]{6,}"),
    # no trailing \b: in protobuf the next tag byte is often an ASCII digit
    ("MAC", rb"(?i)(?<![0-9a-f:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}"),
    ("IP", rb"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b"),
    ("GAIA", rb"\b1\d{20}\b"),
]
# protobuf-only patterns (not applied to HTML/JS bodies)
ENTITY = re.compile(rb"/[mg]/[0-9a-z_]{4,}")  # Knowledge Graph ids in per-user settings
OPAQUE = re.compile(rb"[A-Za-z0-9_/+-]{20,}={0,2}")  # tokens and server-generated ids
SNAKE = re.compile(rb"[A-Za-z]+(?:_[A-Za-z0-9]+){2,}")  # identifiers like fopo_release_2026_w10_RC05
UUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PUBLIC_UUIDS = {b"6117439b-1508-4065-9e69-2a006d8f7730"}  # Omaha appid of the Cast OS (constant)
EPOCH_TEXT = re.compile(rb"(?<!\d)1\d{9}(?:\d{3})?(?!\d)")
OMAHA_EPOCH = 1167609600  # 2007-01-01 UTC, base of Omaha elapsed_days


def is_opaque_token(b: bytes) -> bool:
    """Random base64 has upper and lower case in similar shares; names and URLs
    (ChromecastManhattan__aog_..., resources_tts_joplin_...) are mostly lower case."""
    up, lo = len(re.findall(rb"[A-Z]", b)), len(re.findall(rb"[a-z]", b))
    letters = up + lo
    return (re.search(rb"[0-9]", b) and letters >= 10
            and up >= 0.3 * letters and lo >= 0.3 * letters
            and not b.startswith(b"type.googleapis.com") and not SNAKE.fullmatch(b)
            and not ENTITY.fullmatch(b))


def venc(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def vdec(b: bytes, i: int):
    r = s = 0
    for j in range(i, min(i + 10, len(b))):
        r |= (b[j] & 0x7F) << s
        s += 7
        if b[j] < 0x80:
            return r, j + 1
    return None, None


class TimeShift:
    """One secret offset; recognizes epoch values (s / ms / us) inside the capture window."""

    SCALES = (1, 1000, 1_000_000)

    def __init__(self, t_min: float, t_max: float):
        days = 30 + secrets.randbelow(336)
        self.offset = (days * 86400 + secrets.randbelow(86400)) * (1 if secrets.randbelow(2) else -1)
        self.lo, self.hi = t_min - 7 * 86400, t_max + 86400
        self.hits = 0

    def scale_of(self, v: int):
        for sc in self.SCALES:
            if self.lo * sc <= v <= self.hi * sc:
                return sc
        return None

    def shift_int(self, v: int, sc: int) -> int:
        return v + self.offset * sc

    def text(self, data: bytes) -> bytes:
        def repl(m):
            v = int(m.group())
            sc = self.scale_of(v)
            if not sc:
                return m.group()
            self.hits += 1
            return str(self.shift_int(v, sc)).encode()
        return EPOCH_TEXT.sub(repl, data)

    def protobuf(self, data: bytes) -> bytes:
        """Rewrite in place every varint/fixed64 that decodes to a time in the window and
        follows a byte with the matching wire type. Encoded length must not change."""
        b = bytearray(data)
        i = 1
        while i < len(b):
            wt = b[i - 1] & 7
            if wt == 0:
                v, end = vdec(b, i)
                sc = self.scale_of(v) if v is not None else None
                if sc:
                    new = venc(self.shift_int(v, sc))
                    if len(new) != end - i:
                        raise SystemExit("!! time shift changed a varint length -- rerun")
                    b[i:end] = new
                    self.hits += 1
                    i = end
                    continue
            elif wt == 1 and i + 8 <= len(b):
                v = struct.unpack_from("<Q", b, i)[0]
                sc = self.scale_of(v)
                if sc in (1000, 1_000_000):
                    struct.pack_into("<Q", b, i, self.shift_int(v, sc))
                    self.hits += 1
                    i += 8
                    continue
            i += 1
        return bytes(b)

    def http_date(self, v: str) -> str:
        try:
            d = email.utils.parsedate_to_datetime(v)
        except (TypeError, ValueError):
            return v
        if d.year < 2000:  # sentinels such as "Mon, 01 Jan 1990"
            return v
        self.hits += 1
        return email.utils.formatdate(d.timestamp() + self.offset, usegmt=True)

    def omaha(self, days: int, secs: int):
        t = OMAHA_EPOCH + days * 86400 + secs + self.offset
        return (t - OMAHA_EPOCH) // 86400, (t - OMAHA_EPOCH) % 86400

    def state(self, obj):
        """Shift every timestamp_* float in a mitmproxy state dict, recursively."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.startswith("timestamp") and isinstance(v, (int, float)):
                    obj[k] = v + self.offset
                else:
                    self.state(v)
        elif isinstance(obj, list):
            for v in obj:
                self.state(v)


class Redactor:
    def __init__(self):
        self.map: dict[bytes, bytes] = {}
        self.count: dict[str, int] = {}

    def placeholder(self, tag: str, orig: bytes) -> bytes:
        if orig in self.map:
            return self.map[orig]
        self.count[tag] = self.count.get(tag, 0) + 1
        if tag == "UUID":
            ph = str(uuid.uuid4()).encode()
            ph = ph.upper() if orig.isupper() else ph
        else:
            label = f"{tag}{self.count[tag]}".encode()
            n = len(orig)
            ph = (label + b"_" * n)[:n] if n >= len(label) else b"X" * n
        self.map[orig] = ph
        return ph

    def learn(self, tag: str, value):
        if value:
            v = value.encode() if isinstance(value, str) else value
            if len(v) >= 4:
                self.placeholder(tag, v)

    def apply(self, data: bytes, protobuf: bool) -> bytes:
        for tag, pat in TOKEN_PATTERNS:
            for m in set(re.findall(pat, data)):
                self.placeholder(tag, m)
        for m in set(UUID.findall(data)):
            if m.lower() not in PUBLIC_UUIDS:
                self.placeholder("UUID", m)
        if protobuf:
            for m in set(ENTITY.findall(data)):
                self.placeholder("ENTITY", m)
            for m in set(OPAQUE.findall(data)):
                if is_opaque_token(m):
                    self.placeholder("TOKEN", m)
        # longest first so a value containing another is replaced whole
        for orig in sorted(self.map, key=len, reverse=True):
            if orig in data:
                data = data.replace(orig, self.map[orig])
        return data


def discover(r: Redactor, flows):
    """Collect identifiers that are not token-shaped from places we know carry them."""
    for fl in flows:
        for m in (fl.request, fl.response):
            if not m:
                continue
            h = m.headers
            r.learn("DEVID", h.get("cast-app-device-id") or h.get("x-goog-nest-app-device-id"))
            r.learn("SERIAL", h.get("cast-serial-num"))
            auth = h.get("authorization", "")
            if auth.startswith("AidLogin "):
                aid, _, sec = auth[9:].partition(":")
                r.learn("ANDROIDID", aid)
                r.learn("GCMSECRET", sec)
            body = m.get_content(strict=False) or b""
            for pat, tag in ((rb'"serial_num":"([^"]+)"', "SERIAL"),
                             (rb'"mac_addr":"([^"]+)"', "MAC")):
                for v in re.findall(pat, body):
                    r.learn(tag, v)
            # Lycra TechnicalInfoTrait: field 2 = Wi-Fi SSID, next to the IP and MAC strings
            if b"TechnicalInfoTrait" in body:
                mm = re.search(rb"\x12([\x01-\x20])", body[body.index(b"TechnicalInfoTrait"):])
                if mm:
                    start = body.index(b"TechnicalInfoTrait") + mm.end()
                    r.learn("SSID", body[start:start + mm.group(1)[0]])
    for v in list(r.map):  # case variants of hex ids
        for alt in (v.lower(), v.upper()):
            if alt != v and re.fullmatch(rb"[0-9A-Fa-f]{16,}", v):
                r.map.setdefault(alt, r.map[v])


def scrub_headers(r: Redactor, t: TimeShift, headers):
    for k in list(headers.keys()):
        if BLANK_HEADERS.match(k):
            headers[k] = "REDACTED"
        elif k.lower() in DATE_HEADERS:
            headers[k] = t.http_date(headers[k])
    if "x-daynum" in headers and "x-daystart" in headers:
        d, s = t.omaha(int(headers["x-daynum"]), int(headers["x-daystart"]))
        headers["x-daynum"], headers["x-daystart"] = str(d), str(s)
    for k, v in list(headers.items()):
        headers[k] = t.text(r.apply(v.encode(), False)).decode()


def scrub_message(r: Redactor, t: TimeShift, m, kind: str):
    scrub_headers(r, t, m.headers)
    if m.trailers:
        scrub_headers(r, t, m.trailers)
    if not m.raw_content:
        return
    body = m.get_content(strict=False)  # decodes gzip etc.; drops content-encoding below
    m.headers.pop("content-encoding", None)
    if kind == "page":  # public HTML/JS: identifiers only, no heuristics
        m.content = r.apply(body, False)
        return
    def omaha(mm):
        d, s = t.omaha(int(mm.group(2)), int(mm.group(1)))
        return b'"elapsed_seconds":%d,"elapsed_days":%d' % (s, d)
    body = re.sub(rb'"elapsed_seconds":(\d+),"elapsed_days":(\d+)', omaha, body)
    body = r.apply(body, kind == "protobuf")
    body = t.protobuf(body) if kind == "protobuf" else body
    m.content = t.text(body)


def body_kind(m) -> str:
    """By content, not label: e.g. play.googleapis.com/log says form-urlencoded but is
    binary protobuf."""
    ct = (m.headers.get("content-type") or "").lower()
    if "html" in ct or "javascript" in ct:
        return "page"
    body = m.get_content(strict=False) or b""
    try:
        text = body.decode()
    except UnicodeDecodeError:
        return "protobuf"
    return "text" if all(c.isprintable() or c in "\r\n\t" for c in text) else "protobuf"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--drop", default="", help="comma-separated flow indexes to drop")
    a = ap.parse_args()
    drop = {int(x) for x in a.drop.split(",") if x}

    with open(a.src, "rb") as f:
        flows = [fl for fl in io.FlowReader(f).stream() if isinstance(fl, http.HTTPFlow)]
    kept = [fl for i, fl in enumerate(flows)
            if i not in drop and "cookie" not in fl.request.headers]
    print(f"flows: {len(flows)} read, {len(kept)} kept", file=sys.stderr)

    starts = [fl.request.timestamp_start for fl in kept]
    t = TimeShift(min(starts), max(starts))
    r = Redactor()
    discover(r, kept)
    out = []
    for n, fl in enumerate(kept):
        fl.request.path = r.apply(fl.request.path.encode(), False).decode()
        for m in (fl.request, fl.response):
            if m:
                scrub_message(r, t, m, body_kind(m))
        st = fl.get_state()
        t.state(st)
        c, s = st["client_conn"], st["server_conn"]
        c["peername"] = (f"2001:db8::{n + 1:x}", 40000 + n) if c.get("peername") else None
        c["sockname"] = ("2001:db8::12", c["sockname"][1]) if c.get("sockname") else None
        c["certificate_list"], c["mitmcert"] = [], None
        s["peername"] = ("192.0.2.2", s["peername"][1]) if s.get("peername") else None
        s["sockname"] = ("192.0.2.1", s["sockname"][1]) if s.get("sockname") else None
        s["certificate_list"] = []
        st["comment"] = ""
        out.append(http.HTTPFlow.from_state(st))

    with open(a.dst, "wb") as f:
        w = io.FlowWriter(f)
        for fl in out:
            w.add(fl)

    # verification: nothing discovered, token-shaped, or from the original time window
    blob = open(a.dst, "rb").read()
    left = [o for o in r.map if o in blob]
    left += [m for _, p in TOKEN_PATTERNS for m in re.findall(p, blob)]
    left += [m for m in EPOCH_TEXT.findall(blob) if t.scale_of(int(m))]
    for fl in io.FlowReader(open(a.dst, "rb")).stream():
        for m in (fl.request, fl.response):
            if m and m.raw_content and body_kind(m) == "protobuf":
                before = t.hits
                t.protobuf(m.raw_content)
                if t.hits != before:
                    left.append(b"<protobuf time value in original window>")
    for tag in sorted(r.count):
        print(f"  {tag}: {r.count[tag]} distinct value(s) replaced", file=sys.stderr)
    print(f"  time values shifted: {t.hits} (+ all flow/connection timestamps)", file=sys.stderr)
    if left:
        print(f"!! {len(left)} value(s) survived redaction -- do not commit", file=sys.stderr)
        for v in sorted(set(left))[:20]:
            print("   ", v[:60], file=sys.stderr)
        sys.exit(1)
    print(f"ok: {a.dst}", file=sys.stderr)


if __name__ == "__main__":
    main()
