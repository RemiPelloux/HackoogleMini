#!/usr/bin/env python3
"""Read-only recon of the account surface the user owns. GET only, no mutations,
no cross-tenant probing. Session value is passed via $GC_SESSION so it is never
written to disk; key material in responses is redacted before saving."""
import json, os, re, ssl, time, http.client

SID = os.environ["GC_SESSION"]
ROUTES = ["/api/me", "/api/plan", "/api/subscription", "/api/usage", "/api/keys",
          "/api/keys/ips", "/api/affiliate", "/api/config", "/api/chats", "/api/uptime"]
SECRET = re.compile(r"(gcli_[A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]+")

def get(path):
    c = http.client.HTTPSConnection("ghostcli.cloud", 443,
                                    context=ssl.create_default_context(), timeout=60)
    t = time.perf_counter()
    c.request("GET", path, headers={
        "cookie": "gc_session=%s; lang=en" % SID,
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36",
        "accept": "application/json, text/html;q=0.9,*/*;q=0.8",
        "referer": "https://ghostcli.cloud/dashboard"})
    r = c.getresponse()
    body = r.read().decode("utf8", "replace")
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return {"path": path, "http": r.status, "ms": round((time.perf_counter() - t) * 1000),
            "len": len(body), "headers": hdrs, "body": body}

out = {"routes": []}
for p in ROUTES + ["/dashboard"]:
    res = get(p)
    b = res.pop("body")
    red = SECRET.sub(r"\1…REDACTED", b)
    res["body_sample"] = red[:1200]
    try:
        res["json"] = json.loads(b)
    except Exception:
        res["json"] = None
    out["routes"].append(res)
json.dump(out, open("evidence/09-authenticated-surface.json", "w"), indent=1)
for r in out["routes"]:
    keys = list(r["json"]) if isinstance(r["json"], dict) else type(r["json"]).__name__
    print(f"{r['path']:20} http={r['http']} {r['ms']:5}ms {r['len']:6}B  keys={keys}")
    if not isinstance(r["json"], dict):
        print("   body:", r["body_sample"][:150].replace("\n", " "))
