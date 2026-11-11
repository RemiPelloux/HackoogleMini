#!/usr/bin/env python3
"""Probe the documented Gemini surface (/v1beta) — the only API dialect never tested.

Documented claims under test (see /docs):
  * supportedGenerationMethods: generateContent, streamGenerateContent, countTokens
  * auth also accepts ?key= and x-goog-api-key, "matching Google SDK conventions"
  * tool calling maps to functionCall / functionResponse
  * streaming "arrives token by token"

Functional checks against a real, authorized key. Nothing destructive, five requests total.
"""
import json, os, sys, time, urllib.request, urllib.error, pathlib

BASE = "https://ghostcli.cloud"
KEY = os.environ["GHOSTCLI_API_KEY"]
OUT = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "13-gemini-surface.json"


def call(method, path, body=None, headers=None, timeout=120):
    req = urllib.request.Request(BASE + path, method=method)
    # Cloudflare bans the bare "Python-urllib/3.x" signature with error code 1010 (F40).
    req.add_header("user-agent", os.environ.get("GC_UA", "python-requests/2.32.3"))
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("content-type", "application/json")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, data, timeout=timeout) as r:
            raw = r.read()
            return {"status": r.status, "ms": round((time.time() - t0) * 1000),
                    "headers": dict(r.headers), "body": raw.decode("utf8", "replace")}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf8", "replace")
        return {"status": e.code, "ms": round((time.time() - t0) * 1000),
                "headers": dict(e.headers), "body": raw}
    except Exception as e:
        return {"status": None, "ms": round((time.time() - t0) * 1000), "error": repr(e)}


results = {}

# 1. countTokens — does the documented method exist, and does it count the system prompt?
results["countTokens_system+user"] = call(
    "POST", "/v1beta/models/claude-sonnet-5:countTokens",
    {"systemInstruction": {"parts": [{"text": "X" * 4000}]},
     "contents": [{"role": "user", "parts": [{"text": "Say OK."}]}]},
    {"x-goog-api-key": KEY})

# 2. same body without the system instruction — delta shows whether it is counted
results["countTokens_user_only"] = call(
    "POST", "/v1beta/models/claude-sonnet-5:countTokens",
    {"contents": [{"role": "user", "parts": [{"text": "Say OK."}]}]},
    {"x-goog-api-key": KEY})

# 3. streaming — buffered or token-by-token? (F10 cross-check on this dialect)
results["streamGenerateContent"] = call(
    "POST", "/v1beta/models/claude-sonnet-5:streamGenerateContent?alt=sse",
    {"contents": [{"role": "user", "parts": [{"text": "Count from 1 to 30 in words, one per line."}]}]},
    {"x-goog-api-key": KEY})

# 4. documented alternative auth: ?key=
results["generateContent_key_param"] = call(
    "POST", f"/v1beta/models/claude-sonnet-5:generateContent?key={KEY}",
    {"contents": [{"role": "user", "parts": [{"text": "Reply with the single word: pong"}]}]})

# 5. tool calling on this dialect: functionCall / functionResponse
results["generateContent_tools"] = call(
    "POST", "/v1beta/models/claude-sonnet-5:generateContent",
    {"contents": [{"role": "user", "parts": [{"text": "What is the weather in Paris? Use the tool."}]}],
     "tools": [{"functionDeclarations": [{
         "name": "get_weather", "description": "Current weather for a city",
         "parameters": {"type": "object", "properties": {"city": {"type": "string"}},
                        "required": ["city"]}}]}]},
    {"x-goog-api-key": KEY})

for name, r in results.items():
    body = r.get("body", "")
    preview = body if len(body) < 400 else body[:400] + "…"
    print(f"\n=== {name}  status={r['status']} {r['ms']}ms  bytes={len(body)}")
    print("   ", " ".join(preview.split())[:380])

sse = results["streamGenerateContent"].get("body", "")
results["_summary"] = {
    "stream_sse_frames": sse.count("data:"),
    "stream_sse_bytes": len(sse),
    "countTokens_delta_with_4000char_system": None,
}
try:
    a = json.loads(results["countTokens_system+user"]["body"])["totalTokens"]
    b = json.loads(results["countTokens_user_only"]["body"])["totalTokens"]
    results["_summary"]["countTokens_delta_with_4000char_system"] = a - b
    print(f"\ncountTokens: with system={a}  without={b}  delta={a-b} (≈1000 tokens if counted)")
except Exception:
    pass

OUT.write_text(json.dumps(results, indent=1, ensure_ascii=False))
print(f"\nsaved -> {OUT}")
