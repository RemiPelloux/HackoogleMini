#!/usr/bin/env python3
"""Measure streaming TTFB, total time and output tok/s per GhostCLI model.

Non-invasive: one short prompt per model per round, max_tokens capped.
Writes JSON to stdout. Key is read from ~/.config/ghostcli/env.
"""
import json, os, ssl, sys, time, http.client

ENV = os.path.expanduser("~/.config/ghostcli/env")
KEY = None
for line in open(ENV):
    line = line.strip()
    if line.startswith("export GHOSTCLI_API_KEY="):
        KEY = line.split("=", 1)[1].strip().strip('"')
assert KEY, "key not found in " + ENV

HOST = "ghostcli.cloud"
PROMPT = "Count from 1 to 60, comma separated, no other text."
ANTHROPIC = {"claude-opus-5-5", "claude-sonnet-5", "claude-fable-5.1"}
MODELS = ["claude-opus-5-5", "claude-sonnet-5", "claude-fable-5.1",
          "gpt-6-astra[1m]"]
BROKEN = ["z-ai/glm-5.3[1m]"]  # 502 on all four surfaces, see evidence/08


def anthropic(model, max_tokens):
    body = {"model": model, "max_tokens": max_tokens, "stream": True,
            "messages": [{"role": "user", "content": PROMPT}]}
    return ("/v1/messages", body,
            {"x-api-key": KEY, "anthropic-version": "2023-06-01",
             "content-type": "application/json", "accept": "text/event-stream"})


def openai(model, max_tokens):
    body = {"model": model, "max_tokens": max_tokens, "stream": True,
            "stream_options": {"include_usage": True},
            "messages": [{"role": "user", "content": PROMPT}]}
    return ("/v1/chat/completions", body,
            {"authorization": "Bearer " + KEY,
             "content-type": "application/json", "accept": "text/event-stream"})


def run(model, max_tokens=64):
    path, body, headers = (anthropic if model in ANTHROPIC else openai)(model, max_tokens)
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=180)
    t0 = time.perf_counter()
    conn.request("POST", path, json.dumps(body), headers)
    resp = conn.getresponse()
    t_headers = time.perf_counter() - t0
    if resp.status != 200:
        detail = resp.read(400).decode("utf8", "replace")
        conn.close()
        return {"model": model, "http": resp.status, "error": detail,
                "headers_s": round(t_headers, 3)}
    ttft = None
    text = []
    usage = {}
    events = 0
    deltas = 0
    for raw in resp:
        line = raw.decode("utf8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        events += 1
        if data == "[DONE]":
            continue
        try:
            ev = json.loads(data)
        except Exception:
            continue
        if "usage" in ev and ev["usage"]:
            usage = ev["usage"]
        delta = ""
        if ev.get("type") == "content_block_delta":
            delta = (ev.get("delta") or {}).get("text") or ""
        else:
            for ch in (ev.get("choices") or []):
                delta += ((ch.get("delta") or {}).get("content") or "")
        if delta:
            deltas += 1
            if ttft is None:
                ttft = time.perf_counter() - t0
        text.append(delta)
    total = time.perf_counter() - t0
    conn.close()
    out_tok = usage.get("output_tokens") or usage.get("completion_tokens") or 0
    # streaming is buffered by the proxy: the first text delta arrives with the whole answer,
    # so throughput is measured from response headers to the end of the body.
    gen_s = total - t_headers
    return {"model": model, "http": 200, "headers_s": round(t_headers, 3),
            "ttft_s": round(ttft, 3) if ttft else None,
            "total_s": round(total, 3),
            "output_tokens": out_tok,
            "tok_per_s": round(out_tok / gen_s, 1) if out_tok and gen_s > 0.05 else None,
            "stream_deltas": deltas,
            "sse_events": events, "chars": len("".join(text)),
            "sample": "".join(text)[:80]}


if __name__ == "__main__":
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    max_tokens = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    out = {"prompt": PROMPT, "max_tokens": max_tokens, "rounds": rounds, "runs": []}
    for r in range(rounds):
        for m in MODELS:
            res = run(m, max_tokens)
            res["round"] = r + 1
            out["runs"].append(res)
            print(json.dumps(res), file=sys.stderr, flush=True)
    json.dump(out, sys.stdout, indent=1)
