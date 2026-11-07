"""mitmproxy addon: make a Cast device's Omaha update check claim an older build, so
Google answers with a real OTA offer (codebase URL + sha256) instead of `noupdate`.

Load it next to forward_by_host.py (see notes/mitm-capture.md):

    mitmweb ... -s forward_by_host.py -s omaha_spoof.py

Options (`--set name=value`):
    omaha_fake_version   build number to claim (default 468362 = target's 3.75 build)
    omaha_neutralize     true (default): after logging the real offer, hand the device a
                         `noupdate` so it does NOT download/flash anything.
                         false: pass the offer through (the device will update + reboot).
    omaha_log            file the raw offers are appended to (default /tmp/omaha-offers.jsonl)

Download the offered zip afterwards with `scripts/fetch-ota.sh`.
"""
import json
import time

from mitmproxy import ctx, http

XSSI = ")]}'\n"


def load(loader):
    loader.add_option("omaha_fake_version", str, "468362", "Build number to claim in Omaha checks")
    loader.add_option("omaha_neutralize", bool, True, "Return noupdate to the device after logging")
    loader.add_option("omaha_log", str, "/tmp/omaha-offers.jsonl", "Where to append Omaha responses")


def _is_omaha(flow: http.HTTPFlow) -> bool:
    return (flow.request.pretty_host == "tools.google.com"
            and flow.request.path.startswith("/service/update2/json"))


def request(flow: http.HTTPFlow) -> None:
    if not _is_omaha(flow):
        return
    try:
        body = json.loads(flow.request.get_text())
        g = body["gupdate"]
        orig = g["app"]["version"]
    except (ValueError, KeyError, TypeError):
        return
    flow.metadata["omaha_orig_version"] = orig
    # Rewrites update checks and event pings alike, so the server sees one version.
    fake = ctx.options.omaha_fake_version
    g["app"]["version"] = fake
    g.setdefault("os", {})["version"] = fake
    flow.request.set_text(json.dumps(body, separators=(",", ":")))
    ctx.log.info(f"omaha: claimed version {fake} (device has {orig})")


def response(flow: http.HTTPFlow) -> None:
    if "omaha_orig_version" not in flow.metadata or not flow.response:
        return
    raw = flow.response.get_text(strict=False)
    prefix = XSSI if raw.startswith(")]}'") else ""
    try:
        data = json.loads(raw[len(prefix):] if prefix else raw)
    except ValueError:
        return
    apps = data.get("gupdate", {}).get("app", [])
    offered = [a["updatecheck"] for a in apps
               if isinstance(a.get("updatecheck"), dict) and a["updatecheck"].get("codebase")]
    if not offered:
        return
    for uc in offered:
        ctx.log.warn(f"omaha OFFER: {uc.get('DisplayVersion')} size={uc.get('size')} "
                     f"sha256={uc.get('hash_sha256')} {uc.get('codebase')}")
    with open(ctx.options.omaha_log, "a") as f:
        f.write(json.dumps({"t": time.time(), "claimed": ctx.options.omaha_fake_version,
                            "offers": offered}) + "\n")
    if ctx.options.omaha_neutralize:
        for a in apps:
            if "updatecheck" in a:
                a["updatecheck"] = {"status": "noupdate"}
        flow.response.set_text(prefix + json.dumps(data, separators=(",", ":")))
        ctx.log.info("omaha: offer replaced by noupdate before reaching the device")
