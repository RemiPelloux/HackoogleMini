#!/usr/bin/env python3
"""Play an audio URL on a Cast device, and print what devices exist.

This is the "speaker half" of the replacement stack: with the Mini on Wi-Fi you
can push arbitrary TTS audio to it without touching firmware. That is enough to
build  mic -> STT -> LLM -> MCP tools -> TTS -> Mini  on a local box.

Usage:
  scripts/cast_play.py --list
  scripts/cast_play.py --play http://192.168.1.24:8000/tts.wav
  scripts/cast_play.py --play URL --device "Kitchen speaker"
"""
import sys
import time

import pychromecast


def discover(timeout=8):
    casts, browser = pychromecast.get_chromecasts(timeout=timeout)
    return casts, browser


def main():
    argv = sys.argv[1:]
    if not argv or "--list" in argv:
        casts, browser = discover()
        if not casts:
            print("no Cast devices found")
        for c in casts:
            ci = c.cast_info
            print(f"{ci.friendly_name:28s} {ci.host}:{ci.port}  model={ci.model_name} "
                  f"type={ci.cast_type}")
        pychromecast.discovery.stop_discovery(browser)
        return

    if "--play" not in argv:
        print(__doc__)
        sys.exit(1)
    url = argv[argv.index("--play") + 1]
    want = argv[argv.index("--device") + 1] if "--device" in argv else None

    casts, browser = discover()
    if not casts:
        print("no Cast devices found")
        sys.exit(2)
    target = None
    for c in casts:
        if want is None or want.lower() in c.cast_info.friendly_name.lower():
            target = c
            break
    pychromecast.discovery.stop_discovery(browser)
    if target is None:
        print(f"no device matching {want!r}; candidates: "
              f"{[c.cast_info.friendly_name for c in casts]}")
        sys.exit(2)

    print(f"-> {target.cast_info.friendly_name} ({target.cast_info.model_name})")
    target.wait(timeout=15)
    mc = target.media_controller
    mc.play_media(url, "audio/wav")
    mc.block_until_active(timeout=20)
    print(f"state: {mc.status.player_state}  {mc.status.display_name or ''}")
    time.sleep(1)


if __name__ == "__main__":
    main()
