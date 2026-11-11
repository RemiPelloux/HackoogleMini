#!/usr/bin/env python3
"""Entry point for the Google Home Mini replacement voice agent.

Usage:
  # from reconstruction/agent/
  python main.py

  # list Cast devices without starting the loop:
  python main.py --list-cast

  # test TTS → Cast without wake word:
  python main.py --say "Bonjour, je suis votre assistant local."
"""
import argparse
import asyncio
import logging
import sys

from config import LOG_LEVEL
import cast_out
import tts
from mcp_pool import MCPPool
from voice_loop import run

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


async def _main(args: argparse.Namespace) -> int:
    if args.list_cast:
        devices = cast_out.list_devices()
        if not devices:
            print("No Cast devices found on the LAN.")
            return 1
        for d in devices:
            print(f"{d['name']:30s} {d['host']}  model={d['model']}")
        return 0

    if args.say:
        url = tts.synthesise(args.say)
        print(f"TTS URL: {url}")
        cast_out.play(url)
        await asyncio.sleep(10)  # let Cast finish
        return 0

    pool = MCPPool()
    await pool.start()
    log.info("MCP pool ready (%d tools)", len(pool.tool_schemas()))

    try:
        await run(pool)
    except KeyboardInterrupt:
        log.info("Stopped.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Local LLM voice agent via Google Home Mini")
    ap.add_argument("--list-cast", action="store_true",
                    help="List Cast devices and exit")
    ap.add_argument("--say", metavar="TEXT",
                    help="Synthesise TEXT via TTS and play it, then exit")
    args = ap.parse_args()
    sys.exit(asyncio.run(_main(args)))


if __name__ == "__main__":
    main()
