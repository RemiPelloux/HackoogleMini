#!/usr/bin/env python3
"""UDP server that receives raw PCM audio from the LD_PRELOAD hook on the Mini,
runs Whisper STT + DeepSeek LLM + Piper TTS, and sends back a Cast-playable URL.

This is the Pi-side counterpart to reconstruction/payload/libassist_hook.c.

Protocol:
  ← device sends UDP datagrams with 1280-byte raw 16kHz 16-bit mono PCM chunks
  → server sends back a null-terminated ASCII URL string (TTS WAV for Cast to play)

Usage:
  python3 pi_whisper_server.py

Configure BIND_PORT, CAST_URL_BASE in config.py or via env vars.
"""
import asyncio
import logging
import socket
import time

import stt
import tts
import cast_out
import llm as llm_mod
from config import OLLAMA_MODEL, MIC_SAMPLE_RATE
from mcp_pool import MCPPool

log = logging.getLogger(__name__)

BIND_HOST = "0.0.0.0"
BIND_PORT = 5050
SILENCE_TIMEOUT = 1.5   # seconds of no packets = end of utterance
MIN_AUDIO_SEC   = 0.4   # minimum audio to attempt STT


class AudioCollector(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, pool: MCPPool):
        self._loop = loop
        self._pool = pool
        self._buf = bytearray()
        self._last_packet = 0.0
        self._transport = None
        self._pending: asyncio.Task | None = None
        self._client_addr = None

    def connection_made(self, transport):
        self._transport = transport
        log.info("UDP server ready on %s:%d", BIND_HOST, BIND_PORT)

    def datagram_received(self, data: bytes, addr):
        self._client_addr = addr
        self._buf.extend(data)
        self._last_packet = time.monotonic()

        # Cancel any pending silence-timeout task and restart it
        if self._pending:
            self._pending.cancel()
        self._pending = self._loop.create_task(self._silence_timeout())

    async def _silence_timeout(self):
        await asyncio.sleep(SILENCE_TIMEOUT)
        if not self._buf:
            return
        audio = bytes(self._buf)
        self._buf.clear()

        duration = len(audio) / (MIC_SAMPLE_RATE * 2)
        if duration < MIN_AUDIO_SEC:
            log.debug("utterance too short (%.2fs), skipping", duration)
            return

        log.info("[audio %.1fs received] transcribing …", duration)
        t0 = time.monotonic()

        try:
            text = stt.transcribe(audio, MIC_SAMPLE_RATE)
            log.info("[STT %.1fs] %r", time.monotonic() - t0, text)
            if not text:
                return

            reply = await llm_mod.respond(text, self._pool)
            log.info("[LLM %.1fs] %r", time.monotonic() - t0, reply)
            if not reply:
                return

            url = tts.synthesise(reply)
            log.info("[TTS ready] %s", url)

            # Send URL back to device so cast_shell can play it
            if self._transport and self._client_addr:
                self._transport.sendto(
                    (url + "\x00").encode(), self._client_addr)

            # Also push directly via pychromecast (belt + suspenders)
            try:
                cast_out.play(url)
            except Exception as e:
                log.debug("cast_out.play failed (may be ok): %s", e)

        except Exception as e:
            log.error("Pipeline error: %s", e)


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    pool = MCPPool()
    await pool.start()

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: AudioCollector(loop, pool),
        local_addr=(BIND_HOST, BIND_PORT),
    )
    log.info("Waiting for audio from the Mini on UDP :%d …", BIND_PORT)
    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
