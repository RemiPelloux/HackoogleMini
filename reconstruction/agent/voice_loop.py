"""Main voice loop: wake → record → STT → LLM+MCP → TTS → Cast.

Transport-agnostic design: audio_in and audio_out are callbacks so the
same loop works with any mic source (local device, ESP32, phone) and any
speaker output (Cast, local speaker, file).
"""
import asyncio
import logging
import queue
import threading
import time
from typing import Callable

import numpy as np
import sounddevice as sd

import cast_out
import llm as llm_mod
import stt
import tts
import wake as wake_mod
from config import (MAX_RECORD_SEC, MIC_CHUNK, MIC_DEVICE, MIC_SAMPLE_RATE,
                    VAD_SILENCE_SEC)
from mcp_pool import MCPPool

log = logging.getLogger(__name__)

# Simple energy-based VAD threshold (normalised 0–1 scale)
_VAD_ENERGY = 0.008


def _record_until_silence(audio_q: queue.Queue,
                           stop_event: threading.Event) -> bytes:
    """Pull chunks from audio_q until silence or max duration. Return PCM bytes."""
    buf = bytearray()
    silent_samples = 0
    silence_limit = int(VAD_SILENCE_SEC * MIC_SAMPLE_RATE)
    max_samples    = int(MAX_RECORD_SEC  * MIC_SAMPLE_RATE)
    samples_read   = 0

    while not stop_event.is_set():
        try:
            chunk = audio_q.get(timeout=0.2)
        except queue.Empty:
            continue

        buf.extend(chunk)
        audio = np.frombuffer(chunk, dtype=np.int16).astype(np.float32) / 32768.0
        energy = float(np.sqrt(np.mean(audio ** 2)))

        if energy < _VAD_ENERGY:
            silent_samples += len(audio)
        else:
            silent_samples = 0

        samples_read += len(audio)
        if silent_samples >= silence_limit or samples_read >= max_samples:
            break

    return bytes(buf)


async def run(pool: MCPPool) -> None:
    """Run the voice loop forever. Ctrl-C to stop."""
    audio_q: queue.Queue = queue.Queue(maxsize=200)
    stop_event = threading.Event()

    def mic_callback(indata, frames, time_info, status):
        if status:
            log.debug("mic status: %s", status)
        audio_q.put(bytes(indata))

    stream_kw = dict(
        samplerate=MIC_SAMPLE_RATE,
        channels=1,
        dtype="int16",
        blocksize=MIC_CHUNK,
        callback=mic_callback,
    )
    if MIC_DEVICE is not None:
        stream_kw["device"] = MIC_DEVICE

    log.info("Voice loop started — say the wake word to begin")

    with sd.RawInputStream(**stream_kw):
        while True:
            # ── Phase 1: wait for wake word ──────────────────────────────────
            with audio_q.mutex:
                audio_q.queue.clear()
            detected = wake_mod.listen_for_wake(audio_q, stop_event)
            if not detected:
                break

            # ── Phase 2: record utterance ────────────────────────────────────
            log.info("[recording …]")
            with audio_q.mutex:
                audio_q.queue.clear()
            pcm = _record_until_silence(audio_q, stop_event)
            if len(pcm) < MIC_SAMPLE_RATE // 4:  # less than 0.25 s — skip
                log.debug("utterance too short, ignored")
                continue

            # ── Phase 3: STT ─────────────────────────────────────────────────
            t0 = time.monotonic()
            text = stt.transcribe(pcm, MIC_SAMPLE_RATE)
            log.info("[STT %.1fs] %r", time.monotonic() - t0, text)
            if not text:
                continue

            # ── Phase 4: LLM + MCP ───────────────────────────────────────────
            t1 = time.monotonic()
            reply = await llm_mod.respond(text, pool)
            log.info("[LLM %.1fs] %r", time.monotonic() - t1, reply)
            if not reply:
                continue

            # ── Phase 5: TTS → Cast ──────────────────────────────────────────
            t2 = time.monotonic()
            url = tts.synthesise(reply)
            log.info("[TTS %.1fs] %s", time.monotonic() - t2, url)

            try:
                cast_out.play(url)
                log.info("[total %.1fs]", time.monotonic() - t0)
            except Exception as e:
                log.error("Cast playback failed: %s", e)
