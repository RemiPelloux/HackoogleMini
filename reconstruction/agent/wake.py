"""Wake-word detection via openWakeWord (streaming, runs in background thread)."""
import logging
import queue
import threading

import numpy as np

from config import MIC_CHUNK, MIC_SAMPLE_RATE, WAKE_MODEL, WAKE_THRESHOLD

log = logging.getLogger(__name__)

_oww = None


def _get_oww():
    global _oww
    if _oww is None:
        import openwakeword
        from openwakeword.model import Model
        openwakeword.utils.download_models()
        _oww = Model(wakeword_models=[WAKE_MODEL], inference_framework="onnx")
        log.info("Wake-word model loaded: %s (threshold=%.2f)",
                 WAKE_MODEL, WAKE_THRESHOLD)
    return _oww


def listen_for_wake(audio_queue: queue.Queue, stop_event: threading.Event) -> bool:
    """Pull chunks from audio_queue, return True when wake word detected.

    audio_queue yields bytes chunks (MIC_CHUNK samples, 16-bit LE, 16kHz mono).
    stop_event signals this function to return False immediately.
    """
    oww = _get_oww()
    oww.reset()

    while not stop_event.is_set():
        try:
            chunk = audio_queue.get(timeout=0.1)
        except queue.Empty:
            continue

        audio = np.frombuffer(chunk, dtype=np.int16)
        pred = oww.predict(audio)
        score = pred.get(WAKE_MODEL, 0.0)
        if score >= WAKE_THRESHOLD:
            log.info("Wake word detected (score=%.3f)", score)
            oww.reset()
            return True

    return False
