"""Speech-to-text via faster-whisper. Transcribes raw 16kHz mono PCM bytes."""
import logging
import numpy as np

from config import WHISPER_DEVICE, WHISPER_LANG, WHISPER_MODEL

log = logging.getLogger(__name__)

_model = None


def _get_model():
    global _model
    if _model is None:
        from faster_whisper import WhisperModel
        log.info("Loading Whisper model %s on %s …", WHISPER_MODEL, WHISPER_DEVICE)
        _model = WhisperModel(WHISPER_MODEL, device=WHISPER_DEVICE,
                              compute_type="int8")
        log.info("Whisper ready")
    return _model


def transcribe(pcm_bytes: bytes, sample_rate: int = 16000) -> str:
    """Transcribe raw 16-bit little-endian 16kHz mono PCM. Returns text."""
    model = _get_model()
    audio = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0
    segments, info = model.transcribe(
        audio,
        language=WHISPER_LANG if WHISPER_LANG else None,
        vad_filter=True,
        vad_parameters={"min_silence_duration_ms": 500},
    )
    text = " ".join(seg.text.strip() for seg in segments).strip()
    log.debug("STT [%.1fs detected_lang=%s]: %r",
              info.duration, info.language, text)
    return text
