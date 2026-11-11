"""Text-to-speech via Piper, served over HTTP for the Cast device to pull."""
import http.server
import io
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from config import (PIPER_BINARY, PIPER_MODEL, TTS_CAST_URL_BASE,
                    TTS_SERVE_HOST, TTS_SERVE_PORT)

log = logging.getLogger(__name__)

# In-memory store: token → wav bytes
_files: dict[str, bytes] = {}
_lock = threading.Lock()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.path.lstrip("/")
        with _lock:
            data = _files.get(token)
        if data is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "audio/wav")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass  # suppress request logs


def _start_server():
    srv = http.server.HTTPServer((TTS_SERVE_HOST, TTS_SERVE_PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    log.info("TTS HTTP server on :%d", TTS_SERVE_PORT)


_server_started = False


def _ensure_server():
    global _server_started
    if not _server_started:
        _start_server()
        _server_started = True


def synthesise(text: str) -> str:
    """Synthesise text with Piper. Returns a URL the Cast device can pull."""
    _ensure_server()

    proc = subprocess.run(
        [PIPER_BINARY, "--model", PIPER_MODEL, "--output_raw"],
        input=text.encode(),
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"piper failed: {proc.stderr.decode()[:200]}")

    # piper --output_raw emits raw 16kHz mono PCM; wrap in a WAV header
    raw = proc.stdout
    wav = _raw_to_wav(raw, sample_rate=22050, channels=1, sampwidth=2)

    token = uuid.uuid4().hex
    with _lock:
        _files[token] = wav
        # evict old files (keep last 10)
        if len(_files) > 10:
            oldest = next(iter(_files))
            del _files[oldest]

    url = f"{TTS_CAST_URL_BASE.rstrip('/')}/{token}"
    log.debug("TTS url: %s (%d bytes)", url, len(wav))
    return url


def _raw_to_wav(raw: bytes, sample_rate: int, channels: int,
                sampwidth: int) -> bytes:
    import struct
    data_size = len(raw)
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF", 36 + data_size, b"WAVE",
        b"fmt ", 16,
        1,               # PCM
        channels,
        sample_rate,
        sample_rate * channels * sampwidth,
        channels * sampwidth,
        sampwidth * 8,
        b"data", data_size,
    )
    return header + raw
