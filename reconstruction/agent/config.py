"""Central configuration — edit this file, not the code."""
import os

# ── Cast output ───────────────────────────────────────────────────────────────
CAST_DEVICE       = os.getenv("CAST_DEVICE", "")        # empty → first found
CAST_DISCOVER_SEC = int(os.getenv("CAST_DISCOVER_SEC", "10"))

# ── TTS (Piper) ───────────────────────────────────────────────────────────────
PIPER_BINARY      = os.getenv("PIPER_BIN", "piper")
PIPER_MODEL       = os.getenv("PIPER_MODEL", "en_US-lessac-medium.onnx")
TTS_SERVE_HOST    = os.getenv("TTS_HOST", "0.0.0.0")
TTS_SERVE_PORT    = int(os.getenv("TTS_PORT", "8765"))
# URL the Cast device will pull from (must be LAN-reachable, NOT localhost)
TTS_CAST_URL_BASE = os.getenv("TTS_CAST_URL", "http://192.168.1.100:8765")

# ── STT (faster-whisper) ─────────────────────────────────────────────────────
WHISPER_MODEL     = os.getenv("WHISPER_MODEL", "base")  # tiny/base/small/medium
WHISPER_DEVICE    = os.getenv("WHISPER_DEVICE", "cpu")  # cpu / cuda
WHISPER_LANG      = os.getenv("WHISPER_LANG", "fr")     # device is FR locale

# ── Wake word (openWakeWord) ──────────────────────────────────────────────────
WAKE_MODEL        = os.getenv("WAKE_MODEL", "hey_jarvis")   # or "hey_mycroft"
WAKE_THRESHOLD    = float(os.getenv("WAKE_THRESHOLD", "0.5"))

# ── Microphone ────────────────────────────────────────────────────────────────
MIC_DEVICE        = os.getenv("MIC_DEVICE", None)       # None → system default
MIC_SAMPLE_RATE   = 16000
MIC_CHUNK         = 1280                                 # 80ms @ 16kHz

# ── LLM (Ollama) ─────────────────────────────────────────────────────────────
OLLAMA_HOST       = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")
LLM_SYSTEM_PROMPT = os.getenv("LLM_SYSTEM_PROMPT",
    "You are a helpful home assistant. Be concise — your answer is spoken aloud."
)
LLM_TIMEOUT_SEC   = int(os.getenv("LLM_TIMEOUT", "30"))

# ── MCP servers ───────────────────────────────────────────────────────────────
# List of {name, command, args, env} dicts — each starts a stdio MCP server.
# Example: {"name": "filesystem", "command": "npx",
#            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"]}
MCP_SERVERS: list[dict] = []

# ── Latency / debug ───────────────────────────────────────────────────────────
LOG_LEVEL         = os.getenv("LOG_LEVEL", "INFO")
VAD_SILENCE_SEC   = float(os.getenv("VAD_SILENCE", "1.2"))  # stop recording after
MAX_RECORD_SEC    = float(os.getenv("MAX_RECORD", "15.0"))
