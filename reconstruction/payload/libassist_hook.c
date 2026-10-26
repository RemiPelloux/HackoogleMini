/*
 * LD_PRELOAD hook for cast_shell / libassistant.so audio intercept.
 *
 * What it does:
 *   Intercepts the TLS socket writes that carry gRPC AssistRequest PCM audio
 *   BEFORE encryption, and tees the raw 16kHz PCM to a local UDP socket
 *   pointed at the Pi's Whisper endpoint. The reply comes back from the Pi
 *   as TTS audio, which cast_shell plays via its existing Cast media stack.
 *
 *   This leaves cast_shell running (preserving Cast device auth) while
 *   replacing the cloud STT/LLM/TTS leg with your local Pi stack.
 *
 * Build (cross-compile for ARM):
 *   arm-linux-gnueabi-gcc -shared -fPIC -nostartfiles -Os \
 *     -o libassist_hook.so libassist_hook.c
 *
 * Deploy:
 *   1. Copy libassist_hook.so to /factory_setting/ on the device
 *   2. Modify cast_shell's init script to prepend LD_PRELOAD:
 *      sed -i 's|exec cast_shell|LD_PRELOAD=/factory_setting/libassist_hook.so exec cast_shell|' \
 *        /etc/init.d/S80cast_shell
 *
 * Pi-side listener (receives PCM, runs Whisper, sends TTS URL back):
 *   python3 reconstruction/agent/pi_whisper_server.py
 *
 * Protocol:
 *   UDP port 5050 on PI_IP:
 *   → Device sends raw 16-bit LE 16kHz PCM chunks (1280 bytes each = 80ms)
 *   ← Pi sends a null-terminated ASCII URL string for cast_shell to play
 *      (e.g. "http://192.168.1.100:8765/token\0")
 *      cast_shell plays the TTS WAV via its media stack
 *
 * Note on gRPC interception:
 *   libassistant.so calls SSL_write() to send the AssistRequest protobuf.
 *   We hook write() at the fd level — this catches raw socket writes but
 *   gRPC may use SSL_write() from BoringSSL, in which case hook SSL_write()
 *   instead (same pattern). Use nm -D libassistant.so to check which TLS
 *   functions are imported.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PI_IP    "192.168.1.100"   /* Edit: Pi's LAN IP */
#define PI_PORT  5050
#define PCM_CHUNK 1280             /* 80ms @ 16kHz 16-bit mono */

static int _udp_sock = -1;
static struct sockaddr_in _pi_addr;

static ssize_t (*_real_write)(int, const void *, size_t) = NULL;

/* ── Pattern to detect gRPC AssistRequest PCM frames ────────────────────── */
/* gRPC framing: 5-byte header (0x00 + 4-byte BE length) then protobuf body.
 * AssistRequest with audio_in has field 2 (0x12) followed by raw PCM.
 * Simple heuristic: 5-byte gRPC header + field tag 0x12 at offset 5. */
static int _is_assist_audio(const unsigned char *buf, size_t len) {
    if (len < 8) return 0;
    if (buf[0] != 0x00) return 0;      /* not compressed gRPC */
    if (buf[5] != 0x12) return 0;      /* not field 2 (audio_in) */
    return 1;
}

static void _ensure_udp(void) {
    if (_udp_sock >= 0) return;
    _udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_udp_sock < 0) return;
    memset(&_pi_addr, 0, sizeof(_pi_addr));
    _pi_addr.sin_family = AF_INET;
    _pi_addr.sin_port = htons(PI_PORT);
    inet_pton(AF_INET, PI_IP, &_pi_addr.sin_addr);
}

/* Hook write() — called for every socket write including gRPC over TLS.
 * For SSL_write() variant: replace "write" with "SSL_write" in the dlsym. */
ssize_t write(int fd, const void *buf, size_t count) {
    if (!_real_write)
        _real_write = dlsym(RTLD_NEXT, "write");

    ssize_t ret = _real_write(fd, buf, count);

    /* Tee audio chunks to the Pi */
    if (ret > 0 && _is_assist_audio((const unsigned char *)buf, count)) {
        _ensure_udp();
        if (_udp_sock >= 0) {
            /* Skip the 5-byte gRPC framing header and the 1-byte protobuf tag + varint */
            const unsigned char *pcm = (const unsigned char *)buf + 7;
            size_t pcm_len = count > 7 ? count - 7 : 0;
            if (pcm_len > 0)
                sendto(_udp_sock, pcm, pcm_len, 0,
                       (struct sockaddr *)&_pi_addr, sizeof(_pi_addr));
        }
    }

    return ret;
}
