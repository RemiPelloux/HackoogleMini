"""Cast audio output — push a URL to the Google Home Mini's speaker."""
import logging
import time

import pychromecast

from config import CAST_DEVICE, CAST_DISCOVER_SEC

log = logging.getLogger(__name__)

_cast: pychromecast.Chromecast | None = None
_browser = None


def _connect() -> pychromecast.Chromecast:
    global _cast, _browser
    if _cast is not None:
        try:
            _cast.socket_client.ping()
            return _cast
        except Exception:
            log.warning("Cast link dead, reconnecting")
            _cast = None

    casts, browser = pychromecast.get_chromecasts(timeout=CAST_DISCOVER_SEC)
    if _browser:
        try:
            pychromecast.discovery.stop_discovery(_browser)
        except Exception:
            pass
    _browser = browser

    if not casts:
        raise RuntimeError("No Cast devices found on the LAN")

    if CAST_DEVICE:
        found = [c for c in casts if CAST_DEVICE.lower() in
                 c.cast_info.friendly_name.lower()]
        if not found:
            names = [c.cast_info.friendly_name for c in casts]
            raise RuntimeError(f"Cast device {CAST_DEVICE!r} not found; "
                               f"available: {names}")
        _cast = found[0]
    else:
        _cast = casts[0]

    _cast.wait(timeout=15)
    log.info("Connected to %s (%s)", _cast.cast_info.friendly_name,
             _cast.cast_info.host)
    return _cast


def play(url: str, content_type: str = "audio/wav") -> None:
    """Play an audio URL on the Cast device. Blocks until playback starts."""
    cast = _connect()
    mc = cast.media_controller
    mc.play_media(url, content_type)
    mc.block_until_active(timeout=10)
    log.info("Playing %s on %s", url, cast.cast_info.friendly_name)


def stop() -> None:
    global _cast
    if _cast:
        try:
            _cast.media_controller.stop()
        except Exception:
            pass


def list_devices(timeout: int = CAST_DISCOVER_SEC) -> list[dict]:
    casts, browser = pychromecast.get_chromecasts(timeout=timeout)
    result = [{"name": c.cast_info.friendly_name,
               "host": c.cast_info.host,
               "model": c.cast_info.model_name} for c in casts]
    pychromecast.discovery.stop_discovery(browser)
    return result
