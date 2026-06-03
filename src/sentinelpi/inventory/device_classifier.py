"""
inventory/device_classifier.py - Passive device-type fingerprinting.

Classifies a device into a coarse type (camera, printer, phone, computer, TV,
voice assistant, IoT, NAS, game console, SBC, router, …) from the passive
signals we already collect: the OUI vendor (from the MAC), the reverse-DNS
hostname, and whether it's the gateway. No active scanning.

It's intentionally conservative: a confident hostname hint beats a specific
vendor, which beats an ambiguous vendor; when nothing matches we return
``UNKNOWN`` with zero confidence rather than guessing. The type is advisory
context for alerts and the inventory ("a new *camera* just joined and is
beaconing overseas"), never a sole basis for a high-severity alert.

Adding signals later (open-port profile from active discovery) is a matter of
extending classify_device — the call sites won't change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

# Coarse device types.
ROUTER = "router"
CAMERA = "camera"
PRINTER = "printer"
PHONE = "phone"
COMPUTER = "computer"
TV = "tv"
MEDIA = "media_streamer"
VOICE_ASSISTANT = "voice_assistant"
NAS = "nas"
GAME_CONSOLE = "game_console"
SBC = "single_board_computer"
IOT = "iot"
APPLE_DEVICE = "apple_device"   # phone or computer — Apple OUI alone can't tell
UNKNOWN = "unknown"


@dataclass(frozen=True)
class DeviceClassification:
    device_type: str
    confidence: float
    rationale: str


# Hostname substring → type. Checked first (a user-set/OS hostname is a strong
# signal). Order matters: earlier, more-specific patterns win.
_HOSTNAME_RULES: List[Tuple[str, str]] = [
    ("iphone", PHONE), ("ipad", PHONE), ("android", PHONE), ("pixel", PHONE),
    ("galaxy", PHONE), ("oneplus", PHONE),
    ("macbook", COMPUTER), ("imac", COMPUTER), ("-mbp", COMPUTER),
    ("desktop", COMPUTER), ("laptop", COMPUTER), ("thinkpad", COMPUTER),
    ("printer", PRINTER), ("officejet", PRINTER), ("laserjet", PRINTER),
    ("ipcam", CAMERA), ("camera", CAMERA), ("doorbell", CAMERA),
    ("synology", NAS), ("diskstation", NAS), ("qnap", NAS), ("truenas", NAS), ("nas", NAS),
    ("echo", VOICE_ASSISTANT), ("alexa", VOICE_ASSISTANT), ("homepod", VOICE_ASSISTANT),
    ("chromecast", MEDIA), ("roku", MEDIA), ("appletv", MEDIA), ("apple-tv", MEDIA),
    ("firetv", MEDIA), ("shield", MEDIA),
    ("xbox", GAME_CONSOLE), ("playstation", GAME_CONSOLE), ("ps4", GAME_CONSOLE),
    ("ps5", GAME_CONSOLE), ("nintendo", GAME_CONSOLE),
    ("raspberrypi", SBC), ("raspberry", SBC), ("rpi", SBC),
    ("router", ROUTER), ("gateway", ROUTER), ("openwrt", ROUTER),
    ("tv", TV), ("bravia", TV),
]

# Vendor substring → (type, confidence). Specific single-purpose vendors get
# high confidence; multi-product vendors (Apple, Samsung, HP) are ambiguous.
_VENDOR_RULES: List[Tuple[str, str, float]] = [
    # Cameras / surveillance
    ("hikvision", CAMERA, 0.9), ("dahua", CAMERA, 0.9), ("axis communications", CAMERA, 0.9),
    ("reolink", CAMERA, 0.9), ("amcrest", CAMERA, 0.9), ("wyze", CAMERA, 0.8),
    # Printers
    ("canon", PRINTER, 0.7), ("epson", PRINTER, 0.7), ("brother", PRINTER, 0.8),
    ("lexmark", PRINTER, 0.85), ("xerox", PRINTER, 0.85),
    # NAS
    ("synology", NAS, 0.9), ("qnap", NAS, 0.9), ("western digital", NAS, 0.6),
    # Networking gear
    ("ubiquiti", ROUTER, 0.7), ("netgear", ROUTER, 0.6), ("tp-link", ROUTER, 0.5),
    ("d-link", ROUTER, 0.5), ("mikrotik", ROUTER, 0.8), ("aruba", ROUTER, 0.7),
    ("cisco", ROUTER, 0.6), ("juniper", ROUTER, 0.7),
    # Voice / smart speakers
    ("sonos", VOICE_ASSISTANT, 0.7),
    # Media / TV
    ("roku", MEDIA, 0.9), ("vizio", TV, 0.8), ("lg electronics", TV, 0.5),
    # Game consoles
    ("nintendo", GAME_CONSOLE, 0.9), ("sony interactive", GAME_CONSOLE, 0.9),
    # SBC
    ("raspberry pi", SBC, 0.9),
    # IoT / smart home modules
    ("espressif", IOT, 0.8), ("tuya", IOT, 0.85), ("shelly", IOT, 0.85),
    ("sonoff", IOT, 0.85), ("signify", IOT, 0.7), ("philips lighting", IOT, 0.7),
    ("ring", CAMERA, 0.7), ("nest", IOT, 0.6),
    # Amazon — Echo/Fire/Kindle, treat as IoT-ish
    ("amazon", IOT, 0.5),
    # Ambiguous multi-product vendors (low confidence — could be phone/computer/tv)
    ("apple", APPLE_DEVICE, 0.5),
    ("samsung", PHONE, 0.35),
    ("google", PHONE, 0.35),
    ("xiaomi", PHONE, 0.4), ("huawei", PHONE, 0.4),
    ("intel", COMPUTER, 0.4), ("dell", COMPUTER, 0.5), ("hewlett", COMPUTER, 0.35),
]


def classify_device(
    vendor: str = "",
    hostname: str = "",
    mac: str = "",
    is_gateway: bool = False,
) -> DeviceClassification:
    """Classify a device from passive signals. Always returns a classification."""
    if is_gateway:
        return DeviceClassification(ROUTER, 0.95, "Device is the configured network gateway.")

    host = (hostname or "").lower()
    if host:
        for needle, dtype in _HOSTNAME_RULES:
            if needle in host:
                return DeviceClassification(
                    dtype, 0.85, f"Hostname '{hostname}' matches '{needle}'."
                )

    vlow = (vendor or "").lower()
    if vlow:
        for needle, dtype, conf in _VENDOR_RULES:
            if needle in vlow:
                return DeviceClassification(
                    dtype, conf, f"OUI vendor '{vendor}' matches '{needle}'."
                )

    return DeviceClassification(UNKNOWN, 0.0, "No vendor/hostname signal matched.")
