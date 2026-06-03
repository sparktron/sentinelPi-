"""
tests/test_device_classifier.py - Tests for Phase 1 passive device fingerprinting.

Covers the pure classifier (precedence + per-signal confidence) and its
integration into DeviceTracker (new devices get a device_type that persists and
appears in the new-device alert).
"""

from __future__ import annotations

from sentinelpi.inventory import device_classifier as dc
from sentinelpi.inventory.device_classifier import classify_device


# ---------------------------------------------------------------- pure classifier
def test_gateway_is_router_with_highest_priority():
    # is_gateway wins even over a vendor that says otherwise.
    c = classify_device(vendor="Apple", hostname="iphone", is_gateway=True)
    assert c.device_type == dc.ROUTER
    assert c.confidence >= 0.9


def test_hostname_beats_vendor():
    # Vendor would say apple_device, but the hostname clearly says phone.
    c = classify_device(vendor="Apple, Inc.", hostname="Johns-iPhone")
    assert c.device_type == dc.PHONE
    assert "iphone" in c.rationale.lower()


def test_specific_vendor_camera():
    c = classify_device(vendor="Hikvision Digital Technology")
    assert c.device_type == dc.CAMERA
    assert c.confidence >= 0.85


def test_sbc_vendor():
    assert classify_device(vendor="Raspberry Pi Trading Ltd").device_type == dc.SBC


def test_printer_hostname():
    assert classify_device(hostname="HP-LaserJet-4200").device_type == dc.PRINTER


def test_ambiguous_apple_vendor_low_confidence():
    c = classify_device(vendor="Apple, Inc.")
    assert c.device_type == dc.APPLE_DEVICE
    assert c.confidence < 0.6


def test_unknown_when_nothing_matches():
    c = classify_device(vendor="Obscure Widgets LLC", hostname="thing-1234")
    assert c.device_type == dc.UNKNOWN
    assert c.confidence == 0.0


def test_empty_signals_are_unknown():
    assert classify_device().device_type == dc.UNKNOWN


# ---------------------------------------------------------------- integration
def test_new_device_gets_classified_and_persists(config, db, device_tracker):
    from sentinelpi.capture.proc_reader import ARPEntry
    from sentinelpi.utils import clock

    # MAC whose OUI maps to a known camera vendor would require OUI data; instead
    # drive the hostname path via a stubbed reverse_dns.
    import sentinelpi.inventory.device_tracker as dt
    monkey = ARPEntry(ip="192.168.1.77", mac="de:ad:be:ef:00:77", interface="eth0", flags="0x2")

    orig = dt.reverse_dns
    dt.reverse_dns = lambda ip, timeout=0.5: "living-room-camera"
    try:
        device = device_tracker._create_device(monkey, clock.now())
    finally:
        dt.reverse_dns = orig

    assert device.extra["device_type"] == dc.CAMERA

    # Persists through the DB round-trip.
    db.upsert_device(device)
    loaded = db.get_all_devices()
    match = [d for d in loaded if d.ip == "192.168.1.77"][0]
    assert match.extra["device_type"] == dc.CAMERA


def test_new_device_alert_mentions_type(config, db, device_tracker):
    from sentinelpi.models import Device

    device = Device(ip="192.168.1.88", mac="aa:bb:cc:dd:ee:88", vendor="Synology")
    device.extra["device_type"] = dc.NAS
    alert = device_tracker._new_device_alert(device)
    assert "nas" in alert.title.lower()
