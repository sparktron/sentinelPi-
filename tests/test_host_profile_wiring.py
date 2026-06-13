from __future__ import annotations

from sentinelpi.detectors.host_profile_detector import HostProfileDetector


def test_host_profile_detector_is_event_routed(config, tmp_path):
    from sentinelpi.main import SentinelPi

    config_path = tmp_path / "sentinelpi.yaml"
    config_path.write_text(
        "\n".join([
            "monitoring:",
            "  packet_capture_enabled: false",
            "  host_profile_detection_enabled: true",
            "storage:",
            f"  db_path: {tmp_path / 'app.db'}",
            "logging:",
            f"  log_dir: {tmp_path / 'logs'}",
            f"  json_alerts_file: {tmp_path / 'alerts.json'}",
        ]),
        encoding="utf-8",
    )

    app = SentinelPi(config_path=str(config_path))
    try:
        assert any(isinstance(det, HostProfileDetector) for det in app._build_event_detectors())
    finally:
        app._shutdown()
