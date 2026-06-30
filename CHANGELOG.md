# Changelog

All notable changes to SentinelPi are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- SIEM exports (ECS/CEF/OTLP) no longer reverse source and destination for
  detector alerts where the actor is in `related_host` (port scan, lateral
  movement); the attacker is now mapped to the SIEM source, not the target.
- Suspicion-trend charts return the newest points when a host has more than the
  query limit, instead of charting the oldest points and dropping the current trend.
- The config-doctor packet-capture preflight now gates on Scapy availability to
  match the actual runtime dependency, so `--check` can no longer report OK for a
  `dumpcap`-only environment the daemon will not use.

### Changed

- Declare Python 3.10 support (`requires-python = ">=3.10"`); ruff and mypy now
  target 3.10, and CI runs the suite on 3.10, 3.11, and 3.12.
- Add `[project.urls]` (Homepage, Repository, Issues) and set package author
  metadata (Dylan Sparks).

## [1.0.0] - 2026-06-23

First stable release: a lightweight, whole-network defensive anomaly monitor for
Raspberry Pi.

### Added

- **Detection engine** — per-host behavioral baselines and detectors for port
  scans, host sweeps, connection spikes, new destinations, new listening ports,
  beaconing, ARP spoofing, auth-log brute force, and DNS anomalies (high-entropy
  domains, tunneling, NXDOMAIN/DGA rate, suspicious TLDs, DoH/DoT bypass).
- **Per-host behavior profiles** — learned active hours, country/ASN, peer set,
  destination ports, protocol mix, and per-flow byte ranges, flagging first
  off-profile values once each dimension is established.
- **Adaptive per-host thresholds** — multiplicative backoff so chatty hosts settle
  without changing global sensitivity, decaying back as a host goes quiet and
  never dropping below the global floor.
- **Threat intelligence** — blocklist matching plus centralized GeoIP, new-country
  detection, and ASN/hosting-provider reputation tagging.
- **Alert explainability** — structured evidence and confidence rationale attached
  by every detector, rendered as a "Why this fired" block in the dashboard.
- **Incident correlation** — single-host ordered sequences (new device → port scan
  → lateral movement) and cross-sensor/cross-target incidents combined into one
  narrative timeline.
- **Active response** (dry-run default, approval-gated) — firewall quarantine,
  DNS sinkhole, ARP-spoof auto-restore, honeypot/canary ports, and a kill-switch
  command responder, with a human-in-the-loop approval workflow.
- **Multi-host coverage** — sensor/collector alert forwarding with mTLS,
  per-sensor dashboard views, span/mirror-port capture, router/firewall flow
  ingestion, passive device fingerprinting, and DHCP-lease device identity.
- **Dashboard** — production waitress server with graceful shutdown, browser
  login + Bearer auth, live updates over server-sent events (polling fallback),
  per-host drill-down pages, open-port rollups, and suspicion-trend charts.
- **Notifications** — console, email, webhook, forwarding, ntfy actionable
  approve/reject, and Twilio SMS notifiers.
- **SIEM export** — ECS (Elastic Common Schema) JSON, CEF (syslog), and
  OpenTelemetry OTLP/HTTP logs.
- **Operational watchdog** — self-monitoring for dead worker threads, stalled
  capture, queue saturation, threat-feed refresh failures, and low disk, surfaced
  via `/api/status`, the dashboard health badge, and the daily report.
- **Backup/restore** — `--backup`/`--restore` for a consistent, checksum-verified
  snapshot of the full SQLite database and all learned baseline state.
- **Config doctor** — `--check` active preflight that probes configured
  notifiers/responders and the optional files/binaries enabled features depend on,
  plus `--check-config` validation that rejects invalid operator input.
- **Packaging & deployment** — installable wheel/sdist with bundled dashboard
  templates, hardened systemd unit + install/uninstall scripts, and a
  containerized path (multi-stage Dockerfile, docker-compose, non-root capture).
- **CI** — compile checks, ruff, mypy, coverage gate (`fail_under = 70`), and a
  packaging smoke test.

[Unreleased]: https://github.com/sparktron/sentinelPi/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sparktron/sentinelPi/releases/tag/v1.0.0
