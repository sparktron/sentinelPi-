# SentinelPi — Feature Roadmap

Goal: evolve SentinelPi from a strong single-host anomaly monitor into **the protector of the
whole network** — broader visibility, smarter detection, real response, and a usable interface.

This roadmap is sequenced so each phase is independently shippable and builds on the last.
Phase 0 is the prerequisite cleanup from `CODE_REVIEW.md`; don't build new detection on top of
racy detectors.

---

## Phase 0 — Stabilize the foundation _(prereq)_
- ✅ Fix concurrency (locks), reverse-DNS, dedup memory, baseline math, dashboard auth (see review C1/C2/H1/H2/H4).
- ✅ Add a concurrency stress test and a migration test so the new features below have a safety net.
- ✅ Introduce a single `clock` abstraction (timezone-aware) to make detection deterministic and testable (review M1).
- ✅ Production dashboard server + clean shutdown (review H3).

**Outcome:** a daemon you can trust to run for months.

_Status 2026-06-02: **Phase 0 complete.** All Critical/High items plus the
timezone-aware clock (M1) and production web server (H3) are fixed with regression
tests; suite green at 77 tests. Remaining review items are M2–M6 / L1–L6 hardening
and polish — none block Phase 1._

---

## Phase 1 — Visibility & intelligence enrichment
Make every alert more actionable without new detectors.

- ✅ **Threat-intel feeds.** Match destination IPs/domains against blocklists (abuse.ch URLhaus,
  Feodo Tracker, Spamhaus DROP). Cache locally, refresh daily, promote hits to HIGH.
  _Shipped: `intel/threat_feeds.py` (service, pure parsers, injectable fetcher, IP/CIDR/domain
  matching, on-disk cache, graceful degrade) + `detectors/threat_intel_detector.py`; opt-in via
  `threat_intel.enabled`. Tests in `test_threat_intel.py`. FireHOL feed can be added to the `FEEDS`
  catalog later._
- ✅ **Local DNS-over-HTTPS / DoH detection.** Flag clients bypassing your DNS by talking DoH/DoT to
  known resolvers — a common exfil/evasion vector and directly complements the existing DNS detector.
  _Shipped: `detectors/doh_detector.py` — DoT (TCP 853) to any external host, DoH (TCP 443) to a
  curated set of known public resolver IPs; sanctioned-resolver allowlist; opt-in via
  `monitoring.doh_detection_enabled` (default on). Tests in `test_doh_detector.py`._
- ✅ **Passive OS / device fingerprinting.** Classify devices (camera, phone, computer, printer,
  TV, voice assistant, NAS, game console, SBC, router, IoT) from OUI vendor + hostname + gateway.
  _Shipped: `inventory/device_classifier.py` (data-driven, hostname-beats-vendor precedence,
  per-signal confidence); `DeviceTracker` stamps `device_type` into `Device.extra` (persisted),
  the new-device alert names the type, and the dashboard device API exposes it. Tests in
  `test_device_classifier.py`. Follow-up: fold in an open-port profile once active discovery
  inventories per-device ports._
- ✅ **GeoIP everywhere.** "First connection to a new country for this host" detector.
  _Shipped: `detectors/geo_country_detector.py` — per-host country baseline persisted in the new
  `host_countries` table (schema v4); alerts MEDIUM on a first-seen country (after the learning
  phase), staying silent without a GeoIP DB. Gated on `monitoring.geo_enabled`. Tests in
  `test_geo_country_detector.py`. Follow-up: attach country to **every** external-connection alert
  (broad enrichment of the other detectors), not just this one._
- **ASN / hosting-provider tagging.** Connections to bulletproof/anonymizing ASNs (via an IP→ASN
  db) raise suspicion scores.

---

## Phase 2 — Active protection (the "protector" leap)
Move from detect-only to detect-and-respond. **Gate every action behind explicit config + dry-run.**

- **Response actions framework.** A pluggable `Responder` interface mirroring `Notifier`:
  - **Quarantine** a host via `iptables`/`nftables` drop rules or switch-port ACL.
  - **ARP-spoof defense:** pin gateway MAC and auto-restore the correct ARP entry on detected poisoning.
  - **DNS sinkhole:** push a block to a local Pi-hole/Unbound via its API when a DGA/C2 domain fires.
  - **Kill switch:** disable a port or de-auth a Wi-Fi client (via router API / hostapd) on confirmed compromise.
  - Every responder runs in **dry-run by default**, logs intended action, and requires per-action opt-in.
- **Approval workflow.** HIGH/CRITICAL responses can require one-click confirmation from the
  dashboard or a notifier (e.g. a Telegram/Slack button) before executing — auto-execute only for
  the categories the user explicitly trusts.
- **Honeypot / canary ports.** Open a few fake services; any connection to them is high-fidelity
  evidence of internal scanning and auto-quarantines the source.

---

## Phase 3 — Multi-host / whole-network coverage
Today SentinelPi sees its own host + the LAN it can sniff. To protect *the network*:

- **Sensor + collector architecture.** Run lightweight SentinelPi **sensors** on multiple Pis /
  VLANs that forward events to a central **collector** (gRPC or mTLS HTTP). Correlate across sensors
  so a host sweep spanning VLANs is seen as one event.
- **Router/firewall integration.** Ingest flow data (NetFlow/IPFIX, `conntrack`, or pfSense/OPNsense
  logs) so you see traffic that never crosses the Pi's segment.
- **Span/mirror-port mode.** Document and support capture from a switch mirror port to monitor the
  whole subnet, not just broadcast/local traffic.
- **DHCP + device-identity source of truth.** Pull leases from the router so device naming and
  "new device" detection are authoritative rather than ARP-inferred.

---

## Phase 4 — Smarter detection
- **Per-host behavioral profiles** beyond connection counts: typical destinations, ports, bytes,
  active hours, peer set. Alert on deviation from the host's *own* learned profile.
- **Sequence/correlation engine.** Turn related alerts into **incidents** (e.g. new device → port
  scan → admin connection = "possible intrusion in progress") with a single timeline, instead of N
  independent alerts. This is the highest-leverage UX + accuracy win.
- **Optional ML anomaly scoring** (IsolationForest / simple autoencoder) on the feature vectors you
  already compute, as a *secondary* signal that boosts confidence — never the sole trigger.
- **Adaptive thresholds** that learn per-network noise floors instead of static `sensitivity` tiers.
- **Encrypted-traffic heuristics:** JA3/JA3S TLS fingerprinting to spot malware C2 by its TLS
  client signature even without decryption.

---

## Phase 5 — Usability, reporting, integration
- **Real-time dashboard upgrade:** WebSocket live alert feed, network map (devices + edges), incident
  timeline view, per-host drill-down. (Pairs with the dashboard-hardening from review H2/H3.)
- **Notifier expansion:** Telegram, Slack, Discord, ntfy, Apple Push — with rich actionable buttons
  (ack / mute / quarantine).
- **Scheduled reports:** the `_generate_daily_report` scaffold → emailed daily/weekly digest + a
  monthly "security posture" summary with trends.
- **SIEM export:** native CEF/Syslog and an OpenTelemetry/ECS JSON sink so SentinelPi feeds Wazuh,
  Splunk, or Elastic.
- **Mobile-friendly status page + PWA** so "is my network OK right now?" is a glance on your phone.
- **One-command install / systemd hardening:** ship a `systemd` unit with `CAP_NET_RAW` only
  (no full root), seccomp, and read-only filesystem where possible.

---

## Phase 6 — Trust, safety, and operability
- **Tamper-evident alert log** (hash-chained) so an attacker who lands on the Pi can't silently
  delete evidence; optionally ship alerts off-box immediately.
- **Self-monitoring / watchdog:** detect if capture stopped, a thread died, or disk is full, and
  alert on *its own* degradation (a security tool that silently dies is worse than none).
- **Config validation + `--check` mode** that lints config and tests notifiers/responders in dry-run.
- **Backup/restore** of the baseline DB so a re-image doesn't reset months of learned behavior.

---

## Recommended near-term slice (highest value, lowest risk)
If you want the biggest "protector" payoff for the least work after Phase 0:

1. **Threat-intel blocklist matching** (Phase 1) — instant accuracy boost, low complexity.
2. **Incident correlation** (Phase 4) — turns alert noise into a story; biggest UX win.
3. **Responder framework in dry-run + DNS sinkhole/quarantine** (Phase 2) — the actual
   "protect" capability, shipped safely behind opt-in.
4. **Telegram/ntfy actionable notifier** (Phase 5) — closes the loop so you can respond from your phone.
