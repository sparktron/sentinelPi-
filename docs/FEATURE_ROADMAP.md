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
  `test_geo_country_detector.py`._
- ✅ **Alert enrichment (GeoIP + ASN everywhere).** Every alert is centrally enriched in the
  `AlertManager` with the external IP's country + ASN/org — structured `extra["enrichment"]`, a
  compact description suffix, and an `enrichment` field on the dashboard alert API. No-op without
  the optional databases. Tests in `test_alert_enrichment.py`._
- ✅ **ASN / hosting-provider tagging.** Connections to suspicious ASNs/operators flag and raise
  suspicion. _Shipped: `utils/asn.py` (GeoLite2-ASN lookup, graceful degrade, singleton) +
  `detectors/asn_detector.py` (matches configured `suspicious_asns` / operator-name keywords +
  a small built-in seed; MEDIUM alert that bumps device suspicion via the manager). Gated on
  `monitoring.asn_reputation_enabled`. Tests in `test_asn_detector.py`._

---

## Phase 2 — Active protection (the "protector" leap)
Move from detect-only to detect-and-respond. **Gate every action behind explicit config + dry-run.**

- ✅ **Response actions framework.** A pluggable `Responder` interface mirroring `Notifier`.
  _Shipped: `responders/` (`BaseResponder`/`ResponderAction`, `ResponderManager`, `FirewallResponder`).
  Two-key safety model — executes only when `response.enabled` AND not `response.dry_run`; otherwise
  plans + records without running. Per-responder opt-in, category/severity allowlist (default:
  threat_intel/HIGH only), never blocks private/whitelisted IPs. Wired into the AlertManager.
  Tests in `test_responders.py`._
  - ✅ **Quarantine** a host via `iptables`/`nftables` drop rules (outbound + inbound DROP).
  - ✅ **ARP-spoof defense:** pin the configured gateway MAC and re-assert the correct ARP entry on
    detected poisoning. _Shipped: `responders/arp_restore.py` — on a gateway ARP-anomaly, restores
    `network.gateway_mac` via `arp -s` or `ip neigh replace` (only when gateway IP+MAC are
    configured). Tests in `test_arp_restore.py`._
  - ✅ **DNS sinkhole:** block a malicious domain at the resolver when a DGA/C2/threat-intel domain
    fires. _Shipped: `responders/dns_sinkhole.py` — backends `hosts` (append `0.0.0.0 <domain>`,
    idempotent), `pihole` (`pihole -b`), `unbound` (`local_zone … always_nxdomain`); category/
    severity gating; never sinkholes a whitelisted domain. Tests in `test_dns_sinkhole.py`._
  - ✅ **Kill switch:** run an operator-supplied command on confirmed compromise (hostapd de-auth,
    router API, switch-port ACL, …). _Shipped: `responders/killswitch.py` — generic command template
    with `{ip}/{mac}/{related}/{category}/{severity}` placeholders; never fires without a configured
    command + category; default gate CRITICAL. Tests in `test_killswitch.py`._
  - Every responder runs in **dry-run by default**, logs intended action, and requires per-action opt-in.
- ✅ **Approval workflow.** Armed responders hold actions as PENDING for one-click confirmation
  instead of auto-firing. _Shipped: `ResponderManager` approval gating (`require_approval` +
  `auto_execute_categories` trust list) with a pending registry and `approve()`/`reject()`;
  dashboard `/api/responses/{pending,recent,<id>/approve,<id>/reject}` (auth-gated, only present
  when responders are wired). `ResponderAction` gained id/status/lifecycle. Tests in
  `test_responders.py` + `test_response_api.py`. Follow-up: surface approve/reject in a notifier
  (Telegram/Slack button) and a dashboard UI panel._
- ✅ **Honeypot / canary ports.** Open a few fake services; any connection is high-fidelity
  evidence of internal scanning. _Shipped: `capture/honeypot.py` — binds configured canary ports,
  raises a HIGH `HONEYPOT` alert (new category) on any connect, skips unbindable ports. Gated by
  `monitoring.honeypot_enabled`. Tests (incl. a real-socket integration) in `test_honeypot.py`.
  Auto-quarantine of the (internal) source is a follow-up — it needs a gateway/switch-ACL path,
  since the firewall responder deliberately won't DROP private IPs._

---

## Phase 3 — Multi-host / whole-network coverage
Today SentinelPi sees its own host + the LAN it can sniff. To protect *the network*:

- ✅ **Sensor + collector architecture (foundation).** Lightweight sensors forward their alerts to a
  central collector that aggregates them. _Shipped: `ClusterConfig` (role standalone/sensor/collector);
  `ForwardNotifier` (sensor → collector over HTTP, shared-key auth, async queue, no event bouncing);
  collector `POST /api/ingest` (`alert_from_dict`, constant-time key check, tags `extra.sensor`, runs
  the alert through the full pipeline) active when `collector_key` is set. Tests in `test_cluster.py`._
  - ✅ **Cross-sensor correlation.** _Shipped: `alerts/correlator.py` `IncidentCorrelator` — buckets
    fired alerts by actor in a sliding window; an actor crossing `min_sensors` sensors or
    `min_targets` targets raises one escalated INCIDENT alert (HIGH/CRITICAL). Wired into the
    AlertManager (only sees alerts that actually fire; INCIDENTs never re-correlate). Gated on
    `correlation.enabled`. Tests in `test_correlator.py`._
  - ✅ **Per-sensor dashboard views.** _Shipped: schema-v6 `alerts.sensor` column (populated from
    `extra.sensor` at save time, indexed); `Database.get_sensors()` aggregates reporters with
    counts; `get_recent_alerts(sensor=…)` filters (with `"local"` selecting locally-raised alerts);
    dashboard `GET /api/sensors` + a `?sensor=` filter on `/api/alerts`, and a `sensor` field on the
    alert API. Tests in `test_per_sensor.py`._
  - ✅ **mTLS (sensor ↔ collector).** _Shipped: `ForwardNotifier` presents a client cert and verifies
    the collector via `tls_client_cert`/`tls_client_key`/`tls_ca_cert`/`tls_verify`; the collector's
    `/api/ingest` can require a reverse-proxy-verified client cert
    (`cluster.ingest_require_verified_header` → `X-SentinelPi-Client-Verified: SUCCESS`), layered on
    top of the shared key. Terminate client-cert auth at a proxy (waitress doesn't); see
    `docs/systemd_setup.md`. Tests in `test_cluster.py`._
- ✅ **Router/firewall integration.** Ingest flow data so you see traffic that never crosses the
  Pi's segment. _Shipped: `capture/flow_ingest.py` — `ConntrackFlowSource` (polls `conntrack -L`,
  falls back to `/proc/net/nf_conntrack`, diffs snapshots to emit each NEW flow once, primes on
  first poll to avoid a startup storm) and `NetFlowCollector` (UDP listener parsing NetFlow v5 +
  v9 + IPFIX, with per-exporter template caching). Both normalize to the existing
  `CapturedConnection` events and feed the shared capture queue, so every connection detector
  works on them unchanged. The event router now starts for packet capture OR flow ingest. Gated on
  `flow.conntrack_enabled` / `flow.netflow_enabled` (both default off). Tests in
  `test_flow_ingest.py`._
  - ✅ **pfSense/OPNsense filterlog.** _Shipped: `FilterlogSource` tails a filterlog file (point it at
    the firewall's syslog forwarded to the Pi), parsing the IPv4/IPv6 CSV (pass + block) into
    `CapturedConnection` events; follows rotation/truncation, starts at EOF. Gated on
    `flow.filterlog_enabled`._
- ✅ **Span/mirror-port mode.** Capture from a switch SPAN/mirror port to monitor the whole subnet,
  not just broadcast/local traffic. _Shipped: `network.mirror_mode` flag; capture is explicitly
  promiscuous (`PacketCapture(promisc=…)`, passed to the scapy sniffer) so other hosts' unicast is
  seen, with a clear startup log. Switch setup documented in `docs/configuration_guide.md`. Tests in
  `test_capture_modes.py`._
- ✅ **DHCP + device-identity source of truth.** Name devices from the DHCP server's leases rather
  than guessing. _Shipped: `inventory/dhcp_leases.py` (dnsmasq + ISC parsers, caching
  `DHCPLeaseSource`); `DeviceTracker` consults it first and falls back to reverse DNS, recording
  `extra.identity_source`; refreshed each poll. Gated on `monitoring.dhcp_leases_enabled`. Tests in
  `test_dhcp_leases.py`._

---

## Phase 4 — Smarter detection
- **Per-host behavioral profiles** beyond connection counts: typical destinations, ports, bytes,
  active hours, peer set. Alert on deviation from the host's *own* learned profile.
  - ✅ **Active-hours profile.** _Shipped: `detectors/active_hours_detector.py` — learns each host's
    normal hours-of-activity (persisted in `host_activity_hours`, schema v5) and flags the first
    activity in a never-seen hour, once the host's profile is established (`active_hours_min_known`)
    and past the learning phase. Tests in `test_active_hours.py`._ Remaining profile dimensions
    (typical ports/bytes/peer-set) are follow-ups.
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
