# SentinelPi Development Roadmap

_Created: 2026-06-10. Scope: full repository review of `src/`, `tests/`, `config/`,
`.github/`, and operator docs._

## Review Summary

SentinelPi has a solid structure and a broad regression suite: 281 tests passed during this
review. The highest-value work now is operational correctness for long-running deployments:
make persisted baselines fully survive restarts, make `--check-config` actually reject invalid
operator input, and finish graceful lifecycle handling for services that already have stop APIs.

Severity legend: Critical means detection or shutdown correctness can be wrong in normal use.
High means likely operator confusion, noisy detection, or degraded reliability. Medium means
important hardening or usability work.

## Findings To Fix

Status update 2026-06-10: Phase 1 items 1, 2, 3, 5, and 6 are complete with regression tests.
Phase 2 items 4 and 7 are also complete. The watchdog slice is shipped: dead worker threads,
stale packet/flow event streams, threat-intel refresh failures/staleness, high capture-queue usage,
low disk space, and `/api/status` health exposure. CI now runs compile checks, ruff, and
coverage-enabled pytest. The first incident-UX slice is shipped: ordered single-host
new-device -> port-scan -> lateral-movement chains now raise INCIDENT alerts with timelines, and
the dashboard now renders those timelines inline. The ntfy actionable notifier (Approve/Reject for
pending responses) is also shipped, mypy now passes clean and gates CI, `--check` exercises
configured notifiers/responders in preflight mode, and per-host destination-port/internal-peer
profile dimensions are shipped. Dashboard live updates are shipped via server-sent events with a
polling fallback. Host drill-down pages are shipped with device identity, recent alerts, known
destinations, DNS history, host profile values, response-action history, and dashboard links from
host IPs. Twilio SMS alerts are also shipped as a notification-channel expansion. SIEM-friendly
export (syslog ECS/CEF via `SyslogNotifier`) is shipped, as is database backup/restore via
`--backup`/`--restore`. All four phases are complete (2026-06-17): the remaining Phase 3
detection-quality work (byte-range/protocol-mix host profiles, adaptive per-host thresholds, and
alert explainability across every detector) shipped, along with the last loose ends — daily-report
health summaries, a packaging smoke test in CI, and the config-doctor environment probe. The
"Proposed New Features" backlog is also fully shipped (host suspicion-trend charts, open-port
rollups, dashboard health badges, the incident-timeline narrative, and OpenTelemetry/OTLP export).
No tracked work remains open.

### Critical

1. **Persisted destination and connection baselines are not reloaded on startup.** **Status: fixed.**

   `BaselineEngine._load_from_db()` only hydrates DNS domains from SQLite even though the database
   also persists `baseline_destinations` and `baseline_hourly`. After a restart,
   `_known_destinations` and `_conn_stats` are empty, so new-destination detection and connection
   spike detection behave as if the host has no history until fresh samples rebuild memory.

   Evidence: `src/sentinelpi/baseline/engine.py:103-137`, `src/sentinelpi/baseline/engine.py:172-188`,
   and `src/sentinelpi/storage/database.py:534-563`.

   Plan:
   - Add database read helpers for destination baselines and hourly baseline rows.
   - Rehydrate `_known_destinations` at startup.
   - Rehydrate `_conn_stats` or introduce a serializable `RunningStats` state that includes `M2`.
   - Add restart regression tests proving known destinations and connection spike baselines survive
     a new `BaselineEngine` instance.

2. **`--check-config` reports invalid configs as OK.** **Status: fixed.**

   The loader merges YAML values directly into dataclasses and `--check-config` prints success
   without validating CIDRs, dashboard port types/ranges, enum values, severities, or path-related
   invariants. A manual check with `subnets: ["not-a-cidr"]`, `dashboard.port: nope`, and
   `sensitivity_profile: bananas` still printed `Configuration OK`.

   Evidence: `src/sentinelpi/config/manager.py:356-374`, `src/sentinelpi/config/manager.py:410-435`,
   and `src/sentinelpi/main.py:715-723`.

   Plan:
   - Add a `validate_config(config) -> list[ConfigIssue]` function with typed errors.
   - Validate IPs/CIDRs, ports, booleans/lists that come from YAML, severity/category strings,
     sensitivity profile, DHCP lease format, cluster role, responder backends, and file paths that
     must exist only when the feature is enabled.
   - Make `--check-config` exit non-zero and print actionable errors.
   - Add tests for invalid CIDR, invalid port type, invalid severity, and invalid enum values.

### High

3. **The dashboard server is not stopped during application shutdown.** **Status: fixed.**

   `DashboardServer.stop()` closes the waitress server and joins its thread, but `SentinelPi._shutdown()`
   never calls it. This bypasses the graceful shutdown path already implemented for production serving.

   Evidence: `src/sentinelpi/main.py:650-672` and `src/sentinelpi/ui/dashboard.py:575-586`.

   Plan:
   - Call `self._dashboard_server.stop()` before joining background threads.
   - Add a lifecycle test that injects a dashboard server double and verifies stop is called.

4. **Async notifier worker threads cannot be stopped cleanly.** **Status: fixed.**

   Email, webhook, and forward notifiers start daemon threads whose worker loops are `while True`.
   There is no stop event, drain, or join hook, so shutdown can drop queued notifications and tests
   cannot assert clean notifier lifecycle behavior.

   Evidence: `src/sentinelpi/alerts/notifiers.py:151-179`, `src/sentinelpi/alerts/notifiers.py:237-265`,
   and `src/sentinelpi/alerts/notifiers.py:300-329`.

   Plan:
   - Add optional `close()` methods to queue-backed notifiers.
   - Let `AlertManager` close registered notifiers during shutdown.
   - Use a sentinel item or stop event and drain bounded queues before exit.
   - Add tests for queue drain and no live worker thread after close.

5. **Email timestamps still append `Z` to timezone-aware ISO strings.** **Status: fixed.**

   The clock abstraction intentionally emits aware timestamps with `+00:00`; email formatting still
   builds `2026-...+00:00Z`, which is not the format the clock docs and tests require elsewhere.

   Evidence: `src/sentinelpi/utils/clock.py:14-16` and `src/sentinelpi/alerts/notifiers.py:184-190`.

   Plan:
   - Remove the appended `Z` in `EmailNotifier`.
   - Add a notifier formatting test for aware timestamps.

### Medium

6. **Sample config contradicts dashboard authentication behavior.** **Status: fixed.**

   Runtime code and the configuration guide correctly reject query-string tokens, but
   `config/sentinelpi.yaml` still tells users `?token=<token>` works. This can waste setup time and
   encourages a credential-leaking pattern the dashboard explicitly removed.

   Evidence: `config/sentinelpi.yaml:194-196` and `docs/configuration_guide.md:87-97`.

   Plan:
   - Update the sample config comment to browser login or `Authorization: Bearer`.
   - Keep the configuration guide as the source of truth.

7. **DNS detector cooldown state is not actively pruned.** **Status: fixed.**

   DNS deques are bounded per host, but `_last_alert` is keyed by domains and rate keys and has no
   eviction path because the detector does not implement `_poll()`. Long-lived sensors that see many
   distinct high-entropy or tunneling domains can retain cooldown keys forever.

   Evidence: `src/sentinelpi/detectors/dns_detector.py:46-53`, `src/sentinelpi/detectors/dns_detector.py:140-143`,
   `src/sentinelpi/detectors/dns_detector.py:187-190`, and `src/sentinelpi/detectors/dns_detector.py:320-322`.

   Plan:
   - Prune `_last_alert` opportunistically in `_analyze_dns()` with the base eviction helper.
   - Add a memory-bounding test specific to `DNSDetector`.

8. **CI runs tests but not lint, packaging, or coverage gates.** **Status: largely fixed.**

   The repo has ruff settings and optional coverage dependency, but CI only installs dependencies
   and runs pytest. This misses import/package regressions and low-cost style failures.

   Evidence: `.github/workflows/ci.yml:33-39` and `pyproject.toml:50-57`.

   Plan:
   - Add `python -m compileall -q src tests`.
   - Add `ruff check src tests` once ruff is enabled in dev dependencies.
   - Add `python -m build` or at least an editable install smoke test.
   - Keep coverage informational until thresholds are stable.

   Status update: compileall, ruff, mypy, and coverage XML are now wired into CI (2026-06-10 —
   mypy passes clean on all source files with stubs + `[tool.mypy]` config). ✅ Packaging smoke
   test added (2026-06-17): a `package` CI job builds the sdist+wheel and installs the wheel into a
   clean venv, then runs the console entry point and verifies the bundled dashboard templates ship
   in the wheel — which surfaced and fixed a real packaging bug (templates were absent from the
   wheel; now declared as `tool.setuptools.package-data`). CI is now fully closed out.

## Implementation Roadmap

### Phase 1: Correctness And Operator Safety

- Rehydrate persisted destination and hourly baselines on startup.
- Add real config validation and non-zero `--check-config` failures.
- Stop the dashboard server during shutdown.
- Fix email timestamp formatting.
- Update sample config comments for dashboard auth.

Status: complete as of 2026-06-10.

Exit criteria:
- New restart-persistence tests pass.
- Invalid config fixtures fail with clear messages.
- Existing suite remains green.

### Phase 2: Long-Running Daemon Hardening

- Add notifier lifecycle management and queue draining.
- Prune DNS detector cooldown state.
- Add self-monitoring alerts for dead worker threads, stalled capture, queue saturation, threat-feed
  refresh failures, and low disk space.
- Expose health status in `/api/status` and daily reports.

Status: notifier lifecycle management, DNS cooldown pruning, dead-thread alerts, stale-capture
alerts, threat-intel refresh/staleness alerts, queue-saturation alerts, low-disk alerts, and
`/api/status` watchdog exposure are complete as of 2026-06-10. Daily-report health summaries remain
open.

Exit criteria:
- Shutdown tests prove no managed service is skipped.
- Memory-bounding tests cover DNS alert state.
- Operators can see degraded state from logs and dashboard.

### Phase 3: Detection Quality And Incident UX

- ✅ Build the single-host incident engine: chain alerts such as new device -> port scan -> lateral
  movement into one incident timeline. _Shipped (2026-06-10): `IncidentCorrelator` now detects
  ordered single-host sequences under the existing `correlation.enabled` gate and stores a structured
  timeline in `incident.extra["timeline"]`. The dashboard renders that timeline inline (2026-06-10)._
- ✅ Extend per-host profiles beyond active hours: usual peer set and destination ports. _Shipped
  (2026-06-13): `HostProfileDetector` learns `dst_port` and internal `peer` values per host in
  schema-v7 `host_profile`, then flags first off-profile values once each dimension is established._
- ✅ Extend per-host profiles further with byte ranges and protocol mix. _Shipped (2026-06-17):
  `HostProfileDetector` adds two more dimensions on the same generic `host_profile` store (no schema
  change) — `protocol` (tcp/udp/icmp first-seen once established) and `byte_range` (per-flow size
  buckets, learned only when a flow source supplies byte counts, e.g. NetFlow). Both carry structured
  explainability and are gated by `host_profile_min_known_protocols` / `_byte_ranges`._
- ✅ Add adaptive thresholds per host/network so noisy networks can settle without global sensitivity
  changes. _Shipped (2026-06-17): `detectors/adaptive.py` `AdaptiveThresholds` applies a per-(signal,
  host) multiplicative backoff — a host that keeps tripping the same rate signal gets a higher
  effective bar (capped), decaying back via a sliding window as it goes quiet, and never below the
  global threshold so quiet hosts stay fully sensitive. Wired into the rate detectors (port scan,
  host sweep, DNS NXDOMAIN/DGA rate, lateral-movement fanout); fully config-driven
  (`adaptive_threshold_*`) and surfaced in the alert's explainability when in effect._
- ✅ Add explainability fields to alerts: which thresholds fired, what baseline was compared, and how
  confidence was computed. _Shipped (2026-06-16, detector coverage completed 2026-06-17):
  `models.Evidence` + `explain()` build a structured `extra["explanation"]` payload (evidence list +
  `confidence_basis`), now attached by **every** detector — port scan, host sweep, connection spike,
  new destination, new listening port, beacon, DNS (entropy/tunneling/NXDOMAIN/DGA/TLD), lateral
  movement, ARP (conflict/gateway-change/flood), auth log (brute force/new login/new user/sudo),
  geo-country, ASN, threat-intel, host-profile, active-hours, and DoH/DoT. The dashboard renders it
  as a collapsible "Why this fired" block. It rides the existing `extra` bag, so it round-trips
  through the DB, collector ingest, and ECS SIEM export with no schema change._

Status: complete as of 2026-06-17. All five tracks shipped — incident engine,
per-host profiles (ports/peers/protocol/byte-range), alert explainability across every detector, and
per-host adaptive thresholds.

Exit criteria:
- ✅ Incident alerts reduce duplicate alert noise while preserving raw alerts. _Met for the
  single-host sequence path; the dashboard renders the incident timeline inline (2026-06-10), and
  adaptive per-host thresholds (2026-06-17) further cut repeat noise from chatty hosts._
- ✅ Per-host profile tables are migrated and restart-safe for port/internal-peer dimensions
  (protocol and byte-range dimensions share the same restart-safe store).
- ✅ Dashboard can show incident timeline and contributing evidence. _Shipped (2026-06-10): the
  alerts table renders `extra["timeline"]` as a collapsible per-incident event list, plus a
  per-alert "Why this fired" explainability block (2026-06-16/17)._

### Phase 4: Usability And Integrations

- ✅ Add ntfy actionable notifications for pending responder approvals. _Shipped (2026-06-10):
  `NtfyNotifier` pushes alerts and Approve/Reject action buttons that call the dashboard response
  API; wired via `ResponderManager.set_pending_notifier`._
- ✅ Add active `--check` preflight for configured notifiers/responders. _Shipped (2026-06-11):
  network notifiers are probed, responders plan synthetic alerts without execution, and the CLI
  exits non-zero on preflight failure._
- ✅ Add Twilio SMS alerts for high-signal phone notifications. _Shipped (2026-06-14):
  `TwilioSMSNotifier` sends queued SMS via Twilio Programmable Messaging, supports Account SID/Auth
  Token or API Key credentials, validates sender/recipient settings, and participates in
  `sentinelpi --check`._
- ✅ Add dashboard live updates with server-sent events or WebSockets. _Shipped (2026-06-14):
  `/api/events` streams dashboard status ticks; the frontend uses EventSource for live
  status/alert/response refresh and falls back to polling if the stream drops._
- ✅ Add per-host drill-down pages: timeline, known destinations, DNS history, device identity, and
  responder history. _Shipped (2026-06-14): host IP links open `/devices/<ip>` pages backed by
  `/api/devices/<ip>/detail`, including recent alerts, known destinations, DNS summaries, learned
  host profile values, active hours/countries, and matching response actions._
- ✅ Add SIEM-friendly export formats: ECS-style JSON, syslog/CEF, **and** OpenTelemetry logs.
  _Shipped (2026-06-16): `SyslogNotifier` streams alerts to a syslog collector in ECS (Elastic Common
  Schema JSON) or CEF (ArcSight) payloads over UDP/TCP, with severity/facility mapping and RFC 5424
  framing. OTLP added (2026-06-17): `OTLPNotifier` POSTs alerts as OpenTelemetry OTLP/HTTP JSON logs
  to a collector's `/v1/logs` endpoint (no OTel SDK dependency). All three pure formatters live in
  `alerts/siem.py` and every channel participates in `sentinelpi --check`._
- ✅ Add backup/restore for the SQLite database and baseline state. _Shipped (2026-06-16):
  `storage/backup.py` plus `sentinelpi --backup`/`--restore` write and restore a compressed,
  self-describing snapshot of the database (all learned baselines + alerts + devices). Backups use
  SQLite's online backup API so they are consistent while the daemon runs; restore verifies
  checksum + SQLite integrity, moves the existing DB aside, clears stale WAL/SHM, and refuses a
  newer-schema snapshot unless `--force`._

Exit criteria:
- Operators can approve/reject response actions from a phone.
- ✅ Dashboard can answer "what is this host doing?" without querying raw APIs.
- ✅ Baselines and evidence can survive a Pi re-image. _Met (2026-06-16): `--backup`/`--restore`
  snapshot and restore the full database, including all learned baseline state._

## Proposed New Features

- **Operational watchdog:** ✅ shipped for queue saturation, worker death, stale capture,
  threat-intel refresh health, low disk, and `/api/status`. Daily-report health summaries shipped
  (2026-06-17): `/api/report/daily` now carries a `health` block condensing the watchdog snapshot
  (overall healthy flag plus a plain-English list of anything degraded)._
- **Host investigation view:** ✅ shipped for identity, recent alerts, active hours, countries,
  learned peers/destination ports, top DNS domains, known destinations, and recent responder
  actions. Open-port rollups shipped (2026-06-17): the host page now shows a per-port rollup
  (`get_port_rollup_for_host`) of the destination ports a host uses — service label, protocol,
  distinct destinations, and total connections, ranked by activity. Suspicion trend charts shipped
  (2026-06-17): a schema-v8 `suspicion_history` table records a point each time a host's running
  suspicion score changes (per alert), and the host page renders an inline-SVG sparkline of the
  trend (current/peak/point count). This host-investigation-view follow-up is now complete.
- **Incident timeline engine:** ✅ shipped — the single-host ordered sequence (Phase 3) and the
  cross-sensor/cross-target correlated incident both now combine related alerts into one narrative.
  As of 2026-06-17 the broad correlated incident also carries a structured `timeline`, `first_seen`,
  `affected_hosts`, and `peak_severity` (escalation high-water mark) alongside its recommended next
  action, rendered inline by the dashboard's existing incident-timeline view.
- **Actionable ntfy notifier:** ✅ shipped (2026-06-10) — `NtfyNotifier` sends pending response
  actions with approve/reject buttons that call the existing response endpoints.
- **Twilio SMS notifier:** ✅ shipped (2026-06-14) — high-signal alerts can be sent as SMS with
  preflight delivery checks and severity filtering.
- **Config doctor:** ✅ shipped — active notifier/responder preflight via `--check`, plus (2026-06-17)
  an environment probe that checks the optional files (GeoIP/ASN DBs, auth log, DHCP leases,
  file-integrity paths) and binaries (firewall/ARP/DNS-sinkhole backends, packet capture) that
  enabled features depend on, printing a `WARN` degraded-feature summary without failing the run.
- **Baseline backup/restore:** ✅ shipped (2026-06-16) — `--backup`/`--restore` snapshot and restore
  the full SQLite database (learned DNS, destinations, active hours, countries, host profiles, and
  device inventory) for hardware replacement or SD-card recovery, with checksum/integrity
  verification and online (live-safe) snapshots.
- **Dashboard live mode:** ✅ SSE status/alert/action refresh is shipped, plus (2026-06-17) a
  degraded-health badge in the status bar and a banner that lists what's wrong when the sensor is
  degraded (dead threads, stale capture, queue saturation, low disk, threat-intel refresh problems).
  The `/api/status` payload carries a compact `health` summary derived from the operational watchdog.

## Validation Performed

- `python -m pytest -q` passed: 292 tests after the Phase 1/early Phase 2 fixes.
- Manual invalid-config check proved `--check-config` currently accepts invalid values.
- Static review covered core runtime modules, tests, CI, sample config, README, and existing docs.

Note: local validation used Python 3.10.12 from the current shell, while `pyproject.toml` declares
Python 3.11+. CI already covers Python 3.11 and 3.12, so follow-up implementation should validate on
one of the supported runtimes too.
