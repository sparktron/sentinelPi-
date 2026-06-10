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
coverage-enabled pytest. Next implementation pass should move into incident UX, then mypy
readiness.

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

8. **CI runs tests but not lint, packaging, or coverage gates.** **Status: partially fixed.**

   The repo has ruff settings and optional coverage dependency, but CI only installs dependencies
   and runs pytest. This misses import/package regressions and low-cost style failures.

   Evidence: `.github/workflows/ci.yml:33-39` and `pyproject.toml:50-57`.

   Plan:
   - Add `python -m compileall -q src tests`.
   - Add `ruff check src tests` once ruff is enabled in dev dependencies.
   - Add `python -m build` or at least an editable install smoke test.
   - Keep coverage informational until thresholds are stable.

   Status update: compileall, ruff, and coverage XML are now wired into CI. Packaging smoke tests
   and mypy readiness remain open.

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

- Build the single-host incident engine: chain alerts such as new device -> port scan -> lateral
  movement into one incident timeline.
- Extend per-host profiles beyond active hours: usual peer set, destination ports, byte ranges, and
  protocol mix.
- Add adaptive thresholds per host/network so noisy networks can settle without global sensitivity
  changes.
- Add explainability fields to alerts: which thresholds fired, what baseline was compared, and how
  confidence was computed.

Exit criteria:
- Incident alerts reduce duplicate alert noise while preserving raw alerts.
- Per-host profile tables are migrated and restart-safe.
- Dashboard can show incident timeline and contributing evidence.

### Phase 4: Usability And Integrations

- Add ntfy actionable notifications for pending responder approvals.
- Add dashboard live updates with server-sent events or WebSockets.
- Add per-host drill-down pages: timeline, known destinations, DNS history, device identity, and
  responder history.
- Add SIEM-friendly export formats: ECS-style JSON, syslog/CEF, or OpenTelemetry logs.
- Add backup/restore for the SQLite database and baseline state.

Exit criteria:
- Operators can approve/reject response actions from a phone.
- Dashboard can answer "what is this host doing?" without querying raw APIs.
- Baselines and evidence can survive a Pi re-image.

## Proposed New Features

- **Operational watchdog:** shipped for queue saturation, worker death, stale capture, threat-intel
  refresh health, low disk, and `/api/status`; daily-report health summaries remain open.
- **Host investigation view:** a single page per device with identity, suspicion trend, active hours,
  top peers, top DNS domains, open ports, and recent responder actions.
- **Incident timeline engine:** combine related alerts into one narrative with first-seen, escalation,
  affected hosts, and recommended next action.
- **Actionable ntfy notifier:** send pending response actions with approve/reject buttons that call
  existing response endpoints.
- **Config doctor:** expand `--check-config` into a preflight that validates config, probes optional
  files/binaries, tests notifier credentials in dry-run mode, and prints degraded features.
- **Baseline backup/restore:** export/import learned DNS, destinations, active hours, countries, and
  device inventory for hardware replacement or SD-card recovery.
- **Dashboard live mode:** live alert stream, stale sensor warnings, and queue/degraded-health badges.

## Validation Performed

- `python -m pytest -q` passed: 292 tests after the Phase 1/early Phase 2 fixes.
- Manual invalid-config check proved `--check-config` currently accepts invalid values.
- Static review covered core runtime modules, tests, CI, sample config, README, and existing docs.

Note: local validation used Python 3.10.12 from the current shell, while `pyproject.toml` declares
Python 3.11+. CI already covers Python 3.11 and 3.12, so follow-up implementation should validate on
one of the supported runtimes too.
