# SentinelPi — Code Review

_Review date: 2026-06-02 · Scope: full `src/sentinelpi` tree, config, dashboard, storage._

## Overall assessment

This is a genuinely well-structured project. The separation into `capture / detectors /
baseline / alerts / inventory / storage / ui` is clean, the detector base class is a good
abstraction, the SQLite layer has real migrations and WAL mode, and there is a meaningful
test suite. The detection logic (ARP spoofing, port scans, DNS DGA/tunneling, beaconing,
lateral movement, SSH brute force) is thoughtful and well beyond a toy.

The issues below are mostly about **concurrency correctness**, a couple of **broken-by-design
helpers**, **dashboard hardening**, and **unbounded memory growth** — the things that bite a
long-running daemon rather than a script.

Severity legend: 🔴 critical · 🟠 high · 🟡 medium · ⚪ low/polish.

---

## Resolution status (Phase 0)

_Updated 2026-06-02. Full suite green at 68 tests._

| Item | Status | Notes |
|------|--------|-------|
| C1 — detector data races | ✅ Fixed | `BaseDetector` serializes `poll()`/`process_event()` via an `RLock`; subclasses override `_poll`/`_process_event`. Test: `test_detector_concurrency.py`. |
| C2 — `reverse_dns()` dead off main thread | ✅ Fixed | Replaced `SIGALRM` with a shared `ThreadPoolExecutor` + `future.result(timeout)`. Test: `test_detector_concurrency.py`. |
| H1 — unbounded dedup/suppression memory | ✅ Fixed | `AlertManager._prune_dedup` + `BaseDetector._evict_expired_times`/`_evict_idle_deques` wired into each detector `_poll`. Test: `test_memory_bounding.py`. |
| H2 — dashboard auth off by default | ✅ Fixed | Auto-generated token, header-only, `hmac.compare_digest`, random `SECRET_KEY`, fail-closed non-loopback bind. Test: `test_dashboard_auth.py`. |
| H4 — baseline variance math + atomicity | ✅ Fixed | `update_hourly_baseline` is now an atomic upsert snapshotting the authoritative in-memory `RunningStats` (single source of truth). Test: `test_baseline_persistence.py`. |
| (bug) DB init crash | ✅ Fixed | `_conn()` guarded on `conn.in_transaction` — `executescript()` in migrations implicitly commits. Test: `test_db_migrations.py`. |
| M1 — `datetime.utcnow()` naïve/deprecated; timezone-aware `clock` | ✅ Fixed | New `utils/clock.py` (aware UTC, injectable `FixedClock`). All `utcnow()` routed through `clock.now()`; dropped `isoformat() + "Z"` double-labeling. Quiet-hours intentionally stays local wall-clock. Test: `test_clock.py`. |
| H3 — Flask dev server / no clean shutdown | ✅ Fixed | `DashboardServer` prefers waitress (graceful `stop()` via `server.close()` + thread join); falls back to the dev server with a warning when waitress is absent. Test: `test_dashboard_server.py`. |
| M3 — dead no-op + fragile `_alert_manager` attr | ✅ Fixed | `build_detector_thread` takes `alert_manager` explicitly; removed the `detector.config` no-op and the dynamically-attached attribute. Test: `test_polish_fixes.py`. |
| M4 — `mark_device_suspicious` locking | ✅ Verified | Already guarded by the `DeviceTracker` `RLock`; no change needed. |
| M5 — `except Exception: pass` hides failures | ✅ Fixed | All 8 silent blocks now log at debug (incl. the reverse-DNS swallow in `_create_device`); notifier workers distinguish `queue.Empty` from real send failures (logged at warning). |
| M6 — capture interface edge cases | ✅ Fixed | `PacketCapture.start()` fails clearly on empty interfaces, prunes unknown ones, bails if none remain. Test: `test_polish_fixes.py`. |
| L1/L2 — dashboard param 500s | ✅ Fixed | `/api/alerts` validates int (`_bounded_int`, clamped) and enum params, returning 400 with guidance. Test: `test_polish_fixes.py`. |
| L4 — degraded-mode startup banner | ✅ Fixed | `SentinelPi._log_capabilities()` logs each optional feature's status and a degraded-mode warning. Test: `test_polish_fixes.py`. |
| M2 — dedup keyed on `alert.timestamp` vs ingest time | ⬜ Open (decision) | Needs a product call on event-time vs ingest-time suppression; not a clear bug today. |
| L3 — dedup cache not warmed at startup | ⬜ Open (low) | The DB slow-path in `_is_duplicate` already covers cross-restart dedup; warming is an optimization. |
| L6 — structured (JSON) logs | ⬜ Open (enhancement) | |

---

## 🔴 Critical

### C1. Detectors are mutated from two threads with no locking (data races)
`SentinelPi.__init__` builds one instance per detector. Each of `ARPDetector`,
`ConnectionDetector`, `BeaconDetector`, `LateralMovementDetector` is then registered **both**:

- in `_start_packet_capture._route_events` → calls `det.process_event(...)` on the **EventRouter** thread, and
- in `_start_polling_threads` → calls `det.poll(...)` on a **per-detector polling** thread.

Their internal state is plain `dict` / `collections.deque` (e.g. `PortScanDetector._scan_ports`,
`ARPDetector._ip_to_mac`, `_reply_times`). `_record_connection` appends to a deque while
`_check_port_scan` iterates the same deque — from a different thread. Expect intermittent
`RuntimeError: deque mutated during iteration`, `dict changed size during iteration`, and
silently corrupted counts (i.e. **missed or phantom detections** — the worst failure mode for
a security tool).

**Fix:** give each detector a `threading.Lock` and guard all state mutation/iteration, or
serialize event + poll handling through a single per-detector work queue. The lock approach is
smallest: wrap the bodies of `process_event` and `poll` in `with self._lock:`.

### C2. `reverse_dns()` can never work — `signal` only runs in the main thread
`utils/network.py::reverse_dns` installs a `SIGALRM` handler via `signal.signal()`. Python only
allows that on the **main thread**. It is called from `DeviceTracker._create_device`, which runs
on the `DeviceTracker` polling thread → raises `ValueError: signal only works in main thread`.
The caller swallows it (`except Exception: pass`), so hostnames are **always blank** and the
timeout feature is dead.

**Fix:** drop the signal hack. Use `socket.setdefaulttimeout()` around `gethostbyaddr`, or better,
do the lookup in a `concurrent.futures.ThreadPoolExecutor` with `future.result(timeout=...)`, or
use `dnspython` with an explicit timeout. This also removes a per-call global-handler swap that
is itself not thread-safe.

---

## 🟠 High

### H1. Unbounded memory growth in `AlertManager._recent_dedup`
`_recent_dedup: Dict[str, datetime]` gains a key for every distinct `dedup_key` ever fired and is
**never pruned**. On a busy network (per-domain, per-host, per-flow keys) this grows without
bound for the life of the daemon. Same pattern exists in the detector suppression dicts
(`_last_alert`, per-key cooldown maps) and `defaultdict(lambda: deque(...))` flow maps that only
shrink via `_cleanup_idle_flows` (beacon) but not elsewhere.

**Fix:** prune `_recent_dedup` opportunistically (e.g. in `_handle_alert`, drop entries older than
the max category cooldown), or replace with a TTL cache (`cachetools.TTLCache`). Audit each
detector for an eviction path; `PortScanDetector._last_alert` and the sweep/scan maps need bounding.

### H2. Dashboard ships with authentication off by default
`DashboardConfig.access_token` defaults to `""`, and `require_token` returns the handler
unguarded when the token is empty. Bound to `127.0.0.1:8888` that's tolerable, but the dashboard
exposes the entire network intelligence picture (device inventory, suspicious hosts, DNS, alerts)
and the trust/ack/mute **mutation** endpoints. Anyone who flips `host` to `0.0.0.0` (a natural
thing to do to view it from a laptop) instantly has an open, unauthenticated control panel.

**Fixes:**
- Generate a random token on first run if none is configured, and log it once.
- Refuse to bind to a non-loopback host when `access_token` is empty (fail closed).
- Constant-time compare: `hmac.compare_digest(provided, token)` instead of `!=`.
- Don't accept the token via `?token=` query param (it lands in logs/history); header only.
- Replace the hardcoded `app.config["SECRET_KEY"] = "sentinelpi-dashboard-key"` with a random
  per-process secret.

### H3. Flask dev server used as the long-lived server, with no real shutdown
`DashboardServer.start` runs `app.run(...)` (Werkzeug dev server) in a daemon thread, and
`stop()` is a no-op log line. For an always-on monitor this is the weak point: no graceful
drain, single-process, not hardened.

**Fix:** run under `waitress` (pure-Python, trivial dependency, production-grade) and keep a handle
you can actually stop, or document explicitly that the dashboard is localhost-dev-only and put it
behind a reverse proxy for anything else.

### H4. `Database.update_hourly_baseline` — wrong variance math + non-atomic read/modify/write
Two problems:
1. The "Welford" update is not Welford. It does
   `new_var = old_var + ((x-old_avg)*(x-new_avg) - old_var)/n`, which is an EWMA-style decay, not
   the running sample variance. It biases stddev and will mis-scale z-scores used for spike
   detection. Either store `M2` (sum of squared deviations) and compute `var = M2/n` like the
   in-memory `RunningStats` already does correctly, or commit to a documented EWMA and stop calling
   it Welford.
2. The `SELECT` runs on the autocommit connection and the `UPDATE`/`INSERT` runs inside a separate
   `self._conn()` transaction. Check-then-act is not atomic; concurrent writers (or a future move
   to multi-threaded baseline updates) lose updates. Do the read and write in one transaction, or
   use an `INSERT ... ON CONFLICT DO UPDATE` with the arithmetic expressed in SQL.

Note there are now **two parallel baseline implementations** — the in-memory `RunningStats`
(correct) in `BaselineEngine` and this DB one (incorrect). Decide which is authoritative; the
divergence is a latent correctness bug.

---

## 🟡 Medium

### M1. `datetime.utcnow()` used throughout — deprecated and naïve
`utcnow()` returns a naïve datetime and is deprecated in 3.12+. Mixed with `.isoformat() + "Z"`
in the dashboard, which double-labels timezone inconsistently. Standardize on
`datetime.now(timezone.utc)` and store/emit ISO-8601 with offset. This matters because alert
correlation and quiet-hours logic depend on consistent time semantics.

### M2. Quiet-hours / dedup keyed on `alert.timestamp`, not wall clock
`_is_duplicate` computes `cutoff = alert.timestamp - cooldown`. If a detector backfills events
(e.g. auth-log tailing after a restart) timestamps may be in the past, defeating dedup or quiet
hours. Confirm every alert's `timestamp` is event-time and decide whether suppression should key on
ingest-time instead.

### M3. Dead code / no-op in `build_detector_thread`
```python
detector_instance.config  # access config for alert_manager ref
```
This statement does nothing (the comment is misleading — the manager comes from the `getattr`
below). Remove it. Also, relying on a dynamically-attached `_alert_manager` attribute (set in
`SentinelPi.__init__`) is fragile; pass the alert manager into the detector constructor or into
`build_detector_thread` explicitly so the wiring is type-checked and obvious.

### M4. `AlertManager._handle_alert` holds the lock only for dedup, not for stats consistency
Counters `_total_processed/_suppressed/_fired` are updated under the lock, but the DB save,
suspicion-score update, and notifier fan-out happen outside it (correctly, for latency). Fine —
but `mark_device_suspicious` and notifier sends are themselves touching shared state; verify
`DeviceTracker.mark_device_suspicious` is internally locked (it mutates the device map from
multiple detector threads).

### M5. Broad `except Exception: pass` hides real failures
`_create_device` swallows all reverse-DNS errors (masking C2 entirely). Several detectors wrap
whole `poll()` bodies. At minimum log at `debug` with the exception so failures are diagnosable;
silent `pass` in a security tool means detectors can quietly stop working.

### M6. Packet-capture interface selection edge cases
`AsyncSniffer(iface=self.interfaces if len>1 else self.interfaces[0])` will `IndexError` if
`interfaces` is empty, and there's no validation that configured interfaces exist. Validate at
startup and emit a clear config error.

---

## ⚪ Low / polish

- **L1.** `request.args.get("limit", 100)` / `hours` are `int()`-cast with no try/except — a
  non-numeric `?limit=abc` 500s the endpoint. Validate and clamp.
- **L2.** `api_alerts` casts `Severity(severity)` / `AlertStatus(status)` directly; an invalid
  value raises `ValueError` → 500. Return 400 with a helpful message.
- **L3.** `_recent_dedup` cache is populated from DB on dedup hit but never warmed at startup, so
  the first occurrence of each key after restart always fires even if recently alerted (the DB
  slow-path covers it, but only if `get_recent_dedup_keys` is hit — confirm it's called before the
  in-memory miss returns).
- **L4.** No `requirements`/extras pinning visible for `scapy`, `flask`, `maxminddb`; all are
  imported behind `*_AVAILABLE` flags (good) but the degraded mode should surface a startup banner
  listing what's disabled.
- **L5.** Tests cover detectors and the alert manager but there's no test for the concurrency in
  C1, the dashboard auth in H2, or DB migrations. Add regression tests as you fix the above.
- **L6.** `setup_logging` + per-class `logging.getLogger` is good; consider structured (JSON) logs
  for the file handler so the dashboard/SIEM can parse them.

---

## Suggested fix order

1. **C1** (lock the detectors) and **C2** (fix reverse DNS) — correctness of detection itself.
2. **H1** (memory) and **H2** (dashboard auth) — daemon longevity and exposure.
3. **H4** (baseline math) — accuracy of the anomaly scoring everything else feeds on.
4. **H3 / M-series / L-series** — hardening and polish.

Each of C1, C2, H1, H2 is a small, self-contained PR with an accompanying test.
