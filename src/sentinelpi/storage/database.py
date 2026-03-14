"""
storage/database.py - SQLite persistence layer for SentinelPi.

Design principles:
- One connection per thread (thread-local) to avoid SQLite concurrency issues.
- WAL journal mode for better concurrent read/write performance.
- Schema migrations handled by version table.
- Retention policy enforced by periodic cleanup.

All writes are synchronous — on a Pi 4 with an SSD/fast SD card this is fine
for the volumes we expect (tens of events per minute at most).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Generator

from ..models import Alert, AlertStatus, Device, Severity, AlertCategory

logger = logging.getLogger(__name__)

# Current schema version — bump when adding migrations
SCHEMA_VERSION = 3

# Thread-local storage for per-thread SQLite connections
_thread_local = threading.local()


class Database:
    """
    SQLite-backed store for alerts, devices, baseline metrics, and DNS observations.

    Thread safety: each thread gets its own connection via thread-local storage.
    The database file itself is shared via WAL mode.
    """

    def __init__(self, db_path: str, retention_days: int = 30) -> None:
        self.db_path = db_path
        self.retention_days = retention_days
        # Ensure parent directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # Initialize schema on the calling thread
        with self._conn() as conn:
            self._ensure_schema(conn)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        """Return (or create) the thread-local SQLite connection."""
        conn = getattr(_thread_local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,  # we manage thread safety ourselves
                timeout=10.0,
                isolation_level=None,     # autocommit; we use explicit transactions
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA cache_size=-4096")  # 4 MB cache
            _thread_local.conn = conn
            logger.debug("Opened new SQLite connection on thread %s", threading.current_thread().name)
        return conn

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager that provides a connection and commits/rolls back."""
        conn = self._get_connection()
        conn.execute("BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        """Close the thread-local connection if open."""
        conn = getattr(_thread_local, "conn", None)
        if conn:
            conn.close()
            _thread_local.conn = None

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create tables and run any pending migrations."""
        # Version table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """)
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        current_version = row["version"] if row else 0

        if current_version < 1:
            self._migrate_v1(conn)
        if current_version < 2:
            self._migrate_v2(conn)
        if current_version < 3:
            self._migrate_v3(conn)

        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))

    def _migrate_v1(self, conn: sqlite3.Connection) -> None:
        """Initial schema: alerts and devices."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id      TEXT PRIMARY KEY,
                timestamp     TEXT NOT NULL,
                severity      TEXT NOT NULL,
                category      TEXT NOT NULL,
                affected_host TEXT NOT NULL,
                affected_mac  TEXT,
                related_host  TEXT,
                title         TEXT NOT NULL,
                description   TEXT,
                recommended_action TEXT,
                confidence    REAL,
                confidence_rationale TEXT,
                dedup_key     TEXT,
                status        TEXT DEFAULT 'new',
                extra         TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key ON alerts(dedup_key);
            CREATE INDEX IF NOT EXISTS idx_alerts_host      ON alerts(affected_host);

            CREATE TABLE IF NOT EXISTS devices (
                ip             TEXT NOT NULL,
                mac            TEXT NOT NULL,
                first_seen     TEXT NOT NULL,
                last_seen      TEXT NOT NULL,
                hostname       TEXT,
                vendor         TEXT,
                is_trusted     INTEGER DEFAULT 0,
                is_gateway     INTEGER DEFAULT 0,
                alert_count    INTEGER DEFAULT 0,
                suspicion_score REAL DEFAULT 0,
                extra          TEXT,
                PRIMARY KEY (ip, mac)
            );

            CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
            CREATE INDEX IF NOT EXISTS idx_devices_ip  ON devices(ip);
        """)
        logger.info("Database migration v1 applied.")

    def _migrate_v2(self, conn: sqlite3.Connection) -> None:
        """Baseline metrics tables."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS baseline_hourly (
                ip          TEXT NOT NULL,
                hour_of_day INTEGER NOT NULL,
                day_of_week INTEGER NOT NULL,
                avg_conn    REAL DEFAULT 0,
                stddev_conn REAL DEFAULT 0,
                sample_count INTEGER DEFAULT 0,
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (ip, hour_of_day, day_of_week)
            );

            CREATE TABLE IF NOT EXISTS baseline_destinations (
                src_ip  TEXT NOT NULL,
                dst_ip  TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                PRIMARY KEY (src_ip, dst_ip, dst_port, protocol)
            );

            CREATE TABLE IF NOT EXISTS baseline_dns (
                domain      TEXT PRIMARY KEY,
                query_count INTEGER DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL
            );
        """)
        logger.info("Database migration v2 applied.")

    def _migrate_v3(self, conn: sqlite3.Connection) -> None:
        """DNS observations and connection events."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS dns_observations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                src_ip      TEXT NOT NULL,
                query_name  TEXT NOT NULL,
                query_type  TEXT,
                response_ip TEXT,
                is_nxdomain INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_dns_timestamp  ON dns_observations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_src_ip     ON dns_observations(src_ip);
            CREATE INDEX IF NOT EXISTS idx_dns_query_name ON dns_observations(query_name);

            CREATE TABLE IF NOT EXISTS connection_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                src_ip      TEXT NOT NULL,
                src_port    INTEGER,
                dst_ip      TEXT NOT NULL,
                dst_port    INTEGER,
                protocol    TEXT,
                state       TEXT,
                process_name TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connection_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_conn_src_ip    ON connection_events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_conn_dst_ip    ON connection_events(dst_ip);

            CREATE TABLE IF NOT EXISTS file_hashes (
                path        TEXT PRIMARY KEY,
                sha256      TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
        """)
        logger.info("Database migration v3 applied.")

    # ------------------------------------------------------------------
    # Alert CRUD
    # ------------------------------------------------------------------

    def save_alert(self, alert: Alert) -> None:
        """Persist an alert to the database."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts
                  (alert_id, timestamp, severity, category, affected_host,
                   affected_mac, related_host, title, description,
                   recommended_action, confidence, confidence_rationale,
                   dedup_key, status, extra)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.severity.value,
                    alert.category.value,
                    alert.affected_host,
                    alert.affected_mac,
                    alert.related_host,
                    alert.title,
                    alert.description,
                    alert.recommended_action,
                    alert.confidence,
                    alert.confidence_rationale,
                    alert.dedup_key,
                    alert.status.value,
                    json.dumps(alert.extra),
                ),
            )

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve a single alert by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return _row_to_alert(row) if row else None

    def get_recent_alerts(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        severity: Optional[Severity] = None,
        status: Optional[AlertStatus] = None,
        host: Optional[str] = None,
    ) -> List[Alert]:
        """Fetch recent alerts with optional filters."""
        conn = self._get_connection()
        clauses = []
        params: List[Any] = []

        if since:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.value)
        if status:
            clauses.append("status = ?")
            params.append(status.value)
        if host:
            clauses.append("affected_host = ?")
            params.append(host)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
        return [_row_to_alert(r) for r in rows]

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None:
        """Change alert lifecycle status."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE alerts SET status = ? WHERE alert_id = ?",
                (status.value, alert_id),
            )

    def get_recent_dedup_keys(self, since: datetime) -> set:
        """Return set of dedup_keys for alerts newer than `since` (for suppression)."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT DISTINCT dedup_key FROM alerts WHERE timestamp >= ? AND status != ?",
            (since.isoformat(), AlertStatus.MUTED.value),
        ).fetchall()
        return {r["dedup_key"] for r in rows}

    # ------------------------------------------------------------------
    # Device CRUD
    # ------------------------------------------------------------------

    def upsert_device(self, device: Device) -> None:
        """Insert or update a device record."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO devices
                  (ip, mac, first_seen, last_seen, hostname, vendor,
                   is_trusted, is_gateway, alert_count, suspicion_score, extra)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip, mac) DO UPDATE SET
                  last_seen      = excluded.last_seen,
                  hostname       = excluded.hostname,
                  vendor         = excluded.vendor,
                  is_trusted     = excluded.is_trusted,
                  is_gateway     = excluded.is_gateway,
                  alert_count    = excluded.alert_count,
                  suspicion_score = excluded.suspicion_score,
                  extra          = excluded.extra
                """,
                (
                    device.ip,
                    device.mac,
                    device.first_seen.isoformat(),
                    device.last_seen.isoformat(),
                    device.hostname,
                    device.vendor,
                    int(device.is_trusted),
                    int(device.is_gateway),
                    device.alert_count,
                    device.suspicion_score,
                    json.dumps(device.extra),
                ),
            )

    def get_all_devices(self) -> List[Device]:
        """Return all known devices."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [_row_to_device(r) for r in rows]

    def get_device_by_ip(self, ip: str) -> Optional[Device]:
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
        return _row_to_device(row) if row else None

    def get_device_by_mac(self, mac: str) -> Optional[Device]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM devices WHERE mac = ? ORDER BY last_seen DESC LIMIT 1", (mac.lower(),)
        ).fetchone()
        return _row_to_device(row) if row else None

    def get_all_known_macs(self) -> Dict[str, str]:
        """Return {mac: ip} for all known devices."""
        conn = self._get_connection()
        rows = conn.execute("SELECT mac, ip FROM devices").fetchall()
        return {r["mac"]: r["ip"] for r in rows}

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    def update_hourly_baseline(
        self,
        ip: str,
        hour_of_day: int,
        day_of_week: int,
        new_conn_count: float,
    ) -> None:
        """Incrementally update rolling average and stddev for hourly connection counts."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT avg_conn, stddev_conn, sample_count FROM baseline_hourly WHERE ip=? AND hour_of_day=? AND day_of_week=?",
            (ip, hour_of_day, day_of_week),
        ).fetchone()

        if row is None:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO baseline_hourly VALUES (?,?,?,?,?,?,?)",
                    (ip, hour_of_day, day_of_week, new_conn_count, 0.0, 1, datetime.utcnow().isoformat()),
                )
        else:
            # Welford online algorithm for running mean and variance
            n = row["sample_count"] + 1
            old_avg = row["avg_conn"]
            new_avg = old_avg + (new_conn_count - old_avg) / n
            # Variance update (simplified; store as approximate stddev)
            old_var = row["stddev_conn"] ** 2
            new_var = old_var + ((new_conn_count - old_avg) * (new_conn_count - new_avg) - old_var) / n
            new_stddev = max(0.0, new_var) ** 0.5
            with self._conn() as c:
                c.execute(
                    """UPDATE baseline_hourly
                       SET avg_conn=?, stddev_conn=?, sample_count=?, updated_at=?
                       WHERE ip=? AND hour_of_day=? AND day_of_week=?""",
                    (new_avg, new_stddev, n, datetime.utcnow().isoformat(), ip, hour_of_day, day_of_week),
                )

    def get_hourly_baseline(self, ip: str, hour_of_day: int, day_of_week: int) -> Optional[Dict]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM baseline_hourly WHERE ip=? AND hour_of_day=? AND day_of_week=?",
            (ip, hour_of_day, day_of_week),
        ).fetchone()
        return dict(row) if row else None

    def record_destination(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> None:
        """Record or increment a known (src→dst:port) destination."""
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO baseline_destinations (src_ip, dst_ip, dst_port, protocol, hit_count, first_seen, last_seen)
                VALUES (?,?,?,?,1,?,?)
                ON CONFLICT(src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
                  hit_count = hit_count + 1,
                  last_seen = excluded.last_seen
                """,
                (src_ip, dst_ip, dst_port, protocol, now, now),
            )

    def is_known_destination(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT hit_count FROM baseline_destinations WHERE src_ip=? AND dst_ip=? AND dst_port=? AND protocol=?",
            (src_ip, dst_ip, dst_port, protocol),
        ).fetchone()
        return row is not None and row["hit_count"] > 0

    def record_dns_domain(self, domain: str) -> None:
        """Record a DNS domain as observed."""
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO baseline_dns (domain, query_count, first_seen, last_seen)
                VALUES (?,1,?,?)
                ON CONFLICT(domain) DO UPDATE SET
                  query_count = query_count + 1,
                  last_seen = excluded.last_seen
                """,
                (domain, now, now),
            )

    def is_known_dns_domain(self, domain: str) -> bool:
        conn = self._get_connection()
        row = conn.execute("SELECT query_count FROM baseline_dns WHERE domain=?", (domain,)).fetchone()
        return row is not None

    def get_top_dns_domains(self, limit: int = 20) -> List[Dict]:
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT domain, query_count, first_seen, last_seen FROM baseline_dns ORDER BY query_count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # DNS observations
    # ------------------------------------------------------------------

    def save_dns_observation(self, timestamp: datetime, src_ip: str, query_name: str,
                              query_type: str, response_ip: str = "", is_nxdomain: bool = False) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO dns_observations (timestamp, src_ip, query_name, query_type, response_ip, is_nxdomain) VALUES (?,?,?,?,?,?)",
                (timestamp.isoformat(), src_ip, query_name, query_type, response_ip, int(is_nxdomain)),
            )

    def get_dns_observations(self, since: datetime, src_ip: Optional[str] = None) -> List[Dict]:
        conn = self._get_connection()
        if src_ip:
            rows = conn.execute(
                "SELECT * FROM dns_observations WHERE timestamp >= ? AND src_ip = ? ORDER BY timestamp DESC",
                (since.isoformat(), src_ip),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM dns_observations WHERE timestamp >= ? ORDER BY timestamp DESC",
                (since.isoformat(),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # File integrity
    # ------------------------------------------------------------------

    def get_file_hash(self, path: str) -> Optional[str]:
        conn = self._get_connection()
        row = conn.execute("SELECT sha256 FROM file_hashes WHERE path=?", (path,)).fetchone()
        return row["sha256"] if row else None

    def upsert_file_hash(self, path: str, sha256: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_hashes (path, sha256, recorded_at) VALUES (?,?,?)",
                (path, sha256, datetime.utcnow().isoformat()),
            )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def purge_old_records(self) -> None:
        """Delete records older than retention_days. Called periodically."""
        cutoff = (datetime.utcnow() - timedelta(days=self.retention_days)).isoformat()
        with self._conn() as conn:
            r1 = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            r2 = conn.execute("DELETE FROM dns_observations WHERE timestamp < ?", (cutoff,))
            r3 = conn.execute("DELETE FROM connection_events WHERE timestamp < ?", (cutoff,))
            logger.info(
                "Purged old records: %d alerts, %d DNS obs, %d connections",
                r1.rowcount, r2.rowcount, r3.rowcount,
            )
        self._get_connection().execute("PRAGMA wal_checkpoint(PASSIVE)")

    def vacuum(self) -> None:
        """Reclaim disk space. Run periodically (not in a transaction)."""
        conn = self._get_connection()
        conn.execute("VACUUM")
        logger.info("SQLite VACUUM complete.")

    def get_alert_counts_by_severity(self, since: datetime) -> Dict[str, int]:
        """Used for dashboard summary."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts WHERE timestamp >= ? GROUP BY severity",
            (since.isoformat(),),
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_top_suspicious_hosts(self, limit: int = 10) -> List[Dict]:
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY suspicion_score DESC, alert_count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------
# Row conversion helpers
# ------------------------------------------------------------------

def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        severity=Severity(row["severity"]),
        category=AlertCategory(row["category"]),
        affected_host=row["affected_host"] or "",
        affected_mac=row["affected_mac"] or "",
        related_host=row["related_host"] or "",
        title=row["title"] or "",
        description=row["description"] or "",
        recommended_action=row["recommended_action"] or "",
        confidence=float(row["confidence"] or 1.0),
        confidence_rationale=row["confidence_rationale"] or "",
        dedup_key=row["dedup_key"] or "",
        status=AlertStatus(row["status"]),
        extra=json.loads(row["extra"] or "{}"),
    )


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        ip=row["ip"],
        mac=row["mac"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        hostname=row["hostname"] or "",
        vendor=row["vendor"] or "",
        is_trusted=bool(row["is_trusted"]),
        is_gateway=bool(row["is_gateway"]),
        alert_count=row["alert_count"] or 0,
        suspicion_score=float(row["suspicion_score"] or 0.0),
        extra=json.loads(row["extra"] or "{}"),
    )
