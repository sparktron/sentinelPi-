"""
tests/test_db_migrations.py - Regression tests for schema setup and migrations.

These pin the fix for the executescript()-vs-explicit-transaction bug: the
migrations run via conn.executescript(), which implicitly COMMITs the open
transaction, so _conn() must not blindly COMMIT/ROLLBACK afterwards. Before the
fix, every fresh Database() raised "cannot commit - no transaction is active".

They also confirm that:
  - all expected tables are created and the version is stamped,
  - re-opening an existing DB on disk is idempotent (migrations are skipped),
  - opening with a stale version row runs the pending migrations.
"""

from __future__ import annotations

import os

import pytest

from sentinelpi.storage.database import Database, SCHEMA_VERSION

EXPECTED_TABLES = {
    "schema_version",
    "alerts",
    "devices",
    "baseline_hourly",
    "baseline_destinations",
    "baseline_dns",
    "dns_observations",
    "connection_events",
    "file_hashes",
    "host_countries",
    "host_activity_hours",
}


def _tables(db: Database) -> set:
    conn = db._get_connection()
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r["name"] for r in rows}


def _version(db: Database) -> int:
    conn = db._get_connection()
    return conn.execute("SELECT version FROM schema_version").fetchone()["version"]


def test_fresh_db_initializes_without_error(tmp_path):
    # The bug under test made this constructor raise.
    db = Database(db_path=str(tmp_path / "fresh.db"), retention_days=7)
    try:
        assert _version(db) == SCHEMA_VERSION
        assert EXPECTED_TABLES.issubset(_tables(db))
    finally:
        db.close()


def test_reopen_existing_db_is_idempotent(tmp_path):
    path = str(tmp_path / "reopen.db")
    db1 = Database(db_path=path, retention_days=7)
    db1.close()

    # Second open over the same file on disk must not re-run migrations or raise.
    db2 = Database(db_path=path, retention_days=7)
    try:
        assert _version(db2) == SCHEMA_VERSION
        assert EXPECTED_TABLES.issubset(_tables(db2))
    finally:
        db2.close()


def test_stale_version_runs_pending_migrations(tmp_path):
    path = str(tmp_path / "stale.db")
    db = Database(db_path=path, retention_days=7)
    # Simulate an older install that only reached v1.
    with db._conn() as conn:
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version VALUES (1)")
    db.close()

    # Re-opening should detect the stale version and migrate forward to current.
    db2 = Database(db_path=path, retention_days=7)
    try:
        assert _version(db2) == SCHEMA_VERSION
        assert EXPECTED_TABLES.issubset(_tables(db2))
    finally:
        db2.close()
