"""
utils/asn.py - Optional offline IP→ASN lookup (MaxMind GeoLite2-ASN).

Maps an IP to its Autonomous System number and the operating organization, so
detectors can reason about *who hosts* a destination — useful for flagging
traffic to hosting providers commonly abused for malware/C2/anonymization.

Mirrors utils/geo.py: uses the same maxminddb dependency, degrades gracefully
when the database is absent, caches lookups in memory, and exposes a
module-level singleton for convenience.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import maxminddb  # type: ignore
    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False

# (asn, organization). asn == 0 means "unknown".
ASNResult = Tuple[int, str]
_UNKNOWN: ASNResult = (0, "")


class ASNLookup:
    """Wrapper around the MaxMind GeoLite2-ASN database. Degrades gracefully."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._reader: Optional["maxminddb.Reader"] = None
        self._cache: dict[str, ASNResult] = {}
        self._available = False
        self._load()

    def _load(self) -> None:
        if not MAXMINDDB_AVAILABLE:
            logger.info("maxminddb library not installed — ASN lookups disabled.")
            return
        try:
            self._reader = maxminddb.open_database(self._db_path)
            self._available = True
            logger.info("ASN database loaded from %s", self._db_path)
        except (FileNotFoundError, maxminddb.errors.InvalidDatabaseError) as exc:
            logger.info("ASN database not available (%s) — ASN lookups disabled.", exc)

    @property
    def available(self) -> bool:
        return self._available

    def lookup_asn(self, ip: str) -> ASNResult:
        """Return (asn, organization) for an IP, or (0, "") if unknown."""
        if not self._available or self._reader is None:
            return _UNKNOWN
        if ip in self._cache:
            return self._cache[ip]
        try:
            record = self._reader.get(ip) or {}
            result: ASNResult = (
                int(record.get("autonomous_system_number", 0) or 0),
                record.get("autonomous_system_organization", "") or "",
            )
            if len(self._cache) >= 10_000:
                self._cache.clear()
            self._cache[ip] = result
            return result
        except Exception as exc:
            logger.debug("ASN lookup failed for %s: %s", ip, exc)
            return _UNKNOWN

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception as exc:
                logger.debug("Error closing ASN reader: %s", exc)


# Module-level singleton — set up by main.py after config load.
_instance: Optional[ASNLookup] = None


def init_asn(db_path: str) -> ASNLookup:
    global _instance
    _instance = ASNLookup(db_path)
    return _instance


def lookup_asn(ip: str) -> ASNResult:
    """Convenience function using the module-level singleton."""
    if _instance is None:
        return _UNKNOWN
    return _instance.lookup_asn(ip)
