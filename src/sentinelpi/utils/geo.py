"""
utils/geo.py - Optional offline GeoIP country lookup.

Uses the MaxMind GeoLite2-Country database (free, requires registration).
Gracefully disabled if the database file is not present.

This is used to provide context in alerts ("unusual outbound to RU/CN/KP")
but is never used as a sole basis for blocking or high-severity alerts.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import maxminddb — optional dependency
try:
    import maxminddb  # type: ignore
    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False


class GeoIPLookup:
    """
    Wrapper around MaxMind GeoLite2 database for country lookups.

    Falls back gracefully when the database is unavailable.
    Results are cached in memory to avoid repeated disk reads for the
    same IP address (Pi workloads tend to have many repeated destinations).
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._reader: Optional["maxminddb.Reader"] = None
        self._cache: dict[str, str] = {}
        self._available = False
        self._load()

    def _load(self) -> None:
        """Attempt to open the GeoIP database."""
        if not MAXMINDDB_AVAILABLE:
            logger.info("maxminddb library not installed — GeoIP disabled.")
            return

        try:
            self._reader = maxminddb.open_database(self._db_path)
            self._available = True
            logger.info("GeoIP database loaded from %s", self._db_path)
        except (FileNotFoundError, maxminddb.errors.InvalidDatabaseError) as exc:
            logger.info("GeoIP database not available (%s) — country lookups disabled.", exc)

    @property
    def available(self) -> bool:
        return self._available

    def lookup_country(self, ip: str) -> str:
        """
        Return ISO 3166-1 alpha-2 country code for an IP, or "" if unknown.

        Results are cached; the cache is bounded to 10,000 entries.
        """
        if not self._available or self._reader is None:
            return ""

        if ip in self._cache:
            return self._cache[ip]

        try:
            record = self._reader.get(ip)
            code = ""
            if record and "country" in record:
                code = record["country"].get("iso_code", "")
            # Evict cache if it grows too large
            if len(self._cache) >= 10_000:
                self._cache.clear()
            self._cache[ip] = code
            return code
        except Exception as exc:
            logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
            return ""

    def lookup_country_name(self, ip: str) -> str:
        """Return full country name, or empty string."""
        if not self._available or self._reader is None:
            return ""
        try:
            record = self._reader.get(ip)
            if record and "country" in record:
                names = record["country"].get("names", {})
                return names.get("en", "")
        except Exception:
            pass
        return ""

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass


# Module-level singleton — set up by main.py after config load
_instance: Optional[GeoIPLookup] = None


def init_geo(db_path: str) -> GeoIPLookup:
    global _instance
    _instance = GeoIPLookup(db_path)
    return _instance


def lookup_country(ip: str) -> str:
    """Convenience function using the module-level singleton."""
    if _instance is None:
        return ""
    return _instance.lookup_country(ip)
