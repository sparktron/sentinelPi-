"""
intel/threat_feeds.py - Public threat-intelligence blocklist matching.

Loads a handful of well-known, freely-redistributable blocklists (abuse.ch
Feodo Tracker, abuse.ch URLhaus, Spamhaus DROP) and lets detectors ask
"is this destination IP / domain known-bad?". A hit is a high-confidence
signal — far stronger than the heuristic detectors — so callers promote it to
HIGH.

Design notes
------------
- **Offline-friendly.** Feeds are fetched over the network, cached to disk, and
  reloaded from cache on startup. A failed refresh keeps the last good cache;
  with no cache at all the service simply matches nothing (never raises).
- **Pure parsers.** Each feed's text-to-indicators parser is a module-level pure
  function, so it is trivially unit-testable without any network.
- **Injectable fetcher.** ThreatIntelService takes an optional ``fetcher``
  callable; tests pass a stub instead of hitting the internet.
- **Fast matching.** Exact IPs and domains are O(1) set/dict lookups; only CIDR
  blocklists require a scan, and there are few of those.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Indicator:
    """A single known-bad indicator and where it came from."""
    value: str       # the IP, CIDR, or domain
    kind: str        # "ip" | "cidr" | "domain"
    source: str      # feed name, e.g. "feodo"
    category: str    # short human label, e.g. "botnet_c2"


# --------------------------------------------------------------------------- #
# Feed parsers (pure: raw text -> list of indicator values)
# --------------------------------------------------------------------------- #

def _parse_line_list(text: str) -> List[str]:
    """Generic 'one value per line, # comments' parser (e.g. Feodo IP list)."""
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.split()[0])
    return out


def _parse_spamhaus_drop(text: str) -> List[str]:
    """
    Spamhaus DROP: 'CIDR ; SBLxxxxx' per line, ';' comments.

    Example: '1.10.16.0/20 ; SBL256894'
    """
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        token = line.split(";")[0].strip()
        if token:
            out.append(token)
    return out


def _parse_urlhaus_hosts(text: str) -> List[str]:
    """
    URLhaus text feed: one URL per line, '#' comments. Extract the host.

    A host that is itself an IP is returned as-is (classified as an IP at load
    time); otherwise it is a domain.
    """
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _host_from_url(line)
        if host:
            out.append(host)
    return out


def _host_from_url(url: str) -> str:
    """Extract the host[:port] from a URL line, lowercased, without port."""
    rest = url.split("://", 1)[-1]           # strip scheme
    rest = rest.split("/", 1)[0]             # strip path
    rest = rest.split("@", 1)[-1]            # strip userinfo
    host = rest.split(":", 1)[0]             # strip port
    return host.strip().lower()


@dataclass(frozen=True)
class FeedDef:
    name: str
    url: str
    category: str
    parser: Callable[[str], List[str]]
    # "ip" feeds are pure IPs, "cidr" pure networks, "host" a mix resolved per value.
    kind: str


# Catalog of supported feeds. All are free to redistribute for defensive use.
FEEDS: Dict[str, FeedDef] = {
    "feodo": FeedDef(
        name="feodo",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        category="botnet_c2",
        parser=_parse_line_list,
        kind="ip",
    ),
    "spamhaus_drop": FeedDef(
        name="spamhaus_drop",
        url="https://www.spamhaus.org/drop/drop.txt",
        category="hijacked_netblock",
        parser=_parse_spamhaus_drop,
        kind="cidr",
    ),
    "urlhaus": FeedDef(
        name="urlhaus",
        url="https://urlhaus.abuse.ch/downloads/text/",
        category="malware_distribution",
        parser=_parse_urlhaus_hosts,
        kind="host",
    ),
}


def _classify_host(value: str) -> str:
    """Return 'ip' if value parses as an IP address, else 'domain'."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"


class ThreatIntelService:
    """
    Holds loaded indicators and answers match_ip / match_domain queries.

    Thread-safety: refresh()/load() rebuild fresh structures and swap them in
    atomically (a single attribute assignment), so concurrent readers calling
    match_* never see a half-built index. Readers take no lock.
    """

    def __init__(
        self,
        config,
        fetcher: Optional[Callable[[str, float], str]] = None,
    ) -> None:
        self._config = config
        self._fetcher = fetcher or _http_fetch
        self._cache_dir = Path(config.cache_dir)

        # Match structures (swapped atomically on (re)load).
        self._ips: Dict[str, Indicator] = {}
        self._domains: Dict[str, Indicator] = {}
        self._cidrs: List[Tuple[ipaddress._BaseNetwork, Indicator]] = []

    # ------------------------------------------------------------------ query
    @property
    def indicator_count(self) -> int:
        return len(self._ips) + len(self._domains) + len(self._cidrs)

    def match_ip(self, ip: str) -> Optional[Indicator]:
        """Return the matching indicator for an IP, or None."""
        hit = self._ips.get(ip)
        if hit is not None:
            return hit
        if not self._cidrs:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, indicator in self._cidrs:
            if addr in network:
                return indicator
        return None

    def match_domain(self, domain: str) -> Optional[Indicator]:
        """
        Return the matching indicator for a domain or any of its parents.

        e.g. 'a.b.evil.com' matches an indicator for 'evil.com'.
        """
        if not domain or not self._domains:
            return None
        labels = domain.strip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            hit = self._domains.get(candidate)
            if hit is not None:
                return hit
        return None

    # ------------------------------------------------------------- load/refresh
    def load(self) -> None:
        """(Re)build match structures from whatever is cached on disk."""
        ips: Dict[str, Indicator] = {}
        domains: Dict[str, Indicator] = {}
        cidrs: List[Tuple[ipaddress._BaseNetwork, Indicator]] = []

        for feed_name in self._config.feeds:
            feed = FEEDS.get(feed_name)
            if feed is None:
                logger.warning("Unknown threat-intel feed '%s' — skipping.", feed_name)
                continue
            text = self._read_cache(feed)
            if text is None:
                continue
            self._index_feed(feed, text, ips, domains, cidrs)

        # Atomic swap.
        self._ips, self._domains, self._cidrs = ips, domains, cidrs
        logger.info(
            "Threat intel loaded: %d IPs, %d domains, %d CIDR blocks.",
            len(ips), len(domains), len(cidrs),
        )

    def refresh(self) -> bool:
        """
        Fetch every configured feed, cache it, then reload.

        Returns True if at least one feed was fetched successfully. A feed that
        fails to fetch keeps its previous cache (if any).
        """
        any_ok = False
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        for feed_name in self._config.feeds:
            feed = FEEDS.get(feed_name)
            if feed is None:
                logger.warning("Unknown threat-intel feed '%s' — skipping.", feed_name)
                continue
            try:
                text = self._fetcher(feed.url, float(self._config.fetch_timeout_seconds))
            except Exception as exc:
                logger.warning("Threat feed '%s' fetch failed (%s) — keeping cache.", feed_name, exc)
                continue
            try:
                self._cache_path(feed).write_text(text, encoding="utf-8")
                any_ok = True
            except OSError as exc:
                logger.warning("Could not write cache for feed '%s': %s", feed_name, exc)
        self.load()
        return any_ok

    # --------------------------------------------------------------- internals
    def _index_feed(self, feed, text, ips, domains, cidrs) -> None:
        """Parse one feed's text and add its indicators to the given structures."""
        for value in feed.parser(text):
            kind = feed.kind
            if kind == "host":
                kind = _classify_host(value)
            indicator = Indicator(value=value, kind=kind, source=feed.name, category=feed.category)
            if kind == "ip":
                ips[value] = indicator
            elif kind == "domain":
                domains[value.lower()] = indicator
            elif kind == "cidr":
                try:
                    cidrs.append((ipaddress.ip_network(value, strict=False), indicator))
                except ValueError:
                    logger.debug("Skipping malformed CIDR '%s' from %s", value, feed.name)

    def _cache_path(self, feed) -> Path:
        return self._cache_dir / f"{feed.name}.txt"

    def _read_cache(self, feed) -> Optional[str]:
        path = self._cache_path(feed)
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.debug("No cache yet for feed '%s' (%s)", feed.name, path)
            return None
        except OSError as exc:
            logger.warning("Could not read cache for feed '%s': %s", feed.name, exc)
            return None


def _http_fetch(url: str, timeout: float) -> str:
    """Default fetcher — a thin requests.get wrapper (imported lazily)."""
    import requests

    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "SentinelPi/threatintel"})
    resp.raise_for_status()
    return resp.text
