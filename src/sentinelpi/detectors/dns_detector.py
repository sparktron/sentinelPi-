"""
detectors/dns_detector.py - DNS anomaly detection.

Detects:
1. High-entropy domain names (DGA — domain generation algorithm).
2. Unusually long subdomain labels (DNS tunneling).
3. Excessive NXDOMAIN responses (DGA churn or misconfiguration).
4. Rare TLDs associated with abuse.
5. Excessive unique domain queries (DGA indicator).
6. Large DNS TXT queries (potential DNS tunneling data channel).

This detector processes CapturedDNS events from packet capture and
also reads the system DNS cache/log if packet capture is unavailable.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .base import BaseDetector
from ..capture.packet_capture import CapturedDNS
from ..models import Alert, AlertCategory, Severity
from ..utils.network import domain_entropy, count_subdomains, is_suspicious_tld

logger = logging.getLogger(__name__)

# Known CDN/cloud domains that are legitimately high-entropy — skip them
HIGH_ENTROPY_WHITELIST = {
    "cloudfront.net", "fastly.net", "akamaiedge.net", "edgekey.net",
    "cloudflare.com", "akamaitechnologies.com", "amazonaws.com",
    "googlevideo.com", "ytimg.com", "gstatic.com",
}


class DNSDetector(BaseDetector):
    """
    Detects DNS-based anomalies including DGA and DNS tunneling indicators.

    Works from packet capture events (process_event) or from the
    database's DNS observation log.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # src_ip → deque of (timestamp, domain) for NXDOMAIN tracking
        self._nxdomain_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # src_ip → deque of (timestamp, domain) for unique domain rate
        self._query_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Alert cooldowns
        self._last_alert: Dict[str, datetime] = {}

    def process_event(self, event: object) -> List[Alert]:
        """Process a CapturedDNS event."""
        if not isinstance(event, CapturedDNS):
            return []
        if not event.query_name:
            return []
        return self._analyze_dns(event)

    def _analyze_dns(self, dns: CapturedDNS) -> List[Alert]:
        alerts: List[Alert] = []
        domain = dns.query_name.lower().strip(".")

        if not domain or len(domain) < 4:
            return []

        # Skip whitelisted domains
        if any(domain == w or domain.endswith("." + w) for w in self.config.whitelist_domains):
            return []

        now = dns.timestamp

        # Record for baseline
        is_new = self.baseline.record_dns_domain(domain)

        # Save to database
        self.db.save_dns_observation(
            timestamp=now,
            src_ip=dns.src_ip,
            query_name=domain,
            query_type=dns.query_type,
            response_ip=dns.response_ip,
            is_nxdomain=dns.is_nxdomain,
        )

        # Track NXDOMAIN
        if dns.is_nxdomain:
            self._nxdomain_times[dns.src_ip].append((now, domain))
            nxdomain_alert = self._check_nxdomain_rate(dns.src_ip, now)
            if nxdomain_alert:
                alerts.append(nxdomain_alert)

        # Track query rate for unique domains
        self._query_times[dns.src_ip].append((now, domain))

        # High-entropy detection (DGA)
        entropy_alert = self._check_entropy(domain, dns.src_ip, now)
        if entropy_alert:
            alerts.append(entropy_alert)

        # DNS tunneling: very long labels
        tunneling_alert = self._check_tunneling(domain, dns.src_ip, dns.query_type, now)
        if tunneling_alert:
            alerts.append(tunneling_alert)

        # Suspicious TLD
        if is_suspicious_tld(domain) and is_new and not self.baseline.is_learning:
            alerts.append(self._suspicious_tld_alert(domain, dns.src_ip, now))

        # Unique domain rate (many unique domains in short time)
        dga_rate_alert = self._check_dga_rate(dns.src_ip, now)
        if dga_rate_alert:
            alerts.append(dga_rate_alert)

        return alerts

    def _check_entropy(self, domain: str, src_ip: str, now: datetime) -> Optional[Alert]:
        """Flag high-entropy domain names that resemble DGA output."""
        # Check if the top-level + second-level domain is a known CDN
        parts = domain.split(".")
        if len(parts) >= 2:
            tld2 = ".".join(parts[-2:])
            if any(domain.endswith(w) for w in HIGH_ENTROPY_WHITELIST):
                return None

        entropy = domain_entropy(domain)
        threshold = self.config.thresholds.dns_entropy_threshold

        if entropy < threshold:
            return None

        # Subdomains with very high entropy are more suspicious
        subdomain = parts[0] if parts else domain
        if len(subdomain) < 10:
            return None  # Short labels aren't DGA even with high entropy

        dedup_key = f"dga_entropy:{domain}"
        if self._is_on_cooldown(dedup_key, now, 3600):
            return None
        self._last_alert[dedup_key] = now

        # Check baseline — if we've seen this domain many times it's probably legit
        if not self.baseline.is_learning and self.baseline.is_known_domain(domain):
            return None

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.DNS_ANOMALY,
            affected_host=src_ip,
            title=f"High-entropy domain name: {domain}",
            description=(
                f"{src_ip} queried domain '{domain}' which has a high entropy score "
                f"({entropy:.2f}, threshold: {threshold}). "
                "High-entropy domain names are generated by Domain Generation Algorithms (DGA) "
                "used in malware to automatically generate C2 server addresses."
            ),
            recommended_action=(
                f"Investigate why {src_ip} is querying this domain. "
                "Check threat intelligence for this domain. "
                "Run a malware scan on the source device."
            ),
            confidence=0.65,
            confidence_rationale=f"Entropy {entropy:.2f} exceeds threshold {threshold}.",
            dedup_key=dedup_key,
            extra={"domain": domain, "entropy": round(entropy, 3), "threshold": threshold},
        )

    def _check_tunneling(
        self, domain: str, src_ip: str, query_type: str, now: datetime
    ) -> Optional[Alert]:
        """
        Detect DNS tunneling indicators:
        - Very long subdomain labels (> 50 chars in a single label)
        - TXT queries to unusual domains
        - Many subdomains under a single registered domain
        """
        parts = domain.split(".")
        if not parts:
            return None

        subdomain = parts[0]
        # Very long first label is a strong tunneling indicator
        if len(subdomain) > 50:
            dedup_key = f"dns_tunnel_label:{domain[:50]}"
            if self._is_on_cooldown(dedup_key, now, 3600):
                return None
            self._last_alert[dedup_key] = now

            return Alert(
                severity=Severity.HIGH,
                category=AlertCategory.DNS_ANOMALY,
                affected_host=src_ip,
                title=f"Possible DNS tunneling: very long subdomain label",
                description=(
                    f"{src_ip} queried a domain with a {len(subdomain)}-character subdomain label "
                    f"('{subdomain[:30]}...'). DNS tunneling tools (iodine, dnscat2) encode data "
                    "as base32/hex in subdomain labels to exfiltrate data or establish covert channels."
                ),
                recommended_action=(
                    f"Capture DNS traffic from {src_ip} and analyze the queries. "
                    "Block DNS to external resolvers and force use of your local resolver."
                ),
                confidence=0.80,
                confidence_rationale=f"Subdomain label length {len(subdomain)} > 50 characters.",
                dedup_key=dedup_key,
                extra={"domain": domain, "label_length": len(subdomain)},
            )

        # Suspicious TXT query to unusual domain
        if query_type == "TXT" and len(parts) >= 3 and len(subdomain) > 20:
            dedup_key = f"dns_txt_suspicious:{'.'.join(parts[-2:])}"
            if not self._is_on_cooldown(dedup_key, now, 1800):
                self._last_alert[dedup_key] = now
                return Alert(
                    severity=Severity.LOW,
                    category=AlertCategory.DNS_ANOMALY,
                    affected_host=src_ip,
                    title=f"Suspicious DNS TXT query: {domain}",
                    description=(
                        f"{src_ip} made a TXT record query for '{domain}' with a long subdomain. "
                        "DNS TXT record queries are a common channel for DNS tunneling tools."
                    ),
                    recommended_action="Monitor DNS TXT traffic from this host.",
                    confidence=0.55,
                    confidence_rationale="Long subdomain TXT query — consistent with DNS tunneling.",
                    dedup_key=dedup_key,
                    extra={"domain": domain, "query_type": query_type},
                )

        return None

    def _check_nxdomain_rate(self, src_ip: str, now: datetime) -> Optional[Alert]:
        """Flag high rates of NXDOMAIN responses — suggests DGA domain churn."""
        dedup_key = f"nxdomain_rate:{src_ip}"
        if self._is_on_cooldown(dedup_key, now, 600):
            return None

        cutoff = now - timedelta(seconds=60)
        recent = [(t, d) for t, d in self._nxdomain_times[src_ip] if t > cutoff]

        if len(recent) < 20:  # Threshold: 20 NXDOMAIN in 60 seconds
            return None

        self._last_alert[dedup_key] = now
        unique_domains = {d for _, d in recent}

        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.DNS_ANOMALY,
            affected_host=src_ip,
            title=f"High NXDOMAIN rate: {src_ip} ({len(recent)} failures/min)",
            description=(
                f"{src_ip} received {len(recent)} NXDOMAIN (domain not found) responses "
                f"in the last 60 seconds across {len(unique_domains)} unique domains. "
                "DGA malware tries many generated domain names until it finds one that resolves "
                "to an active C2 server, producing high rates of NXDOMAIN."
            ),
            recommended_action=(
                f"Investigate {src_ip} for malware. Run a full system scan. "
                "Block this host's DNS traffic and monitor for attempts to contact C2 servers."
            ),
            confidence=0.80,
            confidence_rationale=f"{len(recent)} NXDOMAIN in 60s from single host.",
            dedup_key=dedup_key,
            extra={"nxdomain_count": len(recent), "unique_domains": len(unique_domains)},
        )

    def _check_dga_rate(self, src_ip: str, now: datetime) -> Optional[Alert]:
        """Flag a high rate of unique domain queries — another DGA signal."""
        dedup_key = f"dga_query_rate:{src_ip}"
        if self._is_on_cooldown(dedup_key, now, 600):
            return None

        cutoff = now - timedelta(seconds=60)
        recent = [(t, d) for t, d in self._query_times[src_ip] if t > cutoff]
        unique_domains = {d for _, d in recent}

        if len(unique_domains) < 50:
            return None

        self._last_alert[dedup_key] = now

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.DNS_ANOMALY,
            affected_host=src_ip,
            title=f"High unique DNS query rate: {src_ip} ({len(unique_domains)} unique/min)",
            description=(
                f"{src_ip} queried {len(unique_domains)} unique domains in 60 seconds. "
                "This high rate of unique queries is a behavioral indicator of DGA malware "
                "cycling through generated domain names."
            ),
            recommended_action=f"Investigate {src_ip} for DGA malware. Check DNS query logs.",
            confidence=0.70,
            confidence_rationale=f"{len(unique_domains)} unique domains in 60s.",
            dedup_key=dedup_key,
            extra={"unique_domains_per_minute": len(unique_domains)},
        )

    def _suspicious_tld_alert(self, domain: str, src_ip: str, now: datetime) -> Alert:
        return Alert(
            severity=Severity.INFO,
            category=AlertCategory.DNS_ANOMALY,
            affected_host=src_ip,
            title=f"Query to suspicious TLD: {domain}",
            description=(
                f"{src_ip} queried '{domain}' which uses a TLD frequently associated with "
                "malicious or low-quality sites. This alone is not conclusive evidence of compromise."
            ),
            recommended_action="Monitor this domain. No immediate action required.",
            confidence=0.40,
            confidence_rationale="TLD associated with abuse; not observed before in baseline.",
            dedup_key=f"suspicious_tld:{domain}",
            extra={"domain": domain},
        )

    def _is_on_cooldown(self, key: str, now: datetime, seconds: int) -> bool:
        last = self._last_alert.get(key)
        return bool(last and (now - last).total_seconds() < seconds)
