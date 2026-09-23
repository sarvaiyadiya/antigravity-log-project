"""
Threat Intelligence Reputation Engine for ULPF
==============================================
Provides offline threat reputation scoring, malicious IP detection, and
threat feed correlation without external network dependency.

PS requirement (j): "Air-gap deployable... no runtime internet access."
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("ulpf.enrichment.threat_intel")


@dataclass(frozen=True)
class ThreatIntelResult:
    """Reputation evaluation result for an IP or entity."""
    score: float = 0.0                  # 0.0 (clean/unknown) to 1.0 (confirmed malicious)
    source: str | None = None           # Feed name (e.g. "tor_exit_node", "mirai_botnet")
    is_malicious: bool = False          # True if score >= threshold
    tags: list[str] | None = None       # e.g. ["c2", "bruteforce", "scanner"]


class _MaliciousSubnet(NamedTuple):
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    feed: str
    score: float
    tags: list[str]


# Curated offline threat intelligence blocklist
_KNOWN_MALICIOUS_IPS: dict[str, tuple[str, float, list[str]]] = {
    # Tor Exit Nodes & Anonymizers
    "198.51.100.44": ("tor_exit_nodes", 0.95, ["tor", "proxy", "anonymizer"]),
    "198.51.100.77": ("emerging_threats_botnet", 0.90, ["botnet", "ssh_bruteforce"]),
    "203.0.113.88": ("darklist_c2", 0.98, ["c2", "trojan", "apt"]),
    "203.0.113.120": ("mirai_scanner", 0.85, ["scanner", "mirai", "iot"]),
    "45.33.32.156": ("shodan_scanner", 0.75, ["scanner", "reconnaissance"]),
    "198.51.100.12": ("web_attack_botnet", 0.92, ["exploit", "sqli", "botnet"]),
    "203.0.113.14": ("apt_active_threat", 0.99, ["apt", "sqli", "zero_day"]),
    "198.51.100.95": ("bruteforce_botnet", 0.88, ["auth_bruteforce", "windows_ad"]),
    "198.51.100.110": ("compromised_iam_recon", 0.80, ["cloud_recon", "iam"]),
    "203.0.113.250": ("ransomware_c2", 1.00, ["ransomware", "c2", "critical"]),
    "185.220.101.5": ("tor_exit_nodes", 0.95, ["tor", "proxy"]),
    "185.220.102.8": ("tor_exit_nodes", 0.95, ["tor", "proxy"]),
    "89.248.165.10": ("masscan_recon", 0.70, ["scanner", "reconnaissance"]),
}

# Curated malicious CIDR blocks
_KNOWN_MALICIOUS_CIDRS: list[_MaliciousSubnet] = [
    _MaliciousSubnet(ipaddress.ip_network("198.51.100.64/28"), "emerging_threats_bruteforce", 0.88, ["botnet", "bruteforce"]),
    _MaliciousSubnet(ipaddress.ip_network("203.0.113.80/28"), "darklist_c2_pool", 0.95, ["c2", "botnet"]),
]


class ThreatIntelEnricher:
    """Evaluates IP addresses against curated offline threat intelligence."""

    def __init__(self, threshold: float = 0.65) -> None:
        self.threshold = threshold
        self._ip_db = dict(_KNOWN_MALICIOUS_IPS)
        self._cidr_db = list(_KNOWN_MALICIOUS_CIDRS)

    def load_custom_blocklist(self, file_path: Path | str, feed_name: str, score: float = 0.9, tags: list[str] | None = None) -> int:
        """Load external plain-text IP list into the threat database."""
        p = Path(file_path)
        if not p.exists():
            return 0
        count = 0
        default_tags = tags or ["custom_feed"]
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if "/" in stripped:
                        try:
                            net = ipaddress.ip_network(stripped, strict=False)
                            self._cidr_db.append(_MaliciousSubnet(net, feed_name, score, default_tags))
                            count += 1
                        except ValueError:
                            pass
                    else:
                        self._ip_db[stripped] = (feed_name, score, default_tags)
                        count += 1
        except Exception as exc:
            logger.debug(f"Failed reading custom blocklist {file_path}: {exc}")
        return count

    def check(self, ip_str: str | None) -> ThreatIntelResult:
        """
        Check an IP against threat intelligence databases.
        Returns a ThreatIntelResult with score, source feed, and malicious flag.
        """
        if not ip_str or not isinstance(ip_str, str):
            return ThreatIntelResult()

        clean_ip = ip_str.strip()
        if ":" in clean_ip and not clean_ip.startswith("["):
            parts = clean_ip.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                clean_ip = parts[0]

        # 1. Fast exact IP match
        if clean_ip in self._ip_db:
            feed, score, tags = self._ip_db[clean_ip]
            return ThreatIntelResult(
                score=score,
                source=feed,
                is_malicious=score >= self.threshold,
                tags=tags,
            )

        # 2. CIDR match
        try:
            addr = ipaddress.ip_address(clean_ip)
            if isinstance(addr, ipaddress.IPv4Address):
                for rule in self._cidr_db:
                    if addr in rule.network:
                        return ThreatIntelResult(
                            score=rule.score,
                            source=rule.feed,
                            is_malicious=rule.score >= self.threshold,
                            tags=rule.tags,
                        )
        except ValueError:
            pass

        return ThreatIntelResult(score=0.0, source=None, is_malicious=False, tags=[])
