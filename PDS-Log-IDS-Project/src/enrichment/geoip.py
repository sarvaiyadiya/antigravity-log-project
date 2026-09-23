"""
Offline GeoIP & ASN Resolver for ULPF
=====================================
Provides offline, high-speed IP geolocation, ASN resolution, and private
network classification without requiring external network access (air-gapped ready).

PS requirement (j): "Air-gap deployable... no runtime internet access."
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import NamedTuple

logger = logging.getLogger("ulpf.enrichment.geoip")


@dataclass(frozen=True)
class GeoResult:
    """Geographic and autonomous system metadata for an IP address."""
    country: str | None = None          # ISO 3166-1 alpha-2 ("US", "IN", "DE", etc.)
    city: str | None = None             # City or region name
    asn: str | None = None              # Autonomous System ("AS15169 Google LLC")
    is_private: bool = False            # True for RFC 1918 / Loopback / Link-local


class _CidrRule(NamedTuple):
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    country: str
    city: str
    asn: str


# Curated offline CIDR routing table for major global networks, clouds, and CDNs
_OFFLINE_CIDR_TABLE: list[_CidrRule] = [
    # ── DNS & Core Anycast ──────────────────────────────────────────────────
    _CidrRule(ipaddress.ip_network("8.8.8.0/24"), "US", "Mountain View", "AS15169 Google LLC"),
    _CidrRule(ipaddress.ip_network("8.8.4.0/24"), "US", "Mountain View", "AS15169 Google LLC"),
    _CidrRule(ipaddress.ip_network("1.1.1.0/24"), "US", "San Francisco", "AS13335 Cloudflare Inc"),
    _CidrRule(ipaddress.ip_network("1.0.0.0/24"), "US", "San Francisco", "AS13335 Cloudflare Inc"),
    _CidrRule(ipaddress.ip_network("9.9.9.0/24"), "CH", "Zurich", "AS19281 Quad9"),
    _CidrRule(ipaddress.ip_network("208.67.222.0/24"), "US", "San Francisco", "AS36692 Cisco OpenDNS"),
    _CidrRule(ipaddress.ip_network("208.67.220.0/24"), "US", "San Francisco", "AS36692 Cisco OpenDNS"),

    # ── Cloud Providers & Hyperscalers ─────────────────────────────────────
    _CidrRule(ipaddress.ip_network("172.217.0.0/16"), "US", "Mountain View", "AS15169 Google LLC"),
    _CidrRule(ipaddress.ip_network("142.250.0.0/15"), "US", "Mountain View", "AS15169 Google LLC"),
    _CidrRule(ipaddress.ip_network("34.0.0.0/11"), "US", "Council Bluffs", "AS15169 Google Cloud"),
    _CidrRule(ipaddress.ip_network("35.192.0.0/12"), "US", "Council Bluffs", "AS15169 Google Cloud"),
    _CidrRule(ipaddress.ip_network("52.0.0.0/11"), "US", "Ashburn", "AS16509 Amazon.com Inc"),
    _CidrRule(ipaddress.ip_network("54.0.0.0/11"), "US", "Ashburn", "AS16509 Amazon.com Inc"),
    _CidrRule(ipaddress.ip_network("3.0.0.0/9"), "US", "Seattle", "AS16509 Amazon AWS"),
    _CidrRule(ipaddress.ip_network("18.0.0.0/9"), "US", "Seattle", "AS16509 Amazon AWS"),
    _CidrRule(ipaddress.ip_network("13.64.0.0/11"), "US", "Redmond", "AS8075 Microsoft Corp"),
    _CidrRule(ipaddress.ip_network("20.0.0.0/11"), "US", "Redmond", "AS8075 Microsoft Azure"),
    _CidrRule(ipaddress.ip_network("40.64.0.0/10"), "US", "Redmond", "AS8075 Microsoft Azure"),
    _CidrRule(ipaddress.ip_network("104.16.0.0/12"), "US", "San Francisco", "AS13335 Cloudflare CDN"),
    _CidrRule(ipaddress.ip_network("172.64.0.0/13"), "US", "San Francisco", "AS13335 Cloudflare CDN"),
    _CidrRule(ipaddress.ip_network("45.33.32.0/24"), "US", "Atlanta", "AS63949 Linode LLC"),

    # ── Test / Documentation Networks (RFC 5737) ──────────────────────────
    _CidrRule(ipaddress.ip_network("198.51.100.0/24"), "US", "External WAN", "AS64496 Documentation-NET-2"),
    _CidrRule(ipaddress.ip_network("203.0.113.0/24"), "US", "External DMZ", "AS64497 Documentation-NET-3"),
    _CidrRule(ipaddress.ip_network("192.0.2.0/24"), "US", "External Gateway", "AS64498 Documentation-NET-1"),

    # ── European Regional Blocks ──────────────────────────────────────────
    _CidrRule(ipaddress.ip_network("185.0.0.0/8"), "DE", "Frankfurt", "AS3320 Deutsche Telekom AG"),
    _CidrRule(ipaddress.ip_network("193.0.0.0/8"), "NL", "Amsterdam", "AS1103 SURFnet bv"),
    _CidrRule(ipaddress.ip_network("194.0.0.0/8"), "FR", "Paris", "AS3215 Orange S.A."),
    _CidrRule(ipaddress.ip_network("82.0.0.0/8"), "GB", "London", "AS2856 British Telecom"),
    _CidrRule(ipaddress.ip_network("86.0.0.0/8"), "GB", "Manchester", "AS5089 Virgin Media"),

    # ── Asian & Indian Regional Blocks ────────────────────────────────────
    _CidrRule(ipaddress.ip_network("103.0.0.0/8"), "IN", "Mumbai", "AS4755 Bharti Airtel Ltd"),
    _CidrRule(ipaddress.ip_network("106.0.0.0/8"), "IN", "New Delhi", "AS9829 BSNL Internet"),
    _CidrRule(ipaddress.ip_network("117.0.0.0/8"), "IN", "Bangalore", "AS55836 Reliance Jio"),
    _CidrRule(ipaddress.ip_network("122.0.0.0/8"), "IN", "Chennai", "AS4755 Bharti Airtel Ltd"),
    _CidrRule(ipaddress.ip_network("49.0.0.0/8"), "IN", "Hyderabad", "AS55836 Reliance Jio"),
    _CidrRule(ipaddress.ip_network("110.0.0.0/8"), "CN", "Beijing", "AS4134 China Telecom"),
    _CidrRule(ipaddress.ip_network("111.0.0.0/8"), "CN", "Shanghai", "AS9808 China Mobile"),
    _CidrRule(ipaddress.ip_network("112.0.0.0/8"), "CN", "Guangzhou", "AS4837 China Unicom"),
    _CidrRule(ipaddress.ip_network("123.0.0.0/8"), "CN", "Shenzhen", "AS4134 China Telecom"),
]


class GeoIPEnricher:
    """Offline IP Geolocation and ASN resolver."""

    def __init__(self) -> None:
        self._table = _OFFLINE_CIDR_TABLE

    def lookup(self, ip_str: str | None) -> GeoResult:
        """
        Resolve an IP address to country, city, ASN, and private/public status.
        Never throws exceptions; returns empty GeoResult on failure.
        """
        if not ip_str or not isinstance(ip_str, str):
            return GeoResult()

        ip_clean = ip_str.strip()
        # Handle IP:Port format if passed
        if ":" in ip_clean and not ip_clean.startswith("["):
            parts = ip_clean.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                ip_clean = parts[0]

        try:
            addr = ipaddress.ip_address(ip_clean)
        except ValueError:
            return GeoResult()

        # Check curated offline CIDR table first (explicit rules, test-nets, cloud providers)
        if isinstance(addr, ipaddress.IPv4Address):
            for rule in self._table:
                if addr in rule.network:
                    return GeoResult(
                        country=rule.country,
                        city=rule.city,
                        asn=rule.asn,
                        is_private=False,
                    )

        # Check for RFC 1918 private / loopback / link-local addresses
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return GeoResult(
                country="INTERNAL",
                city="Private Network",
                asn="RFC1918 Private",
                is_private=True,
            )

        # Check heuristic regional fallbacks
        if isinstance(addr, ipaddress.IPv4Address):

            # Heuristic IANA octet-based regional fallback for unlisted public IPs
            first_octet = int(ip_clean.split(".")[0])
            if first_octet in (103, 106, 115, 117, 122, 49):
                return GeoResult(country="IN", city="India Regional", asn="AS-APNIC Regional", is_private=False)
            elif first_octet in (110, 111, 112, 113, 123, 220):
                return GeoResult(country="CN", city="China Regional", asn="AS-APNIC Regional", is_private=False)
            elif first_octet in (185, 188, 193, 194, 195, 212, 213, 217):
                return GeoResult(country="EU", city="Europe Regional", asn="AS-RIPE Regional", is_private=False)
            elif first_octet in (3, 12, 13, 15, 16, 17, 18, 20, 24, 32, 34, 35, 40, 44, 45, 50, 52, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99):
                return GeoResult(country="US", city="North America", asn="AS-ARIN Regional", is_private=False)

        return GeoResult(country="GLOBAL", city="Public WAN", asn="AS-Public Internet", is_private=False)
