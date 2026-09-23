"""
Unit tests for ULPF Contextual Enrichment Layer (GeoIP, Threat Intel, MITRE ATT&CK).
"""

import pytest

from src.schema.unified_event import UnifiedEvent, EventAction, EventCategory, EventSeverity
from src.enrichment.geoip import GeoIPEnricher, GeoResult
from src.enrichment.threat_intel import ThreatIntelEnricher, ThreatIntelResult
from src.enrichment.mitre_mapper import MitreMapper, MitreResult
from src.enrichment.enrichment_pipeline import EnrichmentPipeline, get_enrichment_pipeline


class TestGeoIPEnricher:
    """Tests for offline GeoIP and ASN resolution."""

    def setup_method(self):
        self.geo = GeoIPEnricher()

    def test_rfc1918_private_ips(self):
        private_ips = ["10.0.1.50", "192.168.1.100", "172.16.0.5", "127.0.0.1", "169.254.1.1"]
        for ip in private_ips:
            res = self.geo.lookup(ip)
            assert res.is_private is True
            assert res.country == "INTERNAL"

    def test_known_public_dns_ips(self):
        google_dns = self.geo.lookup("8.8.8.8")
        assert google_dns.is_private is False
        assert google_dns.country == "US"
        assert "Google" in (google_dns.asn or "")

        cf_dns = self.geo.lookup("1.1.1.1")
        assert cf_dns.is_private is False
        assert cf_dns.country == "US"
        assert "Cloudflare" in (cf_dns.asn or "")

        quad9 = self.geo.lookup("9.9.9.9")
        assert quad9.is_private is False
        assert quad9.country == "CH"

    def test_regional_ip_resolution(self):
        linode_ip = self.geo.lookup("45.33.32.156")
        assert linode_ip.country == "US"
        assert linode_ip.city == "Atlanta"

        indian_ip = self.geo.lookup("103.21.244.2")
        assert indian_ip.country == "IN"

        german_ip = self.geo.lookup("185.12.34.56")
        assert german_ip.country == "DE"

    def test_ip_with_port(self):
        res = self.geo.lookup("8.8.8.8:53")
        assert res.country == "US"
        assert res.is_private is False

    def test_invalid_and_none_ip_safety(self):
        assert self.geo.lookup(None).country is None
        assert self.geo.lookup("").country is None
        assert self.geo.lookup("not-an-ip").country is None


class TestThreatIntelEnricher:
    """Tests for offline threat reputation scoring."""

    def setup_method(self):
        self.ti = ThreatIntelEnricher(threshold=0.65)

    def test_known_malicious_ips(self):
        tor_exit = self.ti.check("198.51.100.44")
        assert tor_exit.is_malicious is True
        assert tor_exit.score >= 0.9
        assert tor_exit.source == "tor_exit_nodes"

        c2_ip = self.ti.check("203.0.113.88")
        assert c2_ip.is_malicious is True
        assert c2_ip.score >= 0.95

        scanner = self.ti.check("45.33.32.156")
        assert scanner.is_malicious is True
        assert scanner.source == "shodan_scanner"

    def test_benign_ip_is_clean(self):
        res = self.ti.check("8.8.8.8")
        assert res.is_malicious is False
        assert res.score == 0.0
        assert res.source is None

    def test_cidr_block_matching(self):
        # 198.51.100.64/28 range
        res = self.ti.check("198.51.100.66")
        assert res.is_malicious is True
        assert res.source == "emerging_threats_bruteforce"

    def test_invalid_input_safety(self):
        assert self.ti.check(None).is_malicious is False
        assert self.ti.check("").is_malicious is False
        assert self.ti.check("invalid-string").is_malicious is False


class TestMitreMapper:
    """Tests for MITRE ATT&CK taxonomy classification."""

    def setup_method(self):
        self.mitre = MitreMapper()

    def test_sql_injection_mapping(self):
        res = self.mitre.map_event(threat_name="SQL Injection Attempt", raw_log="SELECT * FROM users WHERE id='1' OR '1'='1'")
        assert res.technique_id == "T1190"
        assert res.technique_name == "Exploit Public-Facing Application"
        assert res.tactic == "Initial Access"

    def test_ssh_brute_force_mapping(self):
        res = self.mitre.map_event(threat_name="Potential SSH Brute Force Scan", raw_log="Failed password for invalid user admin")
        assert res.technique_id == "T1110"
        assert res.technique_name == "Brute Force"
        assert res.tactic == "Credential Access"

    def test_network_scan_mapping(self):
        res = self.mitre.map_event(threat_name="ET SCAN Potential Port Scan", raw_log="TCP SYN probe on port 443")
        assert res.technique_id == "T1046"
        assert res.technique_name == "Network Service Discovery"
        assert res.tactic == "Discovery"

    def test_command_injection_mapping(self):
        res = self.mitre.map_event(threat_name="Command Injection", http_url="/cmd.php?cmd=cat%20/etc/passwd")
        assert res.technique_id == "T1059"
        assert res.technique_name == "Command and Scripting Interpreter"
        assert res.tactic == "Execution"

    def test_firewall_deny_fallback(self):
        res = self.mitre.map_event(action="deny", raw_log="Packet dropped by rule 102")
        assert res.technique_id == "T1190"
        assert res.tactic == "Initial Access"


class TestEnrichmentPipeline:
    """End-to-end integration tests for the full enrichment pipeline."""

    def test_end_to_end_event_enrichment(self):
        event = UnifiedEvent.create(
            raw_log="CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|SQL Injection Detected|9|src=198.51.100.44 spt=51234 dst=8.8.8.8 dpt=80 proto=TCP act=drop",
            format_name="cef",
            source_id="perimeter_fw",
            src_ip="198.51.100.44",
            dst_ip="8.8.8.8",
            src_port=51234,
            dst_port=80,
            protocol="tcp",
            event_action=EventAction.DROP,
            event_category=EventCategory.THREAT,
            severity=EventSeverity.CRITICAL,
            threat_name="SQL Injection Detected",
        )

        pipeline = get_enrichment_pipeline()
        enriched = pipeline.enrich(event)

        # 1. Verify GeoIP & ASN
        assert enriched.src_country == "US"
        assert enriched.is_src_private is False
        assert enriched.dst_country == "US"

        # 2. Verify Threat Intel (198.51.100.44 is in Tor exit node feed)
        assert enriched.threat_intel_score is not None
        assert enriched.threat_intel_score >= 0.90
        assert enriched.threat_intel_source == "tor_exit_nodes"
        assert enriched.is_malicious is True
        assert enriched.weak_label == "attack"
        assert enriched.label_confidence >= 0.85

        # 3. Verify MITRE ATT&CK
        assert enriched.mitre_technique_id == "T1190"
        assert enriched.mitre_tactic == "Initial Access"
        assert enriched.mitre_technique_name == "Exploit Public-Facing Application"

    def test_internal_benign_event_enrichment(self):
        event = UnifiedEvent.create(
            raw_log="<134>Jan 18 10:00:00 fw01 %ASA-6-302013: Built outbound TCP connection",
            format_name="cisco_asa",
            source_id="cisco_lan",
            src_ip="10.0.1.50",
            dst_ip="172.16.0.10",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            event_action=EventAction.ALLOW,
        )

        pipeline = get_enrichment_pipeline()
        enriched = pipeline.enrich(event)

        assert enriched.is_src_private is True
        assert enriched.src_country == "INTERNAL"
        assert enriched.is_malicious is False or enriched.is_malicious is None
        assert enriched.threat_intel_score is None
