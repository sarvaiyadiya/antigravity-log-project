"""
Tests for all ULPF format parsers.

Each parser is tested against:
1. can_parse()  — correctly identifies lines it can handle
2. parse_line() — correctly extracts fields from valid lines
3. Error handling — gracefully returns ParseResult(success=False) for invalid input
"""

import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.ingestion.parsers.syslog_parser import SyslogParser
from src.ingestion.parsers.cef_parser import CefParser
from src.ingestion.parsers.leef_parser import LeefParser
from src.ingestion.parsers.snort_parser import SnortParser
from src.ingestion.parsers.json_parser import GenericJsonParser, CjJsonArrayParser
from src.ingestion.parsers.csv_parser import CsvLogParser
from src.ingestion.parser_registry import get_registry

SAMPLES_DIR = Path(__file__).parent / "samples"


# ---------------------------------------------------------------------------
# Syslog Parser Tests
# ---------------------------------------------------------------------------

class TestSyslogParser:
    parser = SyslogParser()

    RFC3164_LINE = (
        "<134>Jan  8 12:34:56 fw01 ASA-3-106023: "
        "Deny tcp src outside:192.168.1.5/44231 dst inside:10.0.0.1/443 "
        "by access-group \"outside_access_in\""
    )
    RFC5424_LINE = (
        "<134>1 2024-01-08T12:34:56.000Z pa-fw-01 firewall - TRAFFIC - "
        "src=192.168.2.10 dst=8.8.8.8 spt=54321 dpt=53 proto=UDP action=allow"
    )

    def test_can_parse_rfc3164(self):
        assert self.parser.can_parse(self.RFC3164_LINE)

    def test_can_parse_rfc5424(self):
        assert self.parser.can_parse(self.RFC5424_LINE)

    def test_cannot_parse_cef(self):
        assert not self.parser.can_parse("CEF:0|Cisco|ASA|9.14|106023|Deny|6|src=1.2.3.4")

    def test_parse_rfc3164(self):
        result = self.parser.parse_line(self.RFC3164_LINE)
        assert result.success
        assert result.format_name == "syslog"
        assert "device_hostname" in result.fields
        assert result.fields["device_hostname"] == "fw01"

    def test_parse_rfc5424(self):
        result = self.parser.parse_line(self.RFC5424_LINE)
        assert result.success
        assert "src_ip" in result.fields or "src" in result.fields

    def test_parse_invalid_line(self):
        result = self.parser.parse_line("this is not syslog at all")
        assert not result.success

    def test_parse_sample_file(self):
        """All non-comment, non-blank lines in the sample file should parse."""
        sample_file = SAMPLES_DIR / "sample_syslog.log"
        if not sample_file.exists():
            pytest.skip("Sample file not found")
        with sample_file.open() as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            result = self.parser.parse_line(line)
            # All sample lines should succeed
            assert result.success, f"Failed to parse: {line!r}\nError: {result.error}"


# ---------------------------------------------------------------------------
# CEF Parser Tests
# ---------------------------------------------------------------------------

class TestCefParser:
    parser = CefParser()

    CEF_LINE = (
        "CEF:0|Cisco|ASA|9.14|106023|Deny TCP|6|"
        "src=192.168.1.5 spt=44231 dst=10.0.0.1 dpt=443 proto=TCP act=Deny"
    )

    def test_can_parse_cef(self):
        assert self.parser.can_parse(self.CEF_LINE)

    def test_cannot_parse_syslog(self):
        assert not self.parser.can_parse(
            "<134>Jan  8 12:34:56 fw01 ASA: msg"
        )

    def test_parse_cef(self):
        result = self.parser.parse_line(self.CEF_LINE)
        assert result.success
        assert result.format_name == "cef"
        assert result.fields.get("vendor") == "Cisco"
        assert result.fields.get("src_ip") == "192.168.1.5"
        assert result.fields.get("src_port") == "44231"
        assert result.fields.get("dst_ip") == "10.0.0.1"
        assert result.fields.get("dst_port") == "443"
        assert result.fields.get("protocol") == "TCP"

    def test_parse_cef_with_severity(self):
        result = self.parser.parse_line(self.CEF_LINE)
        assert result.fields.get("severity_label") == "6"

    def test_parse_threat_fields(self):
        result = self.parser.parse_line(self.CEF_LINE)
        assert result.fields.get("threat_signature_id") == "106023"
        assert result.fields.get("threat_name") == "Deny TCP"

    def test_parse_invalid_cef(self):
        result = self.parser.parse_line("CEF:0|only|two")
        assert not result.success

    def test_parse_sample_file(self):
        sample_file = SAMPLES_DIR / "sample_cef.log"
        if not sample_file.exists():
            pytest.skip("Sample file not found")
        with sample_file.open() as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            result = self.parser.parse_line(line)
            assert result.success, f"Failed: {line!r}\n{result.error}"


# ---------------------------------------------------------------------------
# LEEF Parser Tests
# ---------------------------------------------------------------------------

class TestLeefParser:
    parser = LeefParser()

    LEEF_LINE = (
        "LEEF:1.0|Cisco|ASA|9.14|106023|"
        "src=192.168.1.5\tspt=44231\tdst=10.0.0.1\tdpt=443\tproto=TCP\taction=deny"
    )

    def test_can_parse_leef(self):
        assert self.parser.can_parse(self.LEEF_LINE)

    def test_cannot_parse_cef(self):
        assert not self.parser.can_parse("CEF:0|Cisco|ASA|9.14|106023|Deny|6|")

    def test_parse_leef(self):
        result = self.parser.parse_line(self.LEEF_LINE)
        assert result.success
        assert result.format_name == "leef"
        assert result.fields.get("src_ip") == "192.168.1.5"
        assert result.fields.get("dst_ip") == "10.0.0.1"

    def test_parse_sample_file(self):
        sample_file = SAMPLES_DIR / "sample_leef.log"
        if not sample_file.exists():
            pytest.skip("Sample file not found")
        with sample_file.open() as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            result = self.parser.parse_line(line)
            assert result.success, f"Failed: {line!r}\n{result.error}"


# ---------------------------------------------------------------------------
# Snort Parser Tests
# ---------------------------------------------------------------------------

class TestSnortParser:
    parser = SnortParser()

    SNORT_LINE = (
        "01/08-12:34:56.123456  [**] [1:2100498:7] ICMP PING [**] "
        "[Classification: Misc activity] [Priority: 3] {ICMP} 192.168.1.5 -> 10.0.0.1"
    )
    SURICATA_LINE = (
        "01/08/2024-12:36:00.000000  [Drop] [**] [1:2019284:3] "
        "ET POLICY Suspicious Outbound User-Agent (gobuster) [**] "
        "[Classification: A Network Trojan was Detected] [Priority: 1] "
        "{TCP} 192.168.1.200:43210 -> 8.8.8.8:80"
    )

    def test_can_parse_snort(self):
        assert self.parser.can_parse(self.SNORT_LINE)

    def test_can_parse_suricata(self):
        assert self.parser.can_parse(self.SURICATA_LINE)

    def test_cannot_parse_cef(self):
        assert not self.parser.can_parse("CEF:0|Cisco|ASA|9.14|106023|Deny|6|src=1.2.3.4")

    def test_parse_snort(self):
        result = self.parser.parse_line(self.SNORT_LINE)
        assert result.success
        assert result.format_name == "snort_alert"
        assert result.fields.get("src_ip") == "192.168.1.5"
        assert result.fields.get("dst_ip") == "10.0.0.1"
        assert result.fields.get("threat_name") == "ICMP PING"
        assert "1:2100498:7" in result.fields.get("threat_signature_id", "")

    def test_parse_suricata_with_action(self):
        result = self.parser.parse_line(self.SURICATA_LINE)
        assert result.success
        assert result.fields.get("action") == "drop"
        assert result.fields.get("src_ip") == "192.168.1.200"
        assert result.fields.get("src_port") == "43210"

    def test_parse_sample_file(self):
        sample_file = SAMPLES_DIR / "sample_snort.log"
        if not sample_file.exists():
            pytest.skip("Sample file not found")
        with sample_file.open() as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            result = self.parser.parse_line(line)
            assert result.success, f"Failed: {line!r}\n{result.error}"


# ---------------------------------------------------------------------------
# JSON Parser Tests
# ---------------------------------------------------------------------------

class TestJsonParser:
    generic = GenericJsonParser()
    cj = CjJsonArrayParser()

    JSON_LINE = '{"src_ip": "192.168.1.5", "dst_ip": "10.0.0.1", "action": "deny"}'
    CJ_LINE = '["web_request","page_view","2024-01-08 12:34:56","192.168.1.5",44231,"Mozilla/5.0","en-US","{}"]'

    def test_generic_can_parse(self):
        assert self.generic.can_parse(self.JSON_LINE)

    def test_generic_cannot_parse_array(self):
        assert not self.generic.can_parse(self.CJ_LINE)

    def test_cj_can_parse(self):
        assert self.cj.can_parse(self.CJ_LINE)

    def test_generic_parse(self):
        result = self.generic.parse_line(self.JSON_LINE)
        assert result.success
        assert result.fields.get("src_ip") == "192.168.1.5"

    def test_cj_parse(self):
        result = self.cj.parse_line(self.CJ_LINE)
        assert result.success
        assert result.fields.get("src_ip") == "192.168.1.5"
        assert result.fields.get("src_port") == 44231

    def test_generic_parse_invalid(self):
        result = self.generic.parse_line("not json {")
        assert not result.success


# ---------------------------------------------------------------------------
# Parser Registry Tests
# ---------------------------------------------------------------------------

class TestParserRegistry:
    def test_registry_has_parsers(self):
        registry = get_registry()
        assert len(registry) >= 5

    def test_detect_syslog(self):
        registry = get_registry()
        parser = registry.detect("<134>Jan  8 12:34:56 fw01 msg: test")
        assert parser is not None
        assert parser.format_name == "syslog"

    def test_detect_cef(self):
        registry = get_registry()
        parser = registry.detect("CEF:0|Cisco|ASA|9.14|106023|Deny|6|src=1.2.3.4")
        assert parser is not None
        assert parser.format_name == "cef"

    def test_detect_leef(self):
        registry = get_registry()
        parser = registry.detect("LEEF:1.0|Cisco|ASA|9.14|event|src=1.2.3.4")
        assert parser is not None
        assert parser.format_name == "leef"

    def test_detect_snort(self):
        registry = get_registry()
        parser = registry.detect("01/08-12:34:56  [**] [1:2100498:7] ICMP [**] {ICMP} 1.2.3.4 -> 5.6.7.8")
        assert parser is not None
        assert parser.format_name == "snort_alert"

    def test_detect_unknown(self):
        registry = get_registry()
        parser = registry.detect("this is completely unknown log format xyz123")
        assert parser is None
