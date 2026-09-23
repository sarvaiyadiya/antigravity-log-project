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


# ---------------------------------------------------------------------------
# Windows Event XML Parser Tests
# ---------------------------------------------------------------------------

class TestWindowsEventParser:
    from src.ingestion.parsers.windows_event_parser import WindowsEventParser
    parser = WindowsEventParser()

    LOGON_SUCCESS = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4624</EventID><Level>0</Level>"
        "<TimeCreated SystemTime='2024-01-15T10:23:45.000000000Z'/>"
        "<Channel>Security</Channel>"
        "<Computer>WORKSTATION01.corp.local</Computer></System>"
        "<EventData>"
        "<Data Name='TargetUserName'>alice</Data>"
        "<Data Name='IpAddress'>192.168.1.50</Data>"
        "<Data Name='IpPort'>55421</Data>"
        "</EventData></Event>"
    )

    FAILED_LOGON = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4625</EventID><Level>0</Level>"
        "<TimeCreated SystemTime='2024-01-15T10:24:00.000000000Z'/>"
        "<Channel>Security</Channel>"
        "<Computer>DC01.corp.local</Computer></System>"
        "<EventData>"
        "<Data Name='TargetUserName'>administrator</Data>"
        "<Data Name='IpAddress'>10.0.0.99</Data>"
        "</EventData></Event>"
    )

    INVALID_XML = "<NotAnEvent>missing closing tag"

    def test_can_parse_windows_event(self):
        assert self.parser.can_parse(self.LOGON_SUCCESS) is True

    def test_cannot_parse_non_xml(self):
        assert self.parser.can_parse("Jan 15 10:23:45 host sshd[1234]: Accepted") is False

    def test_parse_logon_success(self):
        result = self.parser.parse_line(self.LOGON_SUCCESS)
        assert result.success is True
        assert result.fields["threat_signature_id"] == "4624"
        assert result.fields["threat_name"] == "Successful Logon"
        assert result.fields["username"] == "alice"
        assert result.fields["src_ip"] == "192.168.1.50"
        assert result.fields["src_port"] == "55421"
        assert result.fields["device_hostname"] == "WORKSTATION01.corp.local"
        assert result.fields["event_action"] == "allow"

    def test_parse_failed_logon(self):
        result = self.parser.parse_line(self.FAILED_LOGON)
        assert result.success is True
        assert result.fields["threat_signature_id"] == "4625"
        assert result.fields["threat_name"] == "Failed Logon"
        assert result.fields["username"] == "administrator"
        assert result.fields["event_action"] == "deny"

    def test_parse_invalid_xml_returns_failure(self):
        result = self.parser.parse_line(self.INVALID_XML)
        assert result.success is False
        assert result.error is not None

    def test_format_name(self):
        assert self.parser.format_name == "windows_event_xml"


# ---------------------------------------------------------------------------
# Cisco ASA Parser Tests
# ---------------------------------------------------------------------------

class TestCiscoAsaParser:
    from src.ingestion.parsers.cisco_asa_parser import CiscoAsaParser
    parser = CiscoAsaParser()

    DENY_TCP = "%ASA-4-106023: Deny tcp src outside:203.0.113.10/54321 dst inside:10.0.0.5/443 by access-group \"OUTSIDE_IN\""
    ALLOW_TCP = "%ASA-6-302013: Built inbound TCP connection 12345678 for outside:192.168.1.100/55000 (192.168.1.100/55000) to inside:10.0.0.10/80 (10.0.0.10/80)"
    DENY_UDP  = "%ASA-4-106006: Deny inbound UDP from 203.0.113.50/53 to 10.0.0.2/53 on interface outside"
    SYSLOG_WRAPPED = "Jan 15 2024 10:23:45: %ASA-3-710003: TCP access denied by ACL from 45.33.32.156/48032 to outside:10.0.0.1/443"
    NOT_ASA = "CEF:0|Cisco|ASA|9.14|106023|Deny TCP|6|src=1.2.3.4"

    def test_can_parse_asa(self):
        assert self.parser.can_parse(self.DENY_TCP) is True

    def test_can_parse_syslog_wrapped(self):
        assert self.parser.can_parse(self.SYSLOG_WRAPPED) is True

    def test_cannot_parse_cef(self):
        assert self.parser.can_parse(self.NOT_ASA) is False

    def test_parse_deny_tcp_fields(self):
        result = self.parser.parse_line(self.DENY_TCP)
        assert result.success is True
        assert result.fields["event_action"] == "deny"
        assert result.fields["protocol"] == "tcp"
        assert result.fields["src_ip"] == "203.0.113.10"
        assert result.fields["src_port"] == "54321"
        assert result.fields["dst_ip"] == "10.0.0.5"
        assert result.fields["dst_port"] == "443"
        assert result.fields["vendor"] == "cisco"
        assert result.fields["threat_signature_id"] == "106023"

    def test_parse_allow_action(self):
        result = self.parser.parse_line(self.ALLOW_TCP)
        assert result.success is True
        assert result.fields["event_action"] == "allow"

    def test_parse_deny_udp(self):
        result = self.parser.parse_line(self.DENY_UDP)
        assert result.success is True
        assert result.fields["protocol"] == "udp"
        assert result.fields["event_action"] == "deny"

    def test_parse_syslog_wrapped(self):
        result = self.parser.parse_line(self.SYSLOG_WRAPPED)
        assert result.success is True
        assert result.fields["threat_signature_id"] == "710003"

    def test_parse_invalid_returns_failure(self):
        result = self.parser.parse_line("completely unrelated log line with no ASA marker")
        assert result.success is False

    def test_format_name(self):
        assert self.parser.format_name == "cisco_asa"


# ---------------------------------------------------------------------------
# Palo Alto PAN-OS Parser Tests
# ---------------------------------------------------------------------------

class TestPaloAltoParser:
    from src.ingestion.parsers.paloalto_parser import PaloAltoTrafficParser, PaloAltoThreatParser
    traffic_parser = PaloAltoTrafficParser()
    threat_parser  = PaloAltoThreatParser()

    TRAFFIC_LINE = (
        "FUTURE_USE,2024/01/15 10:23:45,001234567890,TRAFFIC,end,1,"
        "2024/01/15 10:23:45,192.168.1.100,10.0.0.50,0.0.0.0,0.0.0.0,"
        "Allow-Web,alice,bob,web-browsing,vsys1,trust,untrust,"
        "ethernet1/1,ethernet1/2,default,2024/01/15 10:23:45,"
        "54321,0,55000,80,0,0,0x400000,tcp,allow,1024,512,512,10,"
        "2024/01/15 10:23:35,30,any,0,1234567890123456,0x0,"
        "United States,India,0,1,0,aged-out,0,0,0,0,,PA-220,"
        "from-policy,FUTURE_USE,0,0,0,0,complete,10,20,0,0"
    )

    THREAT_LINE = (
        "FUTURE_USE,2024/01/15 10:26:00,001234567890,THREAT,vulnerability,1,"
        "2024/01/15 10:26:00,203.0.113.99,10.0.0.20,0.0.0.0,0.0.0.0,"
        "Block-Threats,,,web-browsing,vsys1,untrust,trust,"
        "ethernet1/2,ethernet1/1,default,2024/01/15 10:26:00,"
        "54231,0,443,80,0,0,0x0,tcp,alert,0,0,0,0,"
        "2024/01/15 10:26:00,0,any,0,1234567890123459,0x0,"
        "China,India,0,0,0,threat,0,0,0,0,,PA-220,"
        "from-policy,FUTURE_USE,0,0,0,0,complete,10,5,0,0,"
        "GET /cmd.php HTTP/1.1,attacker,,,36336,SQL Injection,high,client-to-server,,"
    )

    SHORT_LINE = "FUTURE_USE,2024/01/15,001,TRAFFIC"

    def test_traffic_can_parse(self):
        assert self.traffic_parser.can_parse(self.TRAFFIC_LINE) is True

    def test_traffic_cannot_parse_threat(self):
        assert self.traffic_parser.can_parse(self.THREAT_LINE) is False

    def test_threat_can_parse(self):
        assert self.threat_parser.can_parse(self.THREAT_LINE) is True

    def test_threat_cannot_parse_traffic(self):
        assert self.threat_parser.can_parse(self.TRAFFIC_LINE) is False

    def test_parse_traffic_fields(self):
        result = self.traffic_parser.parse_line(self.TRAFFIC_LINE)
        assert result.success is True
        assert result.fields["src_ip"] == "192.168.1.100"
        assert result.fields["dst_ip"] == "10.0.0.50"
        assert result.fields["src_port"] == "55000"
        assert result.fields["dst_port"] == "80"
        assert result.fields["protocol"] == "tcp"
        assert result.fields["event_action"] == "allow"
        assert result.fields["vendor"] == "palo_alto"

    def test_parse_too_short_returns_failure(self):
        result = self.traffic_parser.parse_line(self.SHORT_LINE)
        assert result.success is False

    def test_traffic_format_name(self):
        assert self.traffic_parser.format_name == "paloalto_traffic"

    def test_threat_format_name(self):
        assert self.threat_parser.format_name == "paloalto_threat"


# ---------------------------------------------------------------------------
# AWS CloudTrail Parser Tests
# ---------------------------------------------------------------------------

class TestCloudTrailParser:
    from src.ingestion.parsers.cloudtrail_parser import CloudTrailParser
    parser = CloudTrailParser()

    RECORDS_WRAPPER = (
        '{"Records":[{"eventVersion":"1.08","userIdentity":{"type":"IAMUser",'
        '"userName":"alice","accountId":"123456789012"},'
        '"eventTime":"2024-01-15T10:23:45Z","eventSource":"s3.amazonaws.com",'
        '"eventName":"GetObject","awsRegion":"us-east-1",'
        '"sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.9.0",'
        '"requestID":"EXAMPLE123","eventID":"abc-123","readOnly":true,'
        '"eventType":"AwsApiCall","managementEvent":false,'
        '"recipientAccountId":"123456789012"}]}'
    )

    SINGLE_RECORD = (
        '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"bob",'
        '"accountId":"123456789012"},"eventTime":"2024-01-15T10:24:00Z",'
        '"eventSource":"iam.amazonaws.com","eventName":"CreateUser",'
        '"awsRegion":"us-east-1","sourceIPAddress":"192.168.1.50",'
        '"userAgent":"console.amazonaws.com","requestID":"REQ456",'
        '"eventID":"def-456","readOnly":false,"eventType":"AwsApiCall",'
        '"managementEvent":true,"recipientAccountId":"123456789012"}'
    )

    UNAUTHORIZED = (
        '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"eve",'
        '"accountId":"123456789012"},"eventTime":"2024-01-15T10:25:00Z",'
        '"eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances",'
        '"awsRegion":"ap-south-1","sourceIPAddress":"45.33.32.156",'
        '"userAgent":"boto3/1.28.0","errorCode":"UnauthorizedOperation",'
        '"errorMessage":"Not authorized","requestID":"REQ789","eventID":"ghi-789",'
        '"readOnly":true,"eventType":"AwsApiCall","managementEvent":false,'
        '"recipientAccountId":"123456789012"}'
    )

    NOT_CLOUDTRAIL = '{"message": "regular json log", "level": "info"}'
    NOT_JSON = "Jan 15 10:23:45 host sshd: Accepted"

    def test_can_parse_records_wrapper(self):
        assert self.parser.can_parse(self.RECORDS_WRAPPER) is True

    def test_can_parse_single_record(self):
        assert self.parser.can_parse(self.SINGLE_RECORD) is True

    def test_cannot_parse_regular_json(self):
        assert self.parser.can_parse(self.NOT_CLOUDTRAIL) is False

    def test_cannot_parse_non_json(self):
        assert self.parser.can_parse(self.NOT_JSON) is False

    def test_parse_records_wrapper(self):
        result = self.parser.parse_line(self.RECORDS_WRAPPER)
        assert result.success is True
        assert result.fields["username"] == "alice"
        assert result.fields["src_ip"] == "203.0.113.10"
        assert result.fields["threat_signature_id"] == "GetObject"
        assert result.fields["event_action"] == "allow"

    def test_parse_single_record(self):
        result = self.parser.parse_line(self.SINGLE_RECORD)
        assert result.success is True
        assert result.fields["username"] == "bob"
        assert result.fields["threat_signature_id"] == "CreateUser"
        assert result.fields["severity"] == "medium"

    def test_parse_unauthorized_gives_deny(self):
        result = self.parser.parse_line(self.UNAUTHORIZED)
        assert result.success is True
        assert result.fields["event_action"] == "deny"
        assert result.fields["severity"] == "high"

    def test_parse_invalid_json_returns_failure(self):
        result = self.parser.parse_line("{invalid json}")
        assert result.success is False

    def test_format_name(self):
        assert self.parser.format_name == "aws_cloudtrail"


# ---------------------------------------------------------------------------
# Generic XML Parser Tests
# ---------------------------------------------------------------------------

class TestGenericXmlParser:
    from src.ingestion.parsers.xml_parser import GenericXmlParser
    parser = GenericXmlParser()

    SECURITY_LOG = (
        "<SecurityLog><Event EventID=\"1001\" Severity=\"High\" Action=\"Deny\" "
        "Protocol=\"TCP\" SrcIP=\"203.0.113.5\" SrcPort=\"54321\" "
        "DstIP=\"10.0.0.1\" DstPort=\"22\" "
        "Timestamp=\"2024-01-15T10:23:45Z\" Username=\"root\" "
        "Hostname=\"gateway01\"/></SecurityLog>"
    )

    FIREWALL_EVENT = (
        "<FirewallEvent><Header Timestamp=\"2024-01-15T10:24:00Z\" "
        "DeviceID=\"FW-001\" Hostname=\"perimeter-fw\"/>"
        "<Network SrcIP=\"45.33.32.156\" DstIP=\"192.168.1.10\" "
        "SrcPort=\"12345\" DstPort=\"443\" Protocol=\"TCP\" Action=\"block\"/>"
        "<Threat Severity=\"critical\" Message=\"Port scan detected\"/>"
        "</FirewallEvent>"
    )

    INVALID_XML = "<incomplete tag with no close"
    NOT_XML = "Jan 15 10:23:45 host sshd: Accepted password"

    def test_can_parse_security_log(self):
        assert self.parser.can_parse(self.SECURITY_LOG) is True

    def test_can_parse_firewall_event(self):
        assert self.parser.can_parse(self.FIREWALL_EVENT) is True

    def test_cannot_parse_syslog(self):
        assert self.parser.can_parse(self.NOT_XML) is False

    def test_parse_security_log_maps_fields(self):
        result = self.parser.parse_line(self.SECURITY_LOG)
        assert result.success is True
        # Fields mapped via key hints
        assert result.fields.get("src_ip") == "203.0.113.5" or \
               "203.0.113.5" in str(result.fields)

    def test_parse_invalid_xml_returns_failure(self):
        result = self.parser.parse_line(self.INVALID_XML)
        assert result.success is False
        assert result.error is not None

    def test_format_name(self):
        assert self.parser.format_name == "xml_generic"

    def test_never_raises_exception(self):
        """Parser must never raise — always return ParseResult."""
        try:
            result = self.parser.parse_line("<<bad xml>>>")
            assert result.success is False
        except Exception as exc:
            pytest.fail(f"Parser raised exception instead of returning failure: {exc}")

