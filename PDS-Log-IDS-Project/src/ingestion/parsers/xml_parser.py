"""
Generic XML Parser — fallback parser for any XML-structured log not handled
by a format-specific parser (e.g., WindowsEventParser).

This parser is deliberately registered with lower priority than format-specific
XML parsers. It flattens XML elements and attributes into a key-value dict
and routes everything into extra_fields for downstream analytics.

Use cases
---------
- Vendor-specific appliance XML logs
- SOAP/REST API security event exports
- Database audit logs in XML format
- Firewall/router vendor-specific XML schemas

Behaviour
---------
- Parses the XML line into an element tree
- Extracts attributes of the root element → fields
- Recursively flattens child elements → key = tag path, value = text
- Attempts to detect known field patterns (IP addresses, ports, timestamps)
  and map them to UES canonical fields

PS requirements covered
-----------------------
(b) Extract source-specific attributes — flattens all XML fields
(a) Preserve raw data — raw_log preserved
(e) Plug-and-play — registered via register_parser()
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


# Pattern to detect an IP address
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Pattern to detect a port number
_PORT_RE = re.compile(r"^\d{1,5}$")

# Key name hints → UES canonical field
_KEY_HINTS: dict[str, str] = {
    "srcip": "src_ip",
    "sourceip": "src_ip",
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "dstip": "dst_ip",
    "destip": "dst_ip",
    "destinationip": "dst_ip",
    "dst_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "srcport": "src_port",
    "sourceport": "src_port",
    "src_port": "src_port",
    "dstport": "dst_port",
    "destport": "dst_port",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "proto": "protocol",
    "action": "event_action",
    "severity": "severity",
    "level": "severity",
    "username": "username",
    "user": "username",
    "hostname": "device_hostname",
    "host": "device_hostname",
    "computer": "device_hostname",
    "message": "threat_name",
    "msg": "threat_name",
    "eventid": "threat_signature_id",
    "event_id": "threat_signature_id",
    "timestamp": "timestamp_raw",
    "time": "timestamp_raw",
    "datetime": "timestamp_raw",
    "useragent": "user_agent",
    "user_agent": "user_agent",
    "url": "http_url",
    "uri": "http_url",
}


def _flatten_xml(element: ET.Element, prefix: str = "") -> dict[str, str]:
    """
    Recursively flatten an XML element tree into a key:value dict.
    Keys are built from the tag path (parent_child_grandchild).
    """
    result: dict[str, str] = {}

    # Root attributes
    for attr_name, attr_val in element.attrib.items():
        key = f"{prefix}{attr_name}" if prefix else attr_name
        # Strip XML namespace if present
        if "}" in key:
            key = key.split("}", 1)[1]
        result[key.lower()] = attr_val.strip()

    # Text content of this element
    text = (element.text or "").strip()
    if text:
        tag = element.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        key = f"{prefix}{tag}" if prefix else tag
        result[key.lower()] = text

    # Recurse into children
    for child in element:
        child_tag = child.tag
        if "}" in child_tag:
            child_tag = child_tag.split("}", 1)[1]
        child_prefix = f"{prefix}{child_tag}_" if prefix else f"{child_tag}_"
        result.update(_flatten_xml(child, child_prefix))

    return result


class GenericXmlParser(BaseLogParser):
    """
    Generic XML log parser — fallback for any XML-structured log.

    Flattens all XML fields into a key-value dict and attempts to
    map well-known key names to UES canonical fields.

    Register this parser LAST so format-specific XML parsers
    (e.g., WindowsEventParser) take precedence.
    """

    @property
    def format_name(self) -> str:
        return "xml_generic"

    @property
    def description(self) -> str:
        return "Generic XML log parser — flattens any XML-structured log into UES"

    def can_parse(self, sample: str) -> bool:
        """
        True if sample starts with '<' and is valid XML.
        Deliberately conservative — specific XML parsers should take
        precedence, so this is a last-resort check.
        """
        stripped = sample.strip()
        if not stripped.startswith("<"):
            return False
        try:
            ET.fromstring(stripped)
            return True
        except ET.ParseError:
            return False

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"XML parse error: {exc}",
                format_name=self.format_name,
            )

        # Flatten the entire XML tree
        flat = _flatten_xml(root)

        canonical: dict[str, Any] = {}
        extra: dict[str, Any] = {}

        for raw_key, raw_val in flat.items():
            # Normalize key: remove namespace markers, underscores, lowercase
            norm_key = raw_key.lower().replace("-", "_").replace(" ", "_")
            ues_field = _KEY_HINTS.get(norm_key)
            if ues_field:
                canonical[ues_field] = raw_val
            else:
                extra[raw_key] = raw_val

        # Tag the root element name for traceability
        root_tag = root.tag
        if "}" in root_tag:
            root_tag = root_tag.split("}", 1)[1]
        extra["xml_root_tag"] = root_tag
        canonical["extra_fields"] = extra

        # Apply defaults for required fields
        canonical.setdefault("event_category", "unknown")
        canonical.setdefault("event_action", "unknown")
        canonical.setdefault("severity", "informational")
        canonical.setdefault("device_type", "generic")

        return ParseResult(
            success=True,
            raw_log=line,
            fields=canonical,
            error=None,
            format_name=self.format_name,
        )


# Auto-register on import (register last — lowest priority for XML)
register_parser(GenericXmlParser())
