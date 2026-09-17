"""
Tests for UnifiedEvent schema, field mapper, and schema validator.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.schema.unified_event import (
    UnifiedEvent,
    EventSeverity,
    EventCategory,
    EventAction,
    SourceType,
)
from src.schema.schema_validator import validate_unified_event, SchemaValidationError
from src.schema.field_mapper import FieldMapper


# ---------------------------------------------------------------------------
# UnifiedEvent creation tests
# ---------------------------------------------------------------------------

class TestUnifiedEventCreation:

    def test_create_minimal_event(self):
        event = UnifiedEvent.create(
            raw_log='CEF:0|Cisco|ASA|9.14|106023|Deny|6|src=1.2.3.4',
            format_name="cef",
            source_id="test_source",
        )
        assert event.event_uid is not None
        assert len(event.event_uid) == 36  # UUID v4
        assert event.record_hash is not None
        assert len(event.record_hash) == 32  # SHA-256 truncated
        assert event.raw_log.startswith("CEF:")
        assert event.format_name == "cef"
        assert event.source_id == "test_source"
        assert event.ingest_timestamp is not None

    def test_record_hash_is_deterministic(self):
        raw = "same raw log line"
        e1 = UnifiedEvent.create(raw_log=raw, format_name="test", source_id="s")
        e2 = UnifiedEvent.create(raw_log=raw, format_name="test", source_id="s")
        assert e1.record_hash == e2.record_hash

    def test_record_hash_differs_for_different_content(self):
        e1 = UnifiedEvent.create(raw_log="log line A", format_name="test", source_id="s")
        e2 = UnifiedEvent.create(raw_log="log line B", format_name="test", source_id="s")
        assert e1.record_hash != e2.record_hash

    def test_event_uid_is_unique(self):
        events = [
            UnifiedEvent.create(raw_log="same log", format_name="test", source_id="s")
            for _ in range(100)
        ]
        uids = {e.event_uid for e in events}
        assert len(uids) == 100  # all unique

    def test_raw_log_preserved_exactly(self):
        raw = 'CEF:0|Cisco|ASA|9.14|106023|Deny TCP|6|src=192.168.1.5 spt=44231'
        event = UnifiedEvent.create(raw_log=raw, format_name="cef", source_id="s")
        assert event.raw_log == raw  # no modification

    def test_create_with_all_fields(self):
        event = UnifiedEvent.create(
            raw_log="test",
            format_name="cef",
            source_id="firewall_01",
            src_ip="192.168.1.5",
            dst_ip="10.0.0.1",
            src_port=44231,
            dst_port=443,
            protocol="tcp",
            severity=EventSeverity.HIGH,
            event_category=EventCategory.THREAT,
            event_action=EventAction.DENY,
            weak_label="attack",
            label_confidence=0.85,
        )
        assert event.src_ip == "192.168.1.5"
        assert event.src_port == 44231
        assert event.severity == EventSeverity.HIGH
        assert event.weak_label == "attack"
        assert event.label_confidence == 0.85

    def test_to_dict_is_serializable(self):
        import json
        event = UnifiedEvent.create(
            raw_log="test log",
            format_name="syslog",
            source_id="fw01",
            timestamp_utc=datetime.now(timezone.utc),
        )
        d = event.to_dict()
        # Should serialize without error
        json_str = json.dumps(d)
        assert len(json_str) > 10

    def test_to_json_is_valid_json(self):
        import json
        event = UnifiedEvent.create(
            raw_log='{"src": "1.2.3.4"}',
            format_name="json",
            source_id="test",
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["format_name"] == "json"
        assert parsed["raw_log"] == '{"src": "1.2.3.4"}'


# ---------------------------------------------------------------------------
# Schema validator tests
# ---------------------------------------------------------------------------

class TestSchemaValidator:

    def _make_event(self, **kwargs) -> UnifiedEvent:
        defaults = {
            "raw_log": "test log line",
            "format_name": "cef",
            "source_id": "test_source",
        }
        defaults.update(kwargs)
        return UnifiedEvent.create(**defaults)

    def test_valid_event_passes(self):
        event = self._make_event()
        validate_unified_event(event)  # should not raise

    def test_missing_raw_log_fails(self):
        event = self._make_event()
        event.raw_log = ""
        with pytest.raises(SchemaValidationError, match="raw_log"):
            validate_unified_event(event)

    def test_missing_format_name_fails(self):
        event = self._make_event()
        event.format_name = ""
        with pytest.raises(SchemaValidationError, match="format_name"):
            validate_unified_event(event)

    def test_invalid_record_hash_fails(self):
        event = self._make_event()
        event.record_hash = "not-a-valid-hash"
        with pytest.raises(SchemaValidationError, match="record_hash"):
            validate_unified_event(event)

    def test_invalid_src_port_fails(self):
        event = self._make_event(src_port=99999)
        with pytest.raises(SchemaValidationError, match="src_port"):
            validate_unified_event(event)

    def test_valid_port_passes(self):
        event = self._make_event(src_port=44231, dst_port=443)
        validate_unified_event(event)  # should not raise

    def test_invalid_label_confidence_fails(self):
        event = self._make_event(label_confidence=1.5)
        with pytest.raises(SchemaValidationError, match="label_confidence"):
            validate_unified_event(event)

    def test_valid_label_confidence_passes(self):
        event = self._make_event(label_confidence=0.85)
        validate_unified_event(event)


# ---------------------------------------------------------------------------
# FieldMapper tests
# ---------------------------------------------------------------------------

class TestFieldMapper:

    def test_default_mapper_is_passthrough(self):
        from src.schema.field_mapper import DEFAULT_MAPPER
        raw = {"src": "192.168.1.5", "custom_field": "value"}
        result = DEFAULT_MAPPER.map(raw)
        # All unmapped fields go to extra_fields
        assert "extra_fields" in result
        assert result["extra_fields"].get("src") == "192.168.1.5"

    def test_field_map_translates_names(self):
        mapper = FieldMapper(
            source_id="test",
            vendor="cisco",
            device_type="firewall",
            field_map={"src": "src_ip", "spt": "src_port"},
        )
        result = mapper.map({"src": "192.168.1.5", "spt": "44231"})
        assert result.get("src_ip") == "192.168.1.5"
        assert result.get("src_port") == 44231  # coerced to int

    def test_port_coerced_to_int(self):
        mapper = FieldMapper(
            source_id="test",
            vendor=None,
            device_type="generic",
            field_map={"port": "src_port"},
        )
        result = mapper.map({"port": "8080"})
        assert result.get("src_port") == 8080
        assert isinstance(result.get("src_port"), int)

    def test_severity_coerced_to_enum(self):
        mapper = FieldMapper(
            source_id="test",
            vendor=None,
            device_type="ids_ips",
            field_map={"sev": "severity"},
        )
        result = mapper.map({"sev": "high"})
        assert result.get("severity") == EventSeverity.HIGH

    def test_unmapped_fields_go_to_extra(self):
        mapper = FieldMapper(
            source_id="test",
            vendor=None,
            device_type="generic",
            field_map={"known": "src_ip"},
        )
        result = mapper.map({"known": "1.2.3.4", "unknown_field": "xyz"})
        assert result.get("src_ip") == "1.2.3.4"
        assert result.get("extra_fields", {}).get("unknown_field") == "xyz"
