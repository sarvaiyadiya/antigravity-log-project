"""
AWS CloudTrail Parser — parses AWS CloudTrail JSON log format.

AWS CloudTrail records API calls made to AWS services. Each record
captures who made the call, from where, when, what was called, and
whether it succeeded.

Log Format
----------
CloudTrail writes log files as JSON with a top-level "Records" array:

  {
    "Records": [
      {
        "eventVersion": "1.08",
        "userIdentity": {
          "type": "IAMUser",
          "principalId": "AIDIODR4TAW7CSEXAMPLE",
          "arn": "arn:aws:iam::123456789012:user/Alice",
          "accountId": "123456789012",
          "userName": "Alice"
        },
        "eventTime": "2024-01-15T10:23:45Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0",
        "requestParameters": {...},
        "responseElements": {...},
        "errorCode": "AccessDenied",         # present on failure
        "errorMessage": "...",               # present on failure
        "eventID": "a1b2c3d4-...",
        "eventType": "AwsApiCall"
      }
    ]
  }

This parser handles:
  - Single-record lines (one JSON object per line)
  - Multi-record files ({"Records": [...]} array wrapper)
  - Individual record objects without the Records wrapper

PS requirements covered
-----------------------
(b) Extract source-specific attributes — eventName, sourceIPAddress, userIdentity
(c) Normalize to common taxonomy — mapped to UnifiedEvent
(e) Plug-and-play — registered via register_parser()
"""

from __future__ import annotations

import json
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser

# CloudTrail eventName prefixes that indicate sensitive / attack-relevant actions
_HIGH_SEVERITY_PREFIXES = (
    "Delete", "Remove", "Revoke", "Detach", "Terminate", "Stop",
    "Disable", "Deregister", "Unauthorize",
)
_MEDIUM_SEVERITY_PREFIXES = (
    "Create", "Put", "Add", "Attach", "Authorize", "Enable",
    "Modify", "Update", "Set", "Associate",
)

# errorCode values → event_action
_ERROR_ACTION_MAP: dict[str, str] = {
    "AccessDenied": "deny",
    "UnauthorizedOperation": "deny",
    "AuthFailure": "deny",
    "InvalidClientTokenId": "deny",
    "NoCredentialProviders": "deny",
}


def _infer_severity(event_name: str, error_code: str | None) -> str:
    """Infer severity from event name prefix and error code."""
    if error_code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
        return "high"
    if any(event_name.startswith(p) for p in _HIGH_SEVERITY_PREFIXES):
        return "high"
    if any(event_name.startswith(p) for p in _MEDIUM_SEVERITY_PREFIXES):
        return "medium"
    return "informational"


def _parse_record(record: dict[str, Any], raw_log: str) -> ParseResult:
    """Convert a single CloudTrail record dict to a ParseResult."""
    if not isinstance(record, dict):
        return ParseResult(
            success=False,
            raw_log=raw_log,
            fields={},
            error="CloudTrail record is not a JSON object.",
            format_name="aws_cloudtrail",
        )

    # Core fields
    event_name = record.get("eventName", "")
    event_source = record.get("eventSource", "")
    event_time = record.get("eventTime", "")
    event_id = record.get("eventID", "")
    aws_region = record.get("awsRegion", "")
    src_ip = record.get("sourceIPAddress", "")
    user_agent = record.get("userAgent", "")
    error_code = record.get("errorCode")
    error_message = record.get("errorMessage")

    # Identity
    user_identity = record.get("userIdentity") or {}
    username = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or user_identity.get("arn", "").split("/")[-1]
        or None
    )
    account_id = user_identity.get("accountId")

    # Action
    if error_code:
        action = _ERROR_ACTION_MAP.get(error_code, "alert")
    else:
        action = "allow"

    severity = _infer_severity(event_name, error_code)

    # Category
    if "iam" in event_source or "sts" in event_source or "cognito" in event_source:
        category = "authentication"
    elif error_code in ("AccessDenied", "UnauthorizedOperation"):
        category = "threat"
    else:
        category = "network"

    extra: dict[str, Any] = {
        "event_id_cloudtrail": event_id,
        "event_source": event_source,
        "aws_region": aws_region,
        "account_id": account_id,
        "identity_type": user_identity.get("type"),
        "event_type": record.get("eventType"),
    }
    if error_code:
        extra["error_code"] = error_code
    if error_message:
        extra["error_message"] = error_message
    if record.get("requestParameters"):
        extra["request_parameters"] = json.dumps(record["requestParameters"])

    fields: dict[str, Any] = {
        "vendor": "amazon_aws",
        "device_type": "generic",
        "timestamp_raw": event_time,
        "src_ip": src_ip if src_ip and not src_ip.startswith("AWS") else None,
        "user_agent": user_agent or None,
        "username": username,
        "threat_signature_id": event_name,
        "threat_name": f"AWS:{event_name}",
        "event_action": action,
        "event_category": category,
        "severity": severity,
        "severity_label": error_code or "success",
        "extra_fields": extra,
    }

    return ParseResult(
        success=True,
        raw_log=raw_log,
        fields=fields,
        error=None,
        format_name="aws_cloudtrail",
    )


class CloudTrailParser(BaseLogParser):
    """
    Parses AWS CloudTrail JSON log entries.

    Handles three variants:
    1. {"Records": [...]} — full CloudTrail log file (returns first record)
    2. A single CloudTrail record JSON object per line
    3. A JSON array of records per line
    """

    @property
    def format_name(self) -> str:
        return "aws_cloudtrail"

    @property
    def description(self) -> str:
        return "AWS CloudTrail parser — API call records (JSON)"

    @property
    def vendor_hint(self) -> str | None:
        return "amazon_aws"

    def can_parse(self, sample: str) -> bool:
        """True if sample is JSON and looks like a CloudTrail record or Records wrapper."""
        stripped = sample.strip()
        if not (stripped.startswith("{") or stripped.startswith("[")):
            return False
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return False

        if isinstance(data, dict):
            # Records wrapper
            if "Records" in data:
                return True
            # Single record
            return "eventName" in data and "eventSource" in data
        if isinstance(data, list) and data:
            first = data[0]
            return isinstance(first, dict) and "eventName" in first

        return False

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"JSON parse error: {exc}",
                format_name=self.format_name,
            )

        # Handle Records wrapper — parse first record
        if isinstance(data, dict) and "Records" in data:
            records = data["Records"]
            if not records:
                return ParseResult(
                    success=False,
                    raw_log=line,
                    fields={},
                    error="CloudTrail Records array is empty.",
                    format_name=self.format_name,
                )
            return _parse_record(records[0], line)

        # Handle array of records — parse first
        if isinstance(data, list):
            if not data:
                return ParseResult(
                    success=False,
                    raw_log=line,
                    fields={},
                    error="CloudTrail JSON array is empty.",
                    format_name=self.format_name,
                )
            return _parse_record(data[0], line)

        # Single record object
        if isinstance(data, dict):
            return _parse_record(data, line)

        return ParseResult(
            success=False,
            raw_log=line,
            fields={},
            error="Unrecognised CloudTrail JSON structure.",
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(CloudTrailParser())
