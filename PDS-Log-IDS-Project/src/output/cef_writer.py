"""
CEF Writer — outputs normalized events in ArcSight Common Event Format.

PS requirement (g): "Efficient SIEM and Data Lake integration."

CEF output is accepted directly by:
- Splunk (via syslog or file input)
- IBM QRadar (syslog CEF input)
- ArcSight ESM
- LogRhythm
- Microsoft Sentinel

Format
------
CEF:0|ULPF|UniversalLogFramework|1.0|<SigID>|<Name>|<Severity>|extensions

Usage
-----
writer = CefWriter(output_path)
with writer:
    writer.write(event)
    writer.write_batch(events)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO, Iterator

from src.schema.unified_event import EventSeverity, UnifiedEvent

_CEF_VENDOR = "ULPF"
_CEF_PRODUCT = "UniversalLogFramework"
_CEF_VERSION = "1.0"
_CEF_FORMAT_VERSION = 0

# Map UES EventSeverity → CEF numeric severity (0-10)
_SEVERITY_CEF_MAP: dict[int, int] = {
    EventSeverity.UNKNOWN.value: 0,
    EventSeverity.INFORMATIONAL.value: 1,
    EventSeverity.LOW.value: 3,
    EventSeverity.MEDIUM.value: 5,
    EventSeverity.HIGH.value: 7,
    EventSeverity.CRITICAL.value: 9,
    EventSeverity.EMERGENCY.value: 10,
}


class CefWriter:
    """
    Writes UnifiedEvent objects as CEF-formatted lines.

    Parameters
    ----------
    output : path string, Path, or None (defaults to stdout).
    append : if True, open in append mode; otherwise write mode.
    """

    def __init__(
        self,
        output: str | Path | None = None,
        append: bool = False,
    ) -> None:
        self._output_path = Path(output) if output else None
        self._append = append
        self._file: IO[str] | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "CefWriter":
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def open(self) -> None:
        if self._output_path:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if self._append else "w"
            self._file = self._output_path.open(
                mode, encoding="utf-8", newline="\n"
            )
        else:
            self._file = sys.stdout

    def close(self) -> None:
        if self._file and self._file is not sys.stdout:
            self._file.close()
        self._file = None

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def write(self, event: UnifiedEvent) -> None:
        """Write a single event as one CEF line."""
        if self._file is None:
            raise RuntimeError("Writer is not open. Use 'with CefWriter(...) as w:'")
        line = self.format(event)
        self._file.write(line + "\n")

    def write_batch(self, events: Iterator[UnifiedEvent]) -> int:
        """Write multiple events. Returns count written."""
        count = 0
        for event in events:
            self.write(event)
            count += 1
        return count

    # ------------------------------------------------------------------
    # CEF formatting
    # ------------------------------------------------------------------

    def format(self, event: UnifiedEvent) -> str:
        """Convert a UnifiedEvent to a CEF string."""
        sig_id = event.threat_signature_id or event.event_uid[:8]
        name = self._escape_header(
            event.threat_name or event.event_category.value
        )
        severity_num = _SEVERITY_CEF_MAP.get(
            event.severity.value if event.severity else 0, 0
        )

        header = (
            f"CEF:{_CEF_FORMAT_VERSION}"
            f"|{_CEF_VENDOR}"
            f"|{_CEF_PRODUCT}"
            f"|{_CEF_VERSION}"
            f"|{self._escape_header(sig_id)}"
            f"|{name}"
            f"|{severity_num}"
        )

        extensions = self._build_extensions(event)
        return f"{header}|{extensions}"

    @staticmethod
    def _escape_header(value: str) -> str:
        """Escape pipe and backslash in CEF header fields."""
        return str(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _escape_extension(value: str) -> str:
        """Escape = and \n in CEF extension values."""
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )

    def _build_extensions(self, event: UnifiedEvent) -> str:
        """Build the CEF extension field string."""
        parts: list[str] = []

        def add(key: str, value: object) -> None:
            if value is not None:
                parts.append(f"{key}={self._escape_extension(str(value))}")

        # Standard CEF extension fields
        add("eventId", event.event_uid)
        add("cs1", event.record_hash)
        add("cs1Label", "record_hash")

        if event.timestamp_utc:
            rt_ms = int(event.timestamp_utc.timestamp() * 1000)
            add("rt", str(rt_ms))

        add("src", event.src_ip)
        add("spt", event.src_port)
        add("dst", event.dst_ip)
        add("dpt", event.dst_port)
        add("proto", event.protocol)
        add("act", event.event_action.value if event.event_action else None)
        add("requestMethod", event.http_method)
        add("request", event.http_url)
        add("requestClientApplication", event.user_agent)
        add("suser", event.username)
        add("dvchost", event.device_hostname)
        add("dvc", event.device_ip)

        # ULPF-specific extension fields
        add("cs2", event.weak_label)
        add("cs2Label", "weak_label")
        add("cn1", event.label_confidence)
        add("cn1Label", "label_confidence")
        add("cs3", event.evidence_codes)
        add("cs3Label", "evidence_codes")
        add("cs4", event.format_name)
        add("cs4Label", "format_name")
        add("cs5", event.source_id)
        add("cs5Label", "source_id")
        add("msg", event.raw_log[:512] if event.raw_log else None)

        return " ".join(parts)
