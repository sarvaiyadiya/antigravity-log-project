"""
Feature Extractor for the Universal Log Pre-processing Framework (ULPF).

Extracts a standardized 24-dimensional numerical feature vector from any canonical
UnifiedEvent regardless of source vendor or device format. Designed for both
real-time, single-event streaming inference and high-throughput batch training.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Sequence, Any

import numpy as np

from src.schema.unified_event import (
    UnifiedEvent,
    EventSeverity,
    EventAction,
)

# Standardized 24-dimensional feature vector specification
FEATURE_NAMES: list[str] = [
    "src_port_val",
    "is_src_privileged",
    "is_src_registered",
    "is_src_dynamic",
    "dst_port_val",
    "is_dst_privileged",
    "is_dst_web",
    "is_dst_remote_admin",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "severity_num",
    "action_deny",
    "action_allow",
    "hour_sin",
    "hour_cos",
    "weekday_sin",
    "weekday_cos",
    "is_weekend",
    "is_src_private",
    "threat_intel_score",
    "has_mitre_tag",
    "user_agent_len_log1p",
]

# Common ports for classification heuristics
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888}
REMOTE_ADMIN_PORTS = {22, 23, 3389, 445, 135, 139, 5900, 5985, 5986}
DENIED_ACTIONS = {
    EventAction.DENY,
    EventAction.DROP,
    EventAction.BLOCK,
    EventAction.RESET,
}


class FeatureExtractor:
    """
    Extracts tabular numerical features from UnifiedEvent instances.
    Guaranteed zero exceptions on missing or malformed fields.
    """

    def __init__(self) -> None:
        self.feature_names = list(FEATURE_NAMES)
        self.feature_dim = len(FEATURE_NAMES)

    def extract_single(self, event: UnifiedEvent) -> np.ndarray:
        """
        Extract a 1D float32 numpy array of shape (24,) from a single UnifiedEvent.
        """
        feats = np.zeros(self.feature_dim, dtype=np.float32)

        # 1. Source Port features
        src_port = event.src_port
        if src_port is not None and isinstance(src_port, (int, float)) and 0 <= src_port <= 65535:
            sp = float(src_port)
            feats[0] = sp / 65535.0  # normalized [0, 1]
            feats[1] = 1.0 if sp <= 1023 else 0.0
            feats[2] = 1.0 if 1024 <= sp <= 49151 else 0.0
            feats[3] = 1.0 if sp >= 49152 else 0.0

        # 2. Destination Port features
        dst_port = event.dst_port
        if dst_port is not None and isinstance(dst_port, (int, float)) and 0 <= dst_port <= 65535:
            dp = int(dst_port)
            feats[4] = float(dp) / 65535.0
            feats[5] = 1.0 if dp <= 1023 else 0.0
            feats[6] = 1.0 if dp in WEB_PORTS else 0.0
            feats[7] = 1.0 if dp in REMOTE_ADMIN_PORTS else 0.0

        # 3. Protocol one-hot
        proto = (event.protocol or "").lower().strip()
        if proto == "tcp":
            feats[8] = 1.0
        elif proto == "udp":
            feats[9] = 1.0
        elif proto == "icmp":
            feats[10] = 1.0
        elif proto:
            feats[11] = 1.0

        # 4. Severity
        sev = event.severity
        if isinstance(sev, EventSeverity):
            feats[12] = float(sev.value) / 10.0
        elif isinstance(sev, int):
            feats[12] = min(max(float(sev) / 10.0, 0.0), 1.0)

        # 5. Action
        action = event.event_action
        if action in DENIED_ACTIONS:
            feats[13] = 1.0
        elif action == EventAction.ALLOW:
            feats[14] = 1.0

        # 6. Temporal cyclical features
        dt = event.timestamp_utc or event.ingest_timestamp
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hour_frac = dt.hour + dt.minute / 60.0 + dt.second / 3600.0
            weekday_frac = dt.weekday() + hour_frac / 24.0

            feats[15] = math.sin(2.0 * math.pi * hour_frac / 24.0)
            feats[16] = math.cos(2.0 * math.pi * hour_frac / 24.0)
            feats[17] = math.sin(2.0 * math.pi * weekday_frac / 7.0)
            feats[18] = math.cos(2.0 * math.pi * weekday_frac / 7.0)
            feats[19] = 1.0 if dt.weekday() >= 5 else 0.0

        # 7. Contextual Enrichment (P4)
        if event.is_src_private is True:
            feats[20] = 1.0

        if event.threat_intel_score is not None:
            feats[21] = min(max(float(event.threat_intel_score), 0.0), 1.0)
        elif event.is_malicious is True:
            feats[21] = 1.0

        if event.mitre_technique_id:
            feats[22] = 1.0

        # 8. User-Agent / payload heuristics
        ua = event.user_agent or ""
        if ua:
            feats[23] = math.log1p(len(ua))

        return feats

    def extract_batch(self, events: Sequence[UnifiedEvent]) -> np.ndarray:
        """
        Extract a 2D float32 numpy array of shape (N, 24) from a list of UnifiedEvents.
        """
        n = len(events)
        out = np.empty((n, self.feature_dim), dtype=np.float32)
        for i, ev in enumerate(events):
            out[i] = self.extract_single(ev)
        return out
