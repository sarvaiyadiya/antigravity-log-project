"""
MITRE ATT&CK Taxonomy Mapper for ULPF
=====================================
Maps raw threat signatures, vulnerability IDs, event actions, and log payloads
to the standardized MITRE ATT&CK Enterprise Matrix (Tactics, Techniques, and IDs).

PS requirement: "Security teams often spend substantial effort... universal and extensible log structuring"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("ulpf.enrichment.mitre_mapper")


@dataclass(frozen=True)
class MitreResult:
    """MITRE ATT&CK classification metadata."""
    tactic: str | None = None               # e.g. "Initial Access", "Credential Access"
    tactic_id: str | None = None            # e.g. "TA0001", "TA0006"
    technique_id: str | None = None         # e.g. "T1190", "T1110"
    technique_name: str | None = None       # e.g. "Exploit Public-Facing Application"


# Curated mapping rules: (regex_pattern, tactic_name, tactic_id, tech_id, tech_name)
_ATTACK_PATTERNS: list[tuple[re.Pattern, str, str, str, str]] = [
    # ── Initial Access / Web Exploits (T1190) ──────────────────────────────
    (
        re.compile(r"sql\s*injection|\bsqli\b|or\s+1\s*=\s*1|union\s+select|path\s*traversal|\.\./|\bxss\b|cross[- ]site\s*script|apache\s*path|web[- ]attack|remote\s*code\s*execution|\brce\b", re.IGNORECASE),
        "Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application"
    ),

    # ── Credential Access / Brute Force (T1110) ────────────────────────────
    (
        re.compile(r"brute\s*force|failed\s*logon|login\s*failure|eventid\s*4625|password\s*spray|credential\s*stuffing|auth_failed|auth\s*failure", re.IGNORECASE),
        "Credential Access", "TA0006", "T1110", "Brute Force"
    ),

    # ── Discovery / Network Probing (T1046) ────────────────────────────────
    (
        re.compile(r"port\s*scan|\bscan\b|reconnaissance|shodan|masscan|service\s*discovery|icmp\s*ping|host\s*sweep|\bprobe\b", re.IGNORECASE),
        "Discovery", "TA0007", "T1046", "Network Service Discovery"
    ),

    # ── Execution / Command Interpreter (T1059) ───────────────────────────
    (
        re.compile(r"cmd\.php|powershell|cmd\.exe|/bin/sh|/bin/bash|command\s*injection|script\s*interpreter|reverse\s*shell", re.IGNORECASE),
        "Execution", "TA0002", "T1059", "Command and Scripting Interpreter"
    ),

    # ── Command and Control (T1071) ────────────────────────────────────────
    (
        re.compile(r"\bc2\b|command\s*and\s*control|trojan|botnet|dns\s*tunnel|beacon|cobalt\s*strike|mirai", re.IGNORECASE),
        "Command and Control", "TA0011", "T1071", "Application Layer Protocol"
    ),

    # ── Impact / Denial of Service (T1498) ─────────────────────────────────
    (
        re.compile(r"denial\s*of\s*service|dos|ddos|syn\s*flood|udp\s*flood|bandwidth\s*exhaust", re.IGNORECASE),
        "Impact", "TA0040", "T1498", "Network Denial of Service"
    ),

    # ── Privilege Escalation / Cloud IAM (T1078) ───────────────────────────
    (
        re.compile(r"createaccesskey|accessdenied|assume_role|privilege\s*escalation|unauthorized_api", re.IGNORECASE),
        "Privilege Escalation", "TA0004", "T1078", "Valid Accounts"
    ),
]


class MitreMapper:
    """Classifies log events into MITRE ATT&CK Tactics and Techniques."""

    def __init__(self) -> None:
        self._patterns = _ATTACK_PATTERNS

    def map_event(
        self,
        threat_name: str | None = None,
        raw_log: str | None = None,
        event_name: str | None = None,
        action: str | None = None,
        http_url: str | None = None,
    ) -> MitreResult:
        """
        Evaluate candidate fields against MITRE ATT&CK signature rules.
        Returns a MitreResult with tactic, technique_id, and technique_name.
        """
        # Combine fields for pattern scanning
        text_corpus = " ".join([
            str(threat_name or ""),
            str(event_name or ""),
            str(http_url or ""),
            str(raw_log or ""),
        ])

        if not text_corpus.strip():
            return MitreResult()

        for pattern, tactic, tactic_id, tech_id, tech_name in self._patterns:
            if pattern.search(text_corpus):
                return MitreResult(
                    tactic=tactic,
                    tactic_id=tactic_id,
                    technique_id=tech_id,
                    technique_name=tech_name,
                )

        # Fallback: if firewall blocked traffic but no specific signature
        if action and any(act in action.lower() for act in ("deny", "block", "drop")):
            return MitreResult(
                tactic="Initial Access",
                tactic_id="TA0001",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
            )

        return MitreResult()
