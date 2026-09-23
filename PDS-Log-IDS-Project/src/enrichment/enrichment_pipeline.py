"""
Enrichment Pipeline for ULPF
============================
Chains GeoIP/ASN resolution, threat intelligence scoring, and MITRE ATT&CK
classification into an end-to-end enrichment processor for UnifiedEvent.
"""

from __future__ import annotations

import logging
from typing import Any

from src.schema.unified_event import UnifiedEvent
from .geoip import GeoIPEnricher
from .threat_intel import ThreatIntelEnricher
from .mitre_mapper import MitreMapper

logger = logging.getLogger("ulpf.enrichment.pipeline")


class EnrichmentPipeline:
    """Master coordinator that enriches UnifiedEvent instances."""

    def __init__(
        self,
        geoip_enricher: GeoIPEnricher | None = None,
        threat_intel_enricher: ThreatIntelEnricher | None = None,
        mitre_mapper: MitreMapper | None = None,
    ) -> None:
        self.geoip = geoip_enricher or GeoIPEnricher()
        self.threat_intel = threat_intel_enricher or ThreatIntelEnricher()
        self.mitre = mitre_mapper or MitreMapper()

    def enrich(self, event: UnifiedEvent) -> UnifiedEvent:
        """
        Enrich a UnifiedEvent instance with GeoIP, Threat Intel, and MITRE ATT&CK metadata.
        Safe: modifies event non-destructively and handles missing or malformed fields cleanly.
        """
        # 1. GeoIP & ASN Resolution
        if event.src_ip:
            src_geo = self.geoip.lookup(event.src_ip)
            event.src_country = src_geo.country
            event.src_city = src_geo.city
            event.src_asn = src_geo.asn
            event.is_src_private = src_geo.is_private

        if event.dst_ip:
            dst_geo = self.geoip.lookup(event.dst_ip)
            event.dst_country = dst_geo.country

        # 2. Threat Intelligence Reputation Check
        ti_result = None
        if event.src_ip:
            ti_result = self.threat_intel.check(event.src_ip)
        elif event.dst_ip:
            ti_result = self.threat_intel.check(event.dst_ip)

        if ti_result and ti_result.score > 0.0:
            event.threat_intel_score = ti_result.score
            event.threat_intel_source = ti_result.source
            event.is_malicious = ti_result.is_malicious

            # Adjust weak label if threat intelligence confirms malicious
            if ti_result.is_malicious:
                if not event.weak_label or event.weak_label == "uncertain":
                    event.weak_label = "attack"
                if not event.label_confidence or event.label_confidence < 0.85:
                    event.label_confidence = max(event.label_confidence or 0.0, 0.85)

        # 3. MITRE ATT&CK Classification
        mitre_res = self.mitre.map_event(
            threat_name=event.threat_name or event.threat_signature_name,
            raw_log=event.raw_log,
            action=str(event.event_action.value if hasattr(event.event_action, "value") else event.event_action),
            http_url=event.http_url,
        )
        if mitre_res.technique_id:
            event.mitre_tactic = mitre_res.tactic
            event.mitre_technique_id = mitre_res.technique_id
            event.mitre_technique_name = mitre_res.technique_name

        return event


# Singleton instance
_GLOBAL_ENRICHMENT_PIPELINE: EnrichmentPipeline | None = None


def get_enrichment_pipeline() -> EnrichmentPipeline:
    """Return the global EnrichmentPipeline singleton."""
    global _GLOBAL_ENRICHMENT_PIPELINE
    if _GLOBAL_ENRICHMENT_PIPELINE is None:
        _GLOBAL_ENRICHMENT_PIPELINE = EnrichmentPipeline()
    return _GLOBAL_ENRICHMENT_PIPELINE
