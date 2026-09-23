"""
Unit and integration tests for ULPF Machine Learning Classification & Inference.
Verifies feature extraction, model training, serialized inference, abstention,
evaluation metrics, and end-to-end pipeline ML annotation.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from src.models.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.models.inference import LogClassifier, get_classifier
from src.models.train import train_classifier, generate_synthetic_events
from src.models.evaluate import evaluate_classifier
from src.pipeline import ingest
from src.schema.unified_event import (
    UnifiedEvent,
    EventSeverity,
    EventAction,
    EventCategory,
    SourceType,
)


@pytest.fixture
def sample_attack_event() -> UnifiedEvent:
    return UnifiedEvent.create(
        raw_log="Sample attack log",
        format_name="cisco_asa",
        source_id="test_sensor",
        timestamp_utc=datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc),
        src_ip="203.0.113.55",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        event_action=EventAction.DENY,
        severity=EventSeverity.CRITICAL,
        is_src_private=False,
        threat_intel_score=0.95,
        is_malicious=True,
        mitre_technique_id="T1190",
        user_agent="sqlmap/1.6.4",
    )


@pytest.fixture
def sample_benign_event() -> UnifiedEvent:
    return UnifiedEvent.create(
        raw_log="Sample benign log",
        format_name="syslog",
        source_id="test_sensor",
        timestamp_utc=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.1.20",
        dst_ip="10.0.0.5",
        src_port=49876,
        dst_port=80,
        protocol="tcp",
        event_action=EventAction.ALLOW,
        severity=EventSeverity.INFORMATIONAL,
        is_src_private=True,
        threat_intel_score=0.0,
        is_malicious=False,
    )


class TestFeatureExtractor:
    def test_feature_extractor_dimensions_and_types(self, sample_attack_event):
        extractor = FeatureExtractor()
        feats = extractor.extract_single(sample_attack_event)

        assert isinstance(feats, np.ndarray)
        assert feats.shape == (24,)
        assert feats.dtype == np.float32
        assert np.all(np.isfinite(feats))

    def test_feature_extractor_handles_sparse_events(self):
        sparse_event = UnifiedEvent.create(
            raw_log="sparse log line",
            format_name="generic",
            source_id="test",
        )
        extractor = FeatureExtractor()
        feats = extractor.extract_single(sparse_event)

        assert feats.shape == (24,)
        assert np.all(np.isfinite(feats))
        # Missing fields should default to 0.0
        assert feats[0] == 0.0  # src port
        assert feats[4] == 0.0  # dst port

    def test_feature_extractor_batch_extraction(self, sample_attack_event, sample_benign_event):
        extractor = FeatureExtractor()
        events = [sample_attack_event, sample_benign_event, sample_attack_event]
        batch = extractor.extract_batch(events)

        assert batch.shape == (3, 24)
        assert batch.dtype == np.float32
        assert np.all(np.isfinite(batch))

    def test_feature_extractor_attribute_mapping(self, sample_attack_event):
        extractor = FeatureExtractor()
        feats = extractor.extract_single(sample_attack_event)

        # src_port 54321 is dynamic (>= 49152)
        assert feats[3] == 1.0  # is_src_dynamic
        # dst_port 443 is web
        assert feats[6] == 1.0  # is_dst_web
        # protocol tcp
        assert feats[8] == 1.0  # proto_tcp
        # action DENY
        assert feats[13] == 1.0  # action_deny
        # threat intel score 0.95
        assert abs(feats[21] - 0.95) < 1e-4
        # has mitre tag
        assert feats[22] == 1.0


class TestModelTrainingAndInference:
    def test_synthetic_event_generation(self):
        events, labels = generate_synthetic_events(n_samples=100, attack_ratio=0.5, random_seed=42)
        assert len(events) == 100
        assert len(labels) == 100
        assert set(labels).issubset({0, 1})
        assert all(isinstance(ev, UnifiedEvent) for ev in events)

    def test_model_training_and_serialization(self, tmp_path):
        model_file = str(tmp_path / "test_model.joblib")
        meta_file = str(tmp_path / "test_meta.json")

        artifact = train_classifier(
            n_samples=250,
            model_type="rf",
            output_path=model_file,
            metadata_path=meta_file,
            random_seed=42,
        )

        assert os.path.exists(model_file)
        assert os.path.exists(meta_file)
        assert "metrics" in artifact
        assert artifact["metrics"]["accuracy"] >= 0.85
        assert artifact["metrics"]["f1"] >= 0.85

    def test_log_classifier_inference(self, sample_attack_event, sample_benign_event):
        # Using global classifier or bootstrap
        classifier = get_classifier()
        assert classifier is not None

        label_attack, conf_attack = classifier.predict(sample_attack_event)
        assert label_attack in {"attack", "benign", "uncertain"}
        assert 0.0 <= conf_attack <= 1.0
        assert label_attack == "attack"

        label_benign, conf_benign = classifier.predict(sample_benign_event)
        assert label_benign in {"attack", "benign", "uncertain"}
        assert 0.0 <= conf_benign <= 1.0
        assert label_benign == "benign"

    def test_log_classifier_abstention(self, sample_attack_event):
        # Create classifier with impossibly high confidence threshold to force abstention
        classifier = LogClassifier(abstention_threshold=0.9999)
        label, conf = classifier.predict(sample_attack_event)
        assert label == "uncertain"

    def test_annotate_event(self, sample_attack_event):
        classifier = get_classifier()
        ev = classifier.annotate_event(sample_attack_event)
        assert ev.weak_label is not None
        assert ev.label_confidence is not None
        assert 0.0 <= ev.label_confidence <= 1.0

    def test_annotate_batch(self, sample_attack_event, sample_benign_event):
        classifier = get_classifier()
        events = [sample_attack_event, sample_benign_event]
        annotated = classifier.annotate_batch(events)
        assert len(annotated) == 2
        for ev in annotated:
            assert ev.weak_label is not None
            assert ev.label_confidence is not None

    def test_evaluate_classifier_output(self, tmp_path):
        report_file = str(tmp_path / "test_eval_report.json")
        report = evaluate_classifier(
            n_test_samples=150,
            report_path=report_file,
            random_seed=777,
        )
        assert os.path.exists(report_file)
        assert "evaluation_metrics" in report
        metrics = report["evaluation_metrics"]
        assert "accuracy" in metrics
        assert "f1" in metrics
        assert "mcc" in metrics
        assert "brier_score" in metrics
        assert "confusion_matrix" in metrics


class TestPipelineClassifierIntegration:
    def test_ingest_with_classify_flag(self, tmp_path):
        out_file = tmp_path / "classified_events.jsonl"
        source_file = "configs/sources/cisco_asa.yaml"

        summary = ingest(
            source_config=source_file,
            output_file=out_file,
            classify=True,
            verbose=False,
        )

        assert summary["parsed_ok"] > 0
        assert summary["ml_classified"] is True
        assert out_file.exists()

        import json
        with open(out_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) > 0
        for ev in lines:
            assert "weak_label" in ev
            assert ev["weak_label"] in {"attack", "benign", "uncertain"}
            assert "label_confidence" in ev
            assert ev["label_confidence"] is not None
