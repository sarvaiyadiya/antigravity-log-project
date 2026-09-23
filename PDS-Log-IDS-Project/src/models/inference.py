"""
Serialized Model Inference Engine for ULPF.

Provides high-throughput, thread-safe, air-gapped machine learning inference
for canonical UnifiedEvents. Employs calibrated probabilities and explicit
abstention ("uncertain") for borderline predictions.
"""

from __future__ import annotations

import os
import threading
from typing import Sequence, Any

import joblib
import numpy as np

from src.models.feature_extractor import FeatureExtractor
from src.schema.unified_event import UnifiedEvent

DEFAULT_MODEL_PATH = "models/classifier.joblib"
DEFAULT_ABSTENTION_THRESHOLD = 0.60


class LogClassifier:
    """
    High-performance, calibrated log classifier and annotator.
    """

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL_PATH,
        abstention_threshold: float = DEFAULT_ABSTENTION_THRESHOLD,
    ) -> None:
        self.model_path = model_path
        self.abstention_threshold = abstention_threshold
        self.extractor = FeatureExtractor()
        self._lock = threading.Lock()

        self._load_or_bootstrap_model()

    def _load_or_bootstrap_model(self) -> None:
        """Loads the serialized model or trains a fresh lightweight baseline."""
        if os.path.exists(self.model_path):
            try:
                artifact = joblib.load(self.model_path)
                self.model = artifact["model"]
                self.scaler = artifact["scaler"]
                self.feature_names = artifact.get("feature_names", self.extractor.feature_names)
                self.model_version = artifact.get("model_version", "unknown")
                self.model_type = artifact.get("model_type", "calibrated_rf")
                self.metrics = artifact.get("metrics", {})
                self.trained_timestamp = artifact.get("trained_timestamp", "unknown")
                return
            except Exception as ex:
                print(f"[!] Error loading model from {self.model_path}: {ex}. Bootstrapping...")

        # Bootstrap fresh model if missing or corrupt
        from src.models.train import train_classifier
        print(f"[*] Bootstrapping fresh classifier artifact to {self.model_path}...")
        artifact = train_classifier(
            n_samples=1200,
            output_path=self.model_path,
        )
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_names = artifact.get("feature_names", self.extractor.feature_names)
        self.model_version = artifact.get("model_version", "bootstrap-v1")
        self.model_type = artifact.get("model_type", "rf")
        self.metrics = artifact.get("metrics", {})
        self.trained_timestamp = artifact.get("trained_timestamp", "unknown")

    def predict(self, event: UnifiedEvent) -> tuple[str, float]:
        """
        Classifies a single UnifiedEvent.
        Returns: (label, confidence) where label in {"attack", "benign", "uncertain"}.
        """
        feats = self.extractor.extract_single(event).reshape(1, -1)
        with self._lock:
            scaled = self.scaler.transform(feats)
            probs = self.model.predict_proba(scaled)[0]

        # Index 0: benign, Index 1: attack
        p_benign = float(probs[0])
        p_attack = float(probs[1])

        if p_attack >= p_benign:
            conf = p_attack
            label = "attack" if conf >= self.abstention_threshold else "uncertain"
        else:
            conf = p_benign
            label = "benign" if conf >= self.abstention_threshold else "uncertain"

        return label, round(conf, 4)

    def predict_batch(self, events: Sequence[UnifiedEvent]) -> list[tuple[str, float]]:
        """
        Vectorized high-throughput prediction for a batch of UnifiedEvents.
        """
        if not events:
            return []

        feats = self.extractor.extract_batch(events)
        with self._lock:
            scaled = self.scaler.transform(feats)
            probs = self.model.predict_proba(scaled)

        results: list[tuple[str, float]] = []
        for i in range(len(events)):
            p_benign = float(probs[i, 0])
            p_attack = float(probs[i, 1])

            if p_attack >= p_benign:
                conf = p_attack
                label = "attack" if conf >= self.abstention_threshold else "uncertain"
            else:
                conf = p_benign
                label = "benign" if conf >= self.abstention_threshold else "uncertain"

            results.append((label, round(conf, 4)))

        return results

    def annotate_event(self, event: UnifiedEvent) -> UnifiedEvent:
        """
        Directly populates weak_label and label_confidence on the UnifiedEvent.
        """
        label, conf = self.predict(event)
        event.weak_label = label
        event.label_confidence = conf
        return event

    def annotate_batch(self, events: list[UnifiedEvent]) -> list[UnifiedEvent]:
        """
        Annotates a list of UnifiedEvents in-place with ML predictions.
        """
        predictions = self.predict_batch(events)
        for ev, (label, conf) in zip(events, predictions):
            ev.weak_label = label
            ev.label_confidence = conf
        return events

    def get_model_info(self) -> dict[str, Any]:
        """Returns metadata regarding the loaded classifier model."""
        return {
            "model_version": self.model_version,
            "model_type": self.model_type,
            "feature_dim": len(self.feature_names),
            "abstention_threshold": self.abstention_threshold,
            "trained_timestamp": self.trained_timestamp,
            "metrics": self.metrics,
        }


# Global thread-safe singleton instance
_GLOBAL_CLASSIFIER: LogClassifier | None = None
_GLOBAL_LOCK = threading.Lock()


def get_classifier(model_path: str = DEFAULT_MODEL_PATH) -> LogClassifier:
    """Provides access to the shared LogClassifier instance."""
    global _GLOBAL_CLASSIFIER
    if _GLOBAL_CLASSIFIER is None:
        with _GLOBAL_LOCK:
            if _GLOBAL_CLASSIFIER is None:
                _GLOBAL_CLASSIFIER = LogClassifier(model_path=model_path)
    return _GLOBAL_CLASSIFIER
