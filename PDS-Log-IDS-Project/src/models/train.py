"""
Model Training Module for ULPF.

Trains a leakage-safe, calibrated classifier (RandomForest / LogisticRegression)
on normalized UnifiedEvent perimeter network telemetry.
Exports serialized artifact to models/classifier.joblib and metadata to models/metadata.json.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.models.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.schema.unified_event import (
    UnifiedEvent,
    EventSeverity,
    EventAction,
    EventCategory,
    SourceType,
)

MODEL_VERSION = "ulpf-rf-v1.0"
DEFAULT_MODEL_PATH = "models/classifier.joblib"
DEFAULT_METADATA_PATH = "models/metadata.json"


def generate_synthetic_events(
    n_samples: int = 3000,
    attack_ratio: float = 0.5,
    random_seed: int = 42,
) -> Tuple[list[UnifiedEvent], np.ndarray]:
    """
    Generates a balanced, realistic corpus of UnifiedEvents spanning
    multiple perimeter device formats with ground-truth binary labels
    (1: attack, 0: benign).
    """
    rng = random.Random(random_seed)
    events: list[UnifiedEvent] = []
    labels: list[int] = []

    base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Common attacker signatures & user agents
    attack_uas = [
        "gobuster/3.1.0",
        "sqlmap/1.6.4#stable",
        "nikto/2.1.6",
        "Masscan/1.3.2",
        "Mozilla/5.0 (Hydra-SSH-Brute)",
        "curl/7.68.0",
    ]
    benign_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ]

    formats = [
        "cisco_asa",
        "paloalto_traffic",
        "paloalto_threat",
        "snort",
        "syslog",
        "cloudtrail",
        "windows_event",
        "cef",
        "json",
    ]

    for i in range(n_samples):
        is_attack = rng.random() < attack_ratio
        event_time = base_time + timedelta(seconds=i * 15 + rng.randint(0, 10))

        fmt = rng.choice(formats)

        if is_attack:
            # Adversarial perimeter patterns
            src_ip = f"{rng.randint(45, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            dst_ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
            src_port = rng.randint(30000, 65535)
            # Targets sensitive admin / web / scanning ports
            dst_port = rng.choice([22, 23, 80, 443, 445, 1433, 3389, 8080, rng.randint(1, 1024)])
            proto = rng.choice(["tcp", "tcp", "udp", "icmp"])
            action = rng.choice([EventAction.DENY, EventAction.DROP, EventAction.BLOCK, EventAction.ALERT])
            severity = rng.choice([EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL])
            threat_intel_score = rng.uniform(0.65, 1.0)
            is_malicious = True
            mitre_id = rng.choice(["T1190", "T1110", "T1046", "T1071", "T1059"])
            user_agent = rng.choice(attack_uas) if rng.random() < 0.7 else None
            is_src_priv = False
            raw_log = f"ATTACK: {fmt} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto} {action.value} sev={severity.value}"
            label = 1
        else:
            # Benign operational traffic
            is_internal = rng.random() < 0.6
            if is_internal:
                src_ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
                is_src_priv = True
            else:
                src_ip = f"{rng.randint(11, 200)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                is_src_priv = False

            dst_ip = f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
            src_port = rng.randint(1024, 65535)
            dst_port = rng.choice([80, 443, 53, 123, 8080])
            proto = rng.choice(["tcp", "tcp", "udp"])
            action = EventAction.ALLOW
            severity = rng.choice([EventSeverity.INFORMATIONAL, EventSeverity.LOW])
            threat_intel_score = rng.uniform(0.0, 0.15)
            is_malicious = False
            mitre_id = None
            user_agent = rng.choice(benign_uas) if rng.random() < 0.5 else None
            raw_log = f"BENIGN: {fmt} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto} {action.value} sev={severity.value}"
            label = 0

        ev = UnifiedEvent.create(
            raw_log=raw_log,
            format_name=fmt,
            source_id="synthetic_generator",
            timestamp_utc=event_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            event_action=action,
            severity=severity,
            event_category=EventCategory.THREAT if is_attack else EventCategory.NETWORK,
            device_type=SourceType.FIREWALL,
            is_src_private=is_src_priv,
            threat_intel_score=threat_intel_score,
            is_malicious=is_malicious,
            mitre_technique_id=mitre_id,
            user_agent=user_agent,
        )
        events.append(ev)
        labels.append(label)

    return events, np.array(labels, dtype=np.int32)


def train_classifier(
    n_samples: int = 3000,
    model_type: str = "rf",
    output_path: str = DEFAULT_MODEL_PATH,
    metadata_path: str = DEFAULT_METADATA_PATH,
    random_seed: int = 42,
) -> dict[str, Any]:
    """
    Trains the calibrated classification pipeline and saves model artifacts.
    """
    print(f"[*] Generating {n_samples} training events across perimeter formats...")
    events, y = generate_synthetic_events(n_samples=n_samples, random_seed=random_seed)

    extractor = FeatureExtractor()
    print(f"[*] Extracting {extractor.feature_dim} features per event...")
    X = extractor.extract_batch(events)

    # 70% Train, 15% Validation, 15% Test
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=random_seed, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_seed, stratify=y_temp
    )

    print(f"[*] Split sizes: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Train base model
    if model_type.lower() == "lr":
        print("[*] Training Logistic Regression baseline...")
        base_clf = LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=random_seed,
        )
    else:
        print("[*] Training Random Forest Classifier...")
        base_clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1,
        )

    # Fit base classifier
    base_clf.fit(X_train_scaled, y_train)

    # Calibrate probabilities using Sigmoid / Platt Scaling on validation set
    print("[*] Performing probability calibration...")
    try:
        from sklearn.frozen import FrozenEstimator
        calibrated_clf = CalibratedClassifierCV(
            estimator=FrozenEstimator(base_clf),
            method="sigmoid",
        )
    except ImportError:
        calibrated_clf = CalibratedClassifierCV(
            estimator=base_clf,
            method="sigmoid",
            cv="prefit",
        )
    calibrated_clf.fit(X_val_scaled, y_val)

    # Evaluate on held-out test split
    y_pred = calibrated_clf.predict(X_test_scaled)
    y_prob = calibrated_clf.predict_proba(X_test_scaled)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "mcc": float(matthews_corrcoef(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "brier_score": float(brier_score_loss(y_test, y_prob)),
    }

    print("\n--- Test Set Evaluation Results ---")
    for k, v in metrics.items():
        print(f"  {k:<20}: {v:.4f}")

    # Build export artifact dictionary
    artifact = {
        "model_version": MODEL_VERSION,
        "model_type": model_type,
        "model": calibrated_clf,
        "scaler": scaler,
        "feature_names": extractor.feature_names,
        "feature_dim": extractor.feature_dim,
        "abstention_threshold": 0.60,
        "trained_timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
    }

    # Ensure output directories exist
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(metadata_path) or ".", exist_ok=True)

    print(f"\n[*] Saving serialized model to: {output_path}")
    joblib.dump(artifact, output_path)

    metadata = {
        "version": MODEL_VERSION,
        "model_type": model_type,
        "training_samples": n_samples,
        "feature_names": extractor.feature_names,
        "test_metrics": metrics,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[*] Saved training metadata to: {metadata_path}")

    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Model Training CLI")
    parser.add_argument(
        "--samples",
        type=int,
        default=3000,
        help="Number of synthetic training samples (default: 3000)",
    )
    parser.add_argument(
        "--model-type",
        choices=["rf", "lr"],
        default="rf",
        help="Model architecture: rf (RandomForest) or lr (LogisticRegression)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_MODEL_PATH,
        help=f"Path to save serialized model (default: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--metadata",
        default=DEFAULT_METADATA_PATH,
        help=f"Path to save model metadata (default: {DEFAULT_METADATA_PATH})",
    )

    args = parser.parse_args()
    train_classifier(
        n_samples=args.samples,
        model_type=args.model_type,
        output_path=args.output,
        metadata_path=args.metadata,
    )


if __name__ == "__main__":
    main()
