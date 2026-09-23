"""
Model Evaluation and Diagnostic Module for ULPF.

Computes comprehensive classification metrics (discrimination, calibration,
confusion matrix, and abstention rate) across held-out perimeter telemetry.
Exports detailed audit reports to outputs/model_evaluation_report.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.models.feature_extractor import FeatureExtractor
from src.models.inference import LogClassifier, DEFAULT_MODEL_PATH
from src.models.train import generate_synthetic_events

DEFAULT_REPORT_PATH = "outputs/model_evaluation_report.json"


def evaluate_classifier(
    model_path: str = DEFAULT_MODEL_PATH,
    n_test_samples: int = 1000,
    report_path: str = DEFAULT_REPORT_PATH,
    random_seed: int = 999,  # Distinct seed for uncorrupted test evaluation
) -> dict[str, Any]:
    """
    Evaluates the model against held-out perimeter events and writes a structured report.
    """
    print(f"[*] Loading model for evaluation: {model_path}")
    classifier = LogClassifier(model_path=model_path)

    print(f"[*] Generating {n_test_samples} unseen evaluation events across perimeter formats...")
    events, y_true = generate_synthetic_events(
        n_samples=n_test_samples,
        random_seed=random_seed,
    )

    # Perform inference via the production engine
    predictions = classifier.predict_batch(events)
    labels = [p[0] for p in predictions]
    confidences = [p[1] for p in predictions]

    # Evaluate raw probabilities for calibration & ROC-AUC
    extractor = classifier.extractor
    feats = extractor.extract_batch(events)
    scaled_feats = classifier.scaler.transform(feats)
    probs = classifier.model.predict_proba(scaled_feats)[:, 1]

    # Map labels: attack=1, benign=0, uncertain=-1
    binary_preds = []
    uncertain_count = 0
    for lbl, prob in zip(labels, probs):
        if lbl == "uncertain":
            uncertain_count += 1
            # Fall back to argmax for strict binary metric comparison
            binary_preds.append(1 if prob >= 0.5 else 0)
        elif lbl == "attack":
            binary_preds.append(1)
        else:
            binary_preds.append(0)

    binary_preds = np.array(binary_preds, dtype=np.int32)

    cm = confusion_matrix(y_true, binary_preds).tolist()
    tn, fp, fn, tp = confusion_matrix(y_true, binary_preds).ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_true, binary_preds)),
        "precision": float(precision_score(y_true, binary_preds, zero_division=0)),
        "recall": float(recall_score(y_true, binary_preds, zero_division=0)),
        "f1": float(f1_score(y_true, binary_preds, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, binary_preds)),
        "mcc": float(matthews_corrcoef(y_true, binary_preds)),
        "roc_auc": float(roc_auc_score(y_true, probs)),
        "brier_score": float(brier_score_loss(y_true, probs)),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "abstention_rate": float(uncertain_count / n_test_samples),
        "uncertain_count": int(uncertain_count),
        "total_evaluated": int(n_test_samples),
    }

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model_info": classifier.get_model_info(),
        "evaluation_metrics": metrics,
    }

    print("\n==================================================")
    print("        ULPF CLASSIFIER EVALUATION REPORT         ")
    print("==================================================")
    print(f"  Model Version       : {classifier.model_version}")
    print(f"  Architecture        : {classifier.model_type}")
    print(f"  Evaluated Samples   : {n_test_samples}")
    print(f"  Abstention Rate     : {metrics['abstention_rate'] * 100:.2f}% ({uncertain_count} uncertain)")
    print("--------------------------------------------------")
    print(f"  Accuracy            : {metrics['accuracy']:.4f}")
    print(f"  Precision (Attack)  : {metrics['precision']:.4f}")
    print(f"  Recall (Attack)     : {metrics['recall']:.4f}")
    print(f"  F1 Score            : {metrics['f1']:.4f}")
    print(f"  Balanced Accuracy   : {metrics['balanced_accuracy']:.4f}")
    print(f"  Matthews Corr (MCC) : {metrics['mcc']:.4f}")
    print(f"  ROC-AUC Score       : {metrics['roc_auc']:.4f}")
    print(f"  Brier Score (Calib) : {metrics['brier_score']:.4f}")
    print("--------------------------------------------------")
    print(f"  Confusion Matrix    : TP={tp} | FP={fp} | TN={tn} | FN={fn}")
    print("==================================================\n")

    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Evaluation report saved to: {report_path}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Model Evaluation CLI")
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL_PATH,
        help=f"Path to serialized model (default: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1000,
        help="Number of evaluation samples (default: 1000)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_REPORT_PATH,
        help=f"Path to save evaluation report (default: {DEFAULT_REPORT_PATH})",
    )

    args = parser.parse_args()
    evaluate_classifier(
        model_path=args.model,
        n_test_samples=args.samples,
        report_path=args.output,
    )


if __name__ == "__main__":
    main()
