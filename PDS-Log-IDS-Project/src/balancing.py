import numpy as np
import pandas as pd


BALANCING_VERSION = "class-confidence-v1"

SUPERVISED_CLASSES = (
    "attack",
    "benign",
)

ALLOWED_LABELS = {
    "attack",
    "benign",
    "uncertain",
}


def _prepare_labels(labels):
    label_series = (
        pd.Series(labels)
        .reset_index(drop=True)
        .astype("string")
    )

    unexpected_labels = (
        set(label_series.dropna().unique())
        - ALLOWED_LABELS
    )

    if unexpected_labels:
        raise ValueError(
            f"Unexpected labels: "
            f"{sorted(unexpected_labels)}"
        )

    if label_series.isna().any():
        raise ValueError("Labels contain missing values.")

    return label_series


def _prepare_confidence(confidence, expected_length):
    confidence_series = pd.to_numeric(
        pd.Series(confidence).reset_index(drop=True),
        errors="raise",
    ).astype("float64")

    if len(confidence_series) != expected_length:
        raise ValueError(
            "Labels and confidence lengths differ."
        )

    if not np.isfinite(confidence_series).all():
        raise ValueError(
            "Confidence contains non-finite values."
        )

    if not confidence_series.between(0, 1).all():
        raise ValueError(
            "Confidence must remain between 0 and 1."
        )

    return confidence_series


def calculate_balanced_class_weights(labels):
    label_series = _prepare_labels(labels)

    supervised_labels = label_series[
        label_series.isin(SUPERVISED_CLASSES)
    ]

    class_counts = supervised_labels.value_counts()

    missing_classes = (
        set(SUPERVISED_CLASSES)
        - set(class_counts.index)
    )

    if missing_classes:
        raise ValueError(
            f"Missing supervised classes: "
            f"{sorted(missing_classes)}"
        )

    supervised_count = len(supervised_labels)
    class_count = len(SUPERVISED_CLASSES)

    return {
        label_name: (
            supervised_count
            / (
                class_count
                * int(class_counts[label_name])
            )
        )
        for label_name in SUPERVISED_CLASSES
    }


def calculate_within_class_confidence_means(
    labels,
    confidence,
):
    label_series = _prepare_labels(labels)

    confidence_series = _prepare_confidence(
        confidence,
        len(label_series),
    )

    confidence_means = {}

    for label_name in SUPERVISED_CLASSES:
        class_mask = label_series == label_name

        if not class_mask.any():
            raise ValueError(
                f"No records for class {label_name}."
            )

        class_mean = float(
            confidence_series[class_mask].mean()
        )

        if class_mean <= 0:
            raise ValueError(
                f"Non-positive confidence mean for "
                f"{label_name}."
            )

        confidence_means[label_name] = class_mean

    return confidence_means


def build_confidence_normalized_weights(
    labels,
    confidence,
    class_weights,
    confidence_means,
):
    label_series = _prepare_labels(labels)

    confidence_series = _prepare_confidence(
        confidence,
        len(label_series),
    )

    sample_weights = np.zeros(
        len(label_series),
        dtype=np.float64,
    )

    for label_name in SUPERVISED_CLASSES:
        if label_name not in class_weights:
            raise ValueError(
                f"Missing class weight for {label_name}."
            )

        if label_name not in confidence_means:
            raise ValueError(
                f"Missing confidence mean for "
                f"{label_name}."
            )

        class_mask = (
            label_series == label_name
        ).to_numpy()

        relative_confidence = (
            confidence_series[class_mask].to_numpy()
            / confidence_means[label_name]
        )

        sample_weights[class_mask] = (
            class_weights[label_name]
            * relative_confidence
        )

    if not np.isfinite(sample_weights).all():
        raise RuntimeError(
            "Generated sample weights are non-finite."
        )

    if (sample_weights < 0).any():
        raise RuntimeError(
            "Generated sample weights are negative."
        )

    return pd.Series(
        sample_weights,
        name="sample_weight",
    )
SPLIT_VERSION = "calendar-temporal-v1"

VALIDATION_START = pd.Timestamp(
    "2024-01-01 00:00:00"
)

TEST_START = pd.Timestamp(
    "2024-02-01 00:00:00"
)


def assign_calendar_split(timestamps):
    timestamp_series = pd.Series(
        timestamps,
        copy=False,
    )

    parsed_timestamps = pd.to_datetime(
        timestamp_series,
        format="%Y-%m-%d %H:%M:%S",
        errors="raise",
    )

    assignments = np.select(
        [
            parsed_timestamps < VALIDATION_START,
            parsed_timestamps < TEST_START,
        ],
        [
            "train",
            "validation",
        ],
        default="test",
    )

    return pd.Series(
        assignments,
        index=timestamp_series.index,
        dtype="string",
        name="data_split",
    )