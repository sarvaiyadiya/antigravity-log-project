from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
from typing import MutableMapping

import numpy as np
import pandas as pd

IDENTITY_COLUMNS = [
    "event_id",
    "record_hash",
]

CLEANED_COLUMNS = [
    "event_id",
    "record_hash",
    "timestamp_normalized",
    "client_ip_canonical",
    "source_port_normalized",
]

LABEL_COLUMNS = [
    "event_id",
    "record_hash",
    "weak_label",
    "label_confidence",
    "label_conflict",
]

FEATURE_COLUMNS = [
    "event_id",
    "record_hash",
    "timestamp_reversal_flag",
    "activity_decay_60s",
    "activity_decay_300s",
    "activity_decay_3600s",
]

BALANCING_COLUMNS = [
    "event_id",
    "record_hash",
    "data_split",
]

VALID_LABELS = {
    "attack",
    "benign",
    "uncertain",
}

VALID_SPLITS = {
    "train",
    "validation",
    "test",
}


def require_columns(
    frame: pd.DataFrame,
    required_columns: list[str],
    artifact_name: str,
) -> None:
    """
    Verify that a DataFrame contains all required columns.
    """

    missing_columns = [
        column
        for column in required_columns
        if column not in frame.columns
    ]

    if missing_columns:
        raise ValueError(
            f"{artifact_name} is missing columns: "
            f"{missing_columns}"
        )


def assert_aligned_identity(
    reference_frame: pd.DataFrame,
    candidate_frame: pd.DataFrame,
    candidate_name: str,
) -> None:
    """
    Verify that two aligned chunks contain the same
    event_id and record_hash values in the same order.
    """

    if len(reference_frame) != len(candidate_frame):
        raise ValueError(
            f"{candidate_name} row count differs "
            "within the chunk."
        )

    reference_identity = (
        reference_frame[
            IDENTITY_COLUMNS
        ]
        .astype(str)
        .to_numpy()
    )

    candidate_identity = (
        candidate_frame[
            IDENTITY_COLUMNS
        ]
        .astype(str)
        .to_numpy()
    )

    matching_rows = np.all(
        reference_identity == candidate_identity,
        axis=1,
    )

    if not matching_rows.all():
        first_mismatch = int(
            np.flatnonzero(~matching_rows)[0]
        )

        raise ValueError(
            f"{candidate_name} identity mismatch "
            f"at chunk position {first_mismatch}."
        )


def create_client_key(
    client_ip: str,
    secret: str,
) -> str:
    """
    Create a deterministic privacy-safe client key
    using HMAC-SHA256.
    """

    normalized_ip = str(client_ip).strip()

    if not normalized_ip:
        raise ValueError(
            "Client IP cannot be empty."
        )

    if not secret:
        raise ValueError(
            "HMAC secret cannot be empty."
        )

    digest = hmac.new(
        secret.encode("utf-8"),
        normalized_ip.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"client_{digest[:24]}"


def pseudonymize_clients(
    client_ips: pd.Series,
    secret: str,
    client_key_cache: MutableMapping[str, str],
) -> pd.Series:
    """
    Convert raw client IP addresses into stable
    pseudonymous client keys.

    Previously generated keys are reused from the
    provided cache.
    """

    normalized_ips = (
        client_ips
        .astype(str)
        .str.strip()
    )

    if normalized_ips.eq("").any():
        raise ValueError(
            "An empty client IP was found."
        )

    unique_ips = normalized_ips.unique()

    for client_ip in unique_ips:
        if client_ip not in client_key_cache:
            client_key_cache[
                client_ip
            ] = create_client_key(
                client_ip,
                secret,
            )

    client_keys = normalized_ips.map(
        client_key_cache
    )

    if client_keys.isna().any():
        raise RuntimeError(
            "Client pseudonymisation produced "
            "missing keys."
        )

    return client_keys.astype("string")


def _binary_series(
    values: pd.Series,
    column_name: str,
) -> pd.Series:
    """
    Convert supported binary representations into
    uint8 values containing only 0 or 1.
    """

    normalized = (
        values
        .astype(str)
        .str.strip()
        .str.lower()
    )

    mapping = {
        "true": 1,
        "false": 0,
        "1": 1,
        "0": 0,
    }

    converted = normalized.map(mapping)

    if converted.isna().any():
        invalid_values = sorted(
            normalized[
                converted.isna()
            ].unique()
        )

        raise ValueError(
            f"{column_name} contains invalid "
            f"binary values: "
            f"{invalid_values[:5]}"
        )

    return converted.astype("uint8")


def prepare_analysis_chunk(
    cleaned: pd.DataFrame,
    labels: pd.DataFrame,
    features: pd.DataFrame,
    balancing: pd.DataFrame,
    client_hmac_key: str,
    client_key_cache: MutableMapping[str, str],
) -> pd.DataFrame:
    """
    Combine four already-aligned artifact chunks into
    one privacy-safe analysis view.

    Raw client IP addresses are converted into
    pseudonymous client keys and are not included in
    the returned DataFrame.
    """

    require_columns(
        cleaned,
        CLEANED_COLUMNS,
        "cleaned",
    )

    require_columns(
        labels,
        LABEL_COLUMNS,
        "labels",
    )

    require_columns(
        features,
        FEATURE_COLUMNS,
        "features",
    )

    require_columns(
        balancing,
        BALANCING_COLUMNS,
        "balancing",
    )

    assert_aligned_identity(
        cleaned,
        labels,
        "labels",
    )

    assert_aligned_identity(
        cleaned,
        features,
        "features",
    )

    assert_aligned_identity(
        cleaned,
        balancing,
        "balancing",
    )

    timestamps = pd.to_datetime(
        cleaned[
            "timestamp_normalized"
        ],
        format="%Y-%m-%d %H:%M:%S",
        errors="raise",
    )

    source_ports = pd.to_numeric(
        cleaned[
            "source_port_normalized"
        ],
        errors="raise",
    )

    if not source_ports.between(
        0,
        65535,
    ).all():
        raise ValueError(
            "Source port contains values outside "
            "the valid range 0-65535."
        )

    source_ports = source_ports.astype(
        "uint16"
    )

    label_confidence = pd.to_numeric(
        labels[
            "label_confidence"
        ],
        errors="raise",
    ).astype("float64")

    if not label_confidence.between(
        0,
        1,
    ).all():
        raise ValueError(
            "Label confidence must remain "
            "between 0 and 1."
        )

    weak_labels = (
        labels[
            "weak_label"
        ]
        .astype(str)
        .str.strip()
    )

    data_splits = (
        balancing[
            "data_split"
        ]
        .astype(str)
        .str.strip()
    )

    unexpected_labels = (
        set(weak_labels.unique())
        - VALID_LABELS
    )

    if unexpected_labels:
        raise ValueError(
            "Unexpected weak labels found: "
            f"{sorted(unexpected_labels)}"
        )

    unexpected_splits = (
        set(data_splits.unique())
        - VALID_SPLITS
    )

    if unexpected_splits:
        raise ValueError(
            "Unexpected data splits found: "
            f"{sorted(unexpected_splits)}"
        )

    client_keys = pseudonymize_clients(
        cleaned[
            "client_ip_canonical"
        ],
        client_hmac_key,
        client_key_cache,
    )

    result = pd.DataFrame(
        {
            "event_id":
                cleaned[
                    "event_id"
                ].astype(str),

            "record_hash":
                cleaned[
                    "record_hash"
                ].astype(str),

            "timestamp":
                timestamps,

            "hour_start":
                timestamps.dt.floor("h"),

            "day":
                timestamps.dt.floor("D"),

            "client_key":
                client_keys,

            "source_port":
                source_ports,

            "weak_label":
                weak_labels,

            "label_confidence":
                label_confidence,

            "label_conflict":
                _binary_series(
                    labels[
                        "label_conflict"
                    ],
                    "label_conflict",
                ),

            "timestamp_reversal_flag":
                _binary_series(
                    features[
                        "timestamp_reversal_flag"
                    ],
                    "timestamp_reversal_flag",
                ),

            "activity_decay_60s":
                pd.to_numeric(
                    features[
                        "activity_decay_60s"
                    ],
                    errors="raise",
                ).astype("float64"),

            "activity_decay_300s":
                pd.to_numeric(
                    features[
                        "activity_decay_300s"
                    ],
                    errors="raise",
                ).astype("float64"),

            "activity_decay_3600s":
                pd.to_numeric(
                    features[
                        "activity_decay_3600s"
                    ],
                    errors="raise",
                ).astype("float64"),

            "data_split":
                data_splits,
        }
    )

    forbidden_columns = {
        "client_ip",
        "client_ip_canonical",
        "user_agent",
        "metadata",
    }

    exposed_sensitive_columns = (
        forbidden_columns
        .intersection(
            result.columns
        )
    )

    if exposed_sensitive_columns:
        raise AssertionError(
            "Sensitive raw fields entered the "
            "analysis view: "
            f"{sorted(exposed_sensitive_columns)}"
        )

    if result.isna().any().any():
        missing_columns = (
            result
            .columns[
                result.isna().any()
            ]
            .tolist()
        )

        raise ValueError(
            "Prepared analysis chunk contains "
            "missing values in columns: "
            f"{missing_columns}"
        )

    return result

def create_time_aggregation_state() -> dict:
    return {
        "metrics": {},
        "clients": {},
    }


def update_time_aggregation_state(
    state: dict,
    analysis_chunk: pd.DataFrame,
    grain_column: str,
) -> None:
    if grain_column not in {"hour_start", "day"}:
        raise ValueError(
            "grain_column must be 'hour_start' or 'day'."
        )

    required_columns = [
        "event_id",
        grain_column,
        "data_split",
        "client_key",
        "weak_label",
        "label_confidence",
        "label_conflict",
        "timestamp_reversal_flag",
    ]

    require_columns(
        analysis_chunk,
        required_columns,
        "analysis_chunk",
    )

    working = analysis_chunk[required_columns].copy()

    for label_name in sorted(VALID_LABELS):
        working[f"is_{label_name}"] = (
            working["weak_label"] == label_name
        ).astype("uint8")

    partial_metrics = (
        working
        .groupby(
            [grain_column, "data_split"],
            observed=True,
            sort=False,
        )
        .agg(
            event_count=("event_id", "size"),
            attack_count=("is_attack", "sum"),
            benign_count=("is_benign", "sum"),
            uncertain_count=("is_uncertain", "sum"),
            conflict_count=("label_conflict", "sum"),
            confidence_sum=("label_confidence", "sum"),
            timestamp_reversal_count=(
                "timestamp_reversal_flag",
                "sum",
            ),
        )
        .reset_index()
    )

    for row in partial_metrics.itertuples(index=False):
        key = (
            getattr(row, grain_column),
            row.data_split,
        )

        accumulated = state["metrics"].setdefault(
            key,
            {
                "event_count": 0,
                "attack_count": 0,
                "benign_count": 0,
                "uncertain_count": 0,
                "conflict_count": 0,
                "confidence_sum": 0.0,
                "timestamp_reversal_count": 0,
            },
        )

        for count_name in [
            "event_count",
            "attack_count",
            "benign_count",
            "uncertain_count",
            "conflict_count",
            "timestamp_reversal_count",
        ]:
            accumulated[count_name] += int(
                getattr(row, count_name)
            )

        accumulated["confidence_sum"] += float(
            row.confidence_sum
        )

    client_memberships = (
        working[
            [
                grain_column,
                "data_split",
                "client_key",
            ]
        ]
        .drop_duplicates()
    )

    for key, group in client_memberships.groupby(
        [grain_column, "data_split"],
        observed=True,
        sort=False,
    ):
        client_set = state["clients"].setdefault(
            key,
            set(),
        )

        client_set.update(
            group["client_key"].astype(str)
        )


def finalize_time_aggregation(
    state: dict,
    grain_column: str,
) -> pd.DataFrame:
    records = []

    for key, metrics in state["metrics"].items():
        grain_value, data_split = key
        event_count = metrics["event_count"]

        label_total = (
            metrics["attack_count"]
            + metrics["benign_count"]
            + metrics["uncertain_count"]
        )

        if label_total != event_count:
            raise AssertionError(
                f"Label reconciliation failed for {key}."
            )

        if key not in state["clients"]:
            raise AssertionError(
                f"Client membership is missing for {key}."
            )

        records.append({
            grain_column: grain_value,
            "data_split": data_split,
            "event_count": event_count,
            "unique_client_count": len(
                state["clients"][key]
            ),
            "attack_count": metrics["attack_count"],
            "benign_count": metrics["benign_count"],
            "uncertain_count": metrics["uncertain_count"],
            "attack_percent":
                100.0 * metrics["attack_count"] / event_count,
            "benign_percent":
                100.0 * metrics["benign_count"] / event_count,
            "uncertain_percent":
                100.0 * metrics["uncertain_count"] / event_count,
            "conflict_count": metrics["conflict_count"],
            "conflict_percent":
                100.0 * metrics["conflict_count"] / event_count,
            "mean_label_confidence":
                metrics["confidence_sum"] / event_count,
            "timestamp_reversal_count":
                metrics["timestamp_reversal_count"],
        })

    result = (
        pd.DataFrame(records)
        .sort_values(
            [grain_column, "data_split"],
            kind="stable",
        )
        .reset_index(drop=True)
    )

    if int(result["event_count"].sum()) <= 0:
        raise AssertionError(
            "The time aggregation contains no events."
        )

    return result

def create_client_aggregation_state() -> dict:
    return {
        "metrics": {},
        "ports": {},
    }


def update_client_aggregation_state(
    state: dict,
    analysis_chunk: pd.DataFrame,
    grain_columns: list[str],
) -> None:
    allowed_grains = [
        ["client_key", "data_split"],
        ["client_key", "day", "data_split"],
    ]

    if grain_columns not in allowed_grains:
        raise ValueError(
            f"Unsupported client grain: {grain_columns}"
        )

    required_columns = [
        *grain_columns,
        "event_id",
        "timestamp",
        "source_port",
        "weak_label",
        "label_confidence",
        "label_conflict",
        "timestamp_reversal_flag",
        "activity_decay_60s",
        "activity_decay_300s",
        "activity_decay_3600s",
    ]

    require_columns(
        analysis_chunk,
        required_columns,
        "analysis_chunk",
    )

    working = analysis_chunk[required_columns].copy()

    for label_name in sorted(VALID_LABELS):
        working[f"is_{label_name}"] = (
            working["weak_label"] == label_name
        ).astype("uint8")

    partial_metrics = (
        working
        .groupby(
            grain_columns,
            observed=True,
            sort=False,
        )
        .agg(
            event_count=("event_id", "size"),
            first_timestamp=("timestamp", "min"),
            last_timestamp=("timestamp", "max"),
            attack_count=("is_attack", "sum"),
            benign_count=("is_benign", "sum"),
            uncertain_count=("is_uncertain", "sum"),
            conflict_count=("label_conflict", "sum"),
            confidence_sum=("label_confidence", "sum"),
            timestamp_reversal_count=(
                "timestamp_reversal_flag",
                "sum",
            ),
            activity_decay_60s_sum=(
                "activity_decay_60s",
                "sum",
            ),
            activity_decay_300s_sum=(
                "activity_decay_300s",
                "sum",
            ),
            activity_decay_3600s_sum=(
                "activity_decay_3600s",
                "sum",
            ),
        )
        .reset_index()
    )

    for row in partial_metrics.itertuples(index=False):
        key = tuple(
            getattr(row, column)
            for column in grain_columns
        )

        accumulated = state["metrics"].setdefault(
            key,
            {
                "event_count": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "attack_count": 0,
                "benign_count": 0,
                "uncertain_count": 0,
                "conflict_count": 0,
                "confidence_sum": 0.0,
                "timestamp_reversal_count": 0,
                "activity_decay_60s_sum": 0.0,
                "activity_decay_300s_sum": 0.0,
                "activity_decay_3600s_sum": 0.0,
            },
        )

        current_first = row.first_timestamp
        current_last = row.last_timestamp

        if (
            accumulated["first_timestamp"] is None
            or current_first < accumulated["first_timestamp"]
        ):
            accumulated["first_timestamp"] = current_first

        if (
            accumulated["last_timestamp"] is None
            or current_last > accumulated["last_timestamp"]
        ):
            accumulated["last_timestamp"] = current_last

        for count_name in [
            "event_count",
            "attack_count",
            "benign_count",
            "uncertain_count",
            "conflict_count",
            "timestamp_reversal_count",
        ]:
            accumulated[count_name] += int(
                getattr(row, count_name)
            )

        for sum_name in [
            "confidence_sum",
            "activity_decay_60s_sum",
            "activity_decay_300s_sum",
            "activity_decay_3600s_sum",
        ]:
            accumulated[sum_name] += float(
                getattr(row, sum_name)
            )

    port_memberships = (
        working[
            [
                *grain_columns,
                "source_port",
            ]
        ]
        .drop_duplicates()
    )

    for key, group in port_memberships.groupby(
        grain_columns,
        observed=True,
        sort=False,
    ):
        if not isinstance(key, tuple):
            key = (key,)

        port_set = state["ports"].setdefault(
            key,
            set(),
        )

        port_set.update(
            int(port)
            for port in group["source_port"]
        )


def finalize_client_aggregation(
    state: dict,
    grain_columns: list[str],
) -> pd.DataFrame:
    records = []

    for key, metrics in state["metrics"].items():
        event_count = metrics["event_count"]

        label_total = (
            metrics["attack_count"]
            + metrics["benign_count"]
            + metrics["uncertain_count"]
        )

        if label_total != event_count:
            raise AssertionError(
                f"Label reconciliation failed for {key}."
            )

        if key not in state["ports"]:
            raise AssertionError(
                f"Port membership is missing for {key}."
            )

        record = {
            column: value
            for column, value in zip(grain_columns, key)
        }

        record.update({
            "event_count": event_count,
            "first_timestamp": metrics["first_timestamp"],
            "last_timestamp": metrics["last_timestamp"],
            "active_span_seconds": (
                metrics["last_timestamp"]
                - metrics["first_timestamp"]
            ).total_seconds(),
            "unique_port_count": len(state["ports"][key]),
            "attack_count": metrics["attack_count"],
            "benign_count": metrics["benign_count"],
            "uncertain_count": metrics["uncertain_count"],
            "attack_percent":
                100.0 * metrics["attack_count"] / event_count,
            "benign_percent":
                100.0 * metrics["benign_count"] / event_count,
            "uncertain_percent":
                100.0 * metrics["uncertain_count"] / event_count,
            "conflict_count": metrics["conflict_count"],
            "conflict_percent":
                100.0 * metrics["conflict_count"] / event_count,
            "mean_label_confidence":
                metrics["confidence_sum"] / event_count,
            "timestamp_reversal_count":
                metrics["timestamp_reversal_count"],
            "mean_activity_decay_60s":
                metrics["activity_decay_60s_sum"] / event_count,
            "mean_activity_decay_300s":
                metrics["activity_decay_300s_sum"] / event_count,
            "mean_activity_decay_3600s":
                metrics["activity_decay_3600s_sum"] / event_count,
        })

        records.append(record)

    result = (
        pd.DataFrame(records)
        .sort_values(
            grain_columns,
            kind="stable",
        )
        .reset_index(drop=True)
    )

    if int(result["event_count"].sum()) <= 0:
        raise AssertionError(
            "The client aggregation contains no events."
        )

    return result
def calculate_file_sha256(
    file_path: Path,
    block_size: int = 1024 * 1024,
) -> str:
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        while block := file.read(block_size):
            digest.update(block)

    return digest.hexdigest()


def export_aggregated_views(
    project_root: Path,
    cleaned_file: Path,
    label_file: Path,
    feature_file: Path,
    balancing_file: Path,
    output_directory: Path,
    client_hmac_key: str,
    source_fingerprints: dict[str, str],
    expected_rows: int,
    chunk_size: int = 100_000,
) -> dict:
    aggregation_version = "aggregation-v1"
    project_root = Path(project_root).resolve()
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    input_paths = {
        "cleaned": Path(cleaned_file),
        "labels": Path(label_file),
        "features": Path(feature_file),
        "balancing": Path(balancing_file),
    }

    expected_fingerprint_names = set(input_paths)

    if set(source_fingerprints) != expected_fingerprint_names:
        raise ValueError(
            "source_fingerprints must contain exactly: "
            f"{sorted(expected_fingerprint_names)}"
        )

    for input_name, input_path in input_paths.items():
        if not input_path.exists():
            raise FileNotFoundError(
                f"Missing {input_name} file: {input_path}"
            )

    output_paths = {
        "hourly_summary":
            output_directory / "cj_hourly_summary.csv",
        "daily_summary":
            output_directory / "cj_daily_summary.csv",
        "client_split_summary":
            output_directory / "cj_client_split_summary.csv",
        "client_daily_summary":
            output_directory / "cj_client_daily_summary.csv",
    }

    manifest_path = (
        output_directory / "cj_aggregation_manifest.json"
    )

    pseudonym_key_id = hashlib.sha256(
        client_hmac_key.encode("utf-8")
    ).hexdigest()[:16]

    all_final_paths = [
        *output_paths.values(),
        manifest_path,
    ]

    if all(path.exists() for path in all_final_paths):
        with manifest_path.open(encoding="utf-8") as file:
            existing_manifest = json.load(file)

        if (
            existing_manifest.get("aggregation_version")
            != aggregation_version
        ):
            raise ValueError(
                "Existing aggregation version does not match."
            )

        if (
            existing_manifest.get("source_sha256")
            != source_fingerprints
        ):
            raise ValueError(
                "Existing source fingerprints do not match."
            )

        if (
            existing_manifest.get("pseudonym_key_id")
            != pseudonym_key_id
        ):
            raise ValueError(
                "Existing aggregates used a different "
                "pseudonymisation key."
            )

        if existing_manifest.get("input_rows") != expected_rows:
            raise ValueError(
                "Existing aggregate row contract does not match."
            )

        for output_name, output_path in output_paths.items():
            actual_sha256 = calculate_file_sha256(output_path)
            expected_sha256 = existing_manifest[
                "outputs"
            ][output_name]["sha256"]

            if actual_sha256 != expected_sha256:
                raise ValueError(
                    f"Existing {output_name} fingerprint "
                    "does not match its manifest."
                )

        reused_manifest = dict(existing_manifest)
        reused_manifest["export_status"] = "reused"
        return reused_manifest

    existing_partial_set = [
        path
        for path in all_final_paths
        if path.exists()
    ]

    if existing_partial_set:
        raise FileExistsError(
            "Only part of the final aggregation artifact set "
            "exists. Inspect it before removing or replacing: "
            f"{existing_partial_set}"
        )

    temporary_paths = {
        name: path.with_name(path.name + ".partial")
        for name, path in output_paths.items()
    }

    temporary_manifest = manifest_path.with_name(
        manifest_path.name + ".partial"
    )

    for temporary_path in [
        *temporary_paths.values(),
        temporary_manifest,
    ]:
        if temporary_path.exists():
            temporary_path.unlink()

    readers = {
        "cleaned": pd.read_csv(
            input_paths["cleaned"],
            usecols=CLEANED_COLUMNS,
            chunksize=chunk_size,
            keep_default_na=False,
        ),
        "labels": pd.read_csv(
            input_paths["labels"],
            usecols=LABEL_COLUMNS,
            chunksize=chunk_size,
            keep_default_na=False,
        ),
        "features": pd.read_csv(
            input_paths["features"],
            usecols=FEATURE_COLUMNS,
            chunksize=chunk_size,
            keep_default_na=False,
        ),
        "balancing": pd.read_csv(
            input_paths["balancing"],
            usecols=BALANCING_COLUMNS,
            chunksize=chunk_size,
            keep_default_na=False,
        ),
    }

    hourly_state = create_time_aggregation_state()
    daily_state = create_time_aggregation_state()
    client_split_state = create_client_aggregation_state()
    client_daily_state = create_client_aggregation_state()

    client_key_cache: dict[str, str] = {}

    processed_rows = 0
    chunk_count = 0
    minimum_timestamp = None
    maximum_timestamp = None
    start_time = time.perf_counter()

    for chunks in zip_longest(
        *readers.values(),
        fillvalue=None,
    ):
        chunk_map = dict(zip(readers.keys(), chunks))
        chunk_count += 1

        if any(chunk is None for chunk in chunk_map.values()):
            raise AssertionError(
                f"Input chunk counts differ at chunk {chunk_count}."
            )

        analysis_chunk = prepare_analysis_chunk(
            cleaned=chunk_map["cleaned"],
            labels=chunk_map["labels"],
            features=chunk_map["features"],
            balancing=chunk_map["balancing"],
            client_hmac_key=client_hmac_key,
            client_key_cache=client_key_cache,
        )

        chunk_minimum = analysis_chunk["timestamp"].min()
        chunk_maximum = analysis_chunk["timestamp"].max()

        if (
            minimum_timestamp is None
            or chunk_minimum < minimum_timestamp
        ):
            minimum_timestamp = chunk_minimum

        if (
            maximum_timestamp is None
            or chunk_maximum > maximum_timestamp
        ):
            maximum_timestamp = chunk_maximum

        update_time_aggregation_state(
            hourly_state,
            analysis_chunk,
            "hour_start",
        )

        update_time_aggregation_state(
            daily_state,
            analysis_chunk,
            "day",
        )

        update_client_aggregation_state(
            client_split_state,
            analysis_chunk,
            ["client_key", "data_split"],
        )

        update_client_aggregation_state(
            client_daily_state,
            analysis_chunk,
            ["client_key", "day", "data_split"],
        )

        processed_rows += len(analysis_chunk)

        if chunk_count % 5 == 0:
            print(
                f"Processed {chunk_count} chunks "
                f"({processed_rows:,} events)"
            )

    if processed_rows != expected_rows:
        raise AssertionError(
            f"Processed {processed_rows:,} rows; "
            f"expected {expected_rows:,}."
        )

    output_frames = {
        "hourly_summary": finalize_time_aggregation(
            hourly_state,
            "hour_start",
        ),
        "daily_summary": finalize_time_aggregation(
            daily_state,
            "day",
        ),
        "client_split_summary": finalize_client_aggregation(
            client_split_state,
            ["client_key", "data_split"],
        ),
        "client_daily_summary": finalize_client_aggregation(
            client_daily_state,
            ["client_key", "day", "data_split"],
        ),
    }

    grain_contracts = {
        "hourly_summary": ["hour_start", "data_split"],
        "daily_summary": ["day", "data_split"],
        "client_split_summary": ["client_key", "data_split"],
        "client_daily_summary": [
            "client_key",
            "day",
            "data_split",
        ],
    }

    event_reconciliation = {}

    for output_name, output_frame in output_frames.items():
        reconciled_rows = int(
            output_frame["event_count"].sum()
        )

        if reconciled_rows != expected_rows:
            raise AssertionError(
                f"{output_name} reconciled "
                f"{reconciled_rows:,} events instead of "
                f"{expected_rows:,}."
            )

        grain_columns = grain_contracts[output_name]

        if output_frame.duplicated(grain_columns).any():
            raise AssertionError(
                f"{output_name} contains duplicate grains."
            )

        event_reconciliation[output_name] = reconciled_rows

    output_metadata = {}

    for output_name, output_frame in output_frames.items():
        temporary_path = temporary_paths[output_name]

        output_frame.to_csv(
            temporary_path,
            index=False,
            date_format="%Y-%m-%d %H:%M:%S",
        )

        output_metadata[output_name] = {
            "file": str(
                output_paths[output_name]
                .resolve()
                .relative_to(project_root)
            ).replace("\\", "/"),
            "sha256": calculate_file_sha256(
                temporary_path
            ),
            "rows": len(output_frame),
            "grain": grain_contracts[output_name],
        }

    for output_name, final_path in output_paths.items():
        os.replace(
            temporary_paths[output_name],
            final_path,
        )

    elapsed_seconds = time.perf_counter() - start_time
    aggregation_code_path = Path(__file__).resolve()

    manifest = {
        "created_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "aggregation_version": aggregation_version,
        "input_files": {
            name: str(
                path.resolve().relative_to(project_root)
            ).replace("\\", "/")
            for name, path in input_paths.items()
        },
        "source_sha256": source_fingerprints,
        "aggregation_code_file": str(
            aggregation_code_path.relative_to(project_root)
        ).replace("\\", "/"),
        "aggregation_code_sha256": calculate_file_sha256(
            aggregation_code_path
        ),
        "input_rows": processed_rows,
        "chunk_count": chunk_count,
        "chunk_size": chunk_size,
        "minimum_timestamp": minimum_timestamp.isoformat(),
        "maximum_timestamp": maximum_timestamp.isoformat(),
        "pseudonym_method": "HMAC-SHA256-truncated-96-bit",
        "pseudonym_key_id": pseudonym_key_id,
        "raw_ip_exported": False,
        "descriptive_only": True,
        "event_reconciliation": event_reconciliation,
        "unique_clients": len(client_key_cache),
        "outputs": output_metadata,
        "elapsed_seconds": round(elapsed_seconds, 2),
    }

    with temporary_manifest.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        json.dump(
            manifest,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())

    os.replace(
        temporary_manifest,
        manifest_path,
    )

    manifest["export_status"] = "created"
    return manifest