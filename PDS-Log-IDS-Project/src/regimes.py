from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.aggregation import (
    calculate_file_sha256,
    require_columns,
)


REGIME_VERSION = "active-hour-quantile-v1"


def calculate_burst_threshold(
    hourly_summary: pd.DataFrame,
    training_quantile: float = 0.99,
) -> dict:
    require_columns(
        hourly_summary,
        ["hour_start", "data_split", "event_count"],
        "hourly_summary",
    )

    if not 0 < training_quantile < 1:
        raise ValueError(
            "training_quantile must be between 0 and 1."
        )

    training_counts = hourly_summary.loc[
        hourly_summary["data_split"] == "train",
        "event_count",
    ]

    if training_counts.empty:
        raise ValueError("No training hours are available.")

    raw_threshold = float(
        training_counts.quantile(training_quantile)
    )

    return {
        "source_split": "train",
        "training_quantile": training_quantile,
        "raw_threshold": raw_threshold,
        "threshold_event_count": int(np.ceil(raw_threshold)),
        "training_active_hours": len(training_counts),
    }


def assign_hourly_volume_regimes(
    hourly_summary: pd.DataFrame,
    threshold_event_count: int,
    training_quantile: float,
) -> pd.DataFrame:
    if threshold_event_count <= 0:
        raise ValueError(
            "threshold_event_count must be positive."
        )

    result = (
        hourly_summary
        .sort_values("hour_start", kind="stable")
        .reset_index(drop=True)
        .copy()
    )

    if result.duplicated(
        ["hour_start", "data_split"]
    ).any():
        raise ValueError(
            "Hourly summary contains duplicate grains."
        )

    is_burst = (
        result["event_count"] >= threshold_event_count
    )

    previous_hour_was_burst = is_burst.shift(
        1,
        fill_value=False,
    )

    follows_previous_clock_hour = (
        result["hour_start"].diff()
        == pd.Timedelta(hours=1)
    )

    is_post_burst = (
        ~is_burst
        & previous_hour_was_burst
        & follows_previous_clock_hour
    )

    result["volume_regime"] = np.select(
        [is_burst, is_post_burst],
        ["burst", "post_burst"],
        default="ordinary",
    )

    result["burst_threshold_event_count"] = (
        threshold_event_count
    )
    result["threshold_training_quantile"] = (
        training_quantile
    )
    result["regime_version"] = REGIME_VERSION

    return result

def export_hourly_regimes(
    project_root: Path,
    hourly_summary_file: Path,
    aggregation_manifest_file: Path,
    output_directory: Path,
    expected_events: int,
    training_quantile: float = 0.99,
) -> dict:
    project_root = Path(project_root).resolve()
    hourly_summary_file = Path(hourly_summary_file)
    aggregation_manifest_file = Path(
        aggregation_manifest_file
    )
    output_directory = Path(output_directory)

    output_directory.mkdir(parents=True, exist_ok=True)

    output_file = (
        output_directory / "cj_hourly_regimes.csv"
    )

    manifest_file = (
        output_directory
        / "cj_hourly_regimes_manifest.json"
    )

    temporary_output = output_file.with_name(
        output_file.name + ".partial"
    )

    temporary_manifest = manifest_file.with_name(
        manifest_file.name + ".partial"
    )

    if not hourly_summary_file.exists():
        raise FileNotFoundError(hourly_summary_file)

    if not aggregation_manifest_file.exists():
        raise FileNotFoundError(
            aggregation_manifest_file
        )

    with aggregation_manifest_file.open(
        encoding="utf-8"
    ) as file:
        aggregation_manifest = json.load(file)

    source_sha256 = calculate_file_sha256(
        hourly_summary_file
    )

    expected_source_sha256 = aggregation_manifest[
        "outputs"
    ]["hourly_summary"]["sha256"]

    if source_sha256 != expected_source_sha256:
        raise ValueError(
            "Hourly-summary fingerprint does not match "
            "the aggregation manifest."
        )

    regime_code_file = Path(__file__).resolve()
    regime_code_sha256 = calculate_file_sha256(
        regime_code_file
    )

    if output_file.exists() and manifest_file.exists():
        with manifest_file.open(encoding="utf-8") as file:
            existing_manifest = json.load(file)

        if (
            existing_manifest.get("regime_version")
            != REGIME_VERSION
        ):
            raise ValueError(
                "Existing regime version does not match."
            )

        if (
            existing_manifest.get("source_sha256")
            != source_sha256
        ):
            raise ValueError(
                "Existing regime source does not match."
            )

        if (
            existing_manifest.get("regime_code_sha256")
            != regime_code_sha256
        ):
            raise ValueError(
                "Regime code changed after the existing "
                "artifact was created."
            )

        if (
            calculate_file_sha256(output_file)
            != existing_manifest["output_sha256"]
        ):
            raise ValueError(
                "Existing regime output fingerprint "
                "does not match."
            )

        reused_manifest = dict(existing_manifest)
        reused_manifest["export_status"] = "reused"
        return reused_manifest

    if output_file.exists() or manifest_file.exists():
        raise FileExistsError(
            "Only part of the final regime artifact set "
            "exists. Inspect it before replacement."
        )

    for temporary_path in [
        temporary_output,
        temporary_manifest,
    ]:
        if temporary_path.exists():
            temporary_path.unlink()

    hourly_summary = pd.read_csv(
        hourly_summary_file,
        parse_dates=["hour_start"],
    )

    threshold_contract = calculate_burst_threshold(
        hourly_summary,
        training_quantile=training_quantile,
    )

    hourly_regimes = assign_hourly_volume_regimes(
        hourly_summary=hourly_summary,
        threshold_event_count=threshold_contract[
            "threshold_event_count"
        ],
        training_quantile=training_quantile,
    )

    if len(hourly_regimes) != len(hourly_summary):
        raise AssertionError(
            "Regime assignment changed the hourly row count."
        )

    if int(hourly_regimes["event_count"].sum()) != expected_events:
        raise AssertionError(
            "Regime event count does not reconcile."
        )

    if hourly_regimes.duplicated(
        ["hour_start", "data_split"]
    ).any():
        raise AssertionError(
            "Regime output contains duplicate hourly grains."
        )

    pd.testing.assert_frame_equal(
        hourly_summary.reset_index(drop=True),
        hourly_regimes[
            hourly_summary.columns
        ].reset_index(drop=True),
    )

    regime_distribution = (
        hourly_regimes
        .groupby(
            ["data_split", "volume_regime"],
            observed=True,
        )
        .agg(
            active_hour_count=("hour_start", "size"),
            event_count=("event_count", "sum"),
        )
        .reset_index()
    )

    regime_distribution["active_hour_percent"] = (
        100.0
        * regime_distribution["active_hour_count"]
        / regime_distribution
          .groupby("data_split")["active_hour_count"]
          .transform("sum")
    )

    regime_distribution["event_percent"] = (
        100.0
        * regime_distribution["event_count"]
        / regime_distribution
          .groupby("data_split")["event_count"]
          .transform("sum")
    )

    distribution_records = [
        {
            "data_split": str(row.data_split),
            "volume_regime": str(row.volume_regime),
            "active_hour_count": int(
                row.active_hour_count
            ),
            "event_count": int(row.event_count),
            "active_hour_percent": float(
                row.active_hour_percent
            ),
            "event_percent": float(
                row.event_percent
            ),
        }
        for row in regime_distribution.itertuples(
            index=False
        )
    ]

    hourly_regimes.to_csv(
        temporary_output,
        index=False,
        date_format="%Y-%m-%d %H:%M:%S",
    )

    output_sha256 = calculate_file_sha256(
        temporary_output
    )

    manifest = {
        "created_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "regime_version": REGIME_VERSION,
        "source_file": str(
            hourly_summary_file
            .resolve()
            .relative_to(project_root)
        ).replace("\\", "/"),
        "source_sha256": source_sha256,
        "source_aggregation_manifest": str(
            aggregation_manifest_file
            .resolve()
            .relative_to(project_root)
        ).replace("\\", "/"),
        "source_aggregation_manifest_sha256":
            calculate_file_sha256(
                aggregation_manifest_file
            ),
        "regime_code_file": str(
            regime_code_file.relative_to(project_root)
        ).replace("\\", "/"),
        "regime_code_sha256": regime_code_sha256,
        "input_rows": len(hourly_summary),
        "output_rows": len(hourly_regimes),
        "event_count": expected_events,
        "threshold_contract": threshold_contract,
        "threshold_uses_weak_labels": False,
        "active_hours_only": True,
        "post_burst_requires_immediate_next_hour": True,
        "output_file": str(
            output_file
            .resolve()
            .relative_to(project_root)
        ).replace("\\", "/"),
        "output_sha256": output_sha256,
        "regime_distribution": distribution_records,
    }

    os.replace(
        temporary_output,
        output_file,
    )

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
        manifest_file,
    )

    manifest["export_status"] = "created"
    return manifest