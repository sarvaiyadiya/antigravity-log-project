from __future__ import annotations

from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import pandas as pd
import seaborn as sns


SPLIT_ORDER = ["train", "validation", "test"]


def save_figure(
    figure: plt.Figure,
    output_path: Path,
) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    figure.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight",
        facecolor="white",
    )

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise RuntimeError(
            f"Figure was not written correctly: {output_path}"
        )

    return output_path


def plot_daily_event_volume(
    daily_summary: pd.DataFrame,
    output_path: Path,
) -> tuple[plt.Figure, plt.Axes]:
    required_columns = {
        "day",
        "data_split",
        "event_count",
    }

    missing_columns = (
        required_columns - set(daily_summary.columns)
    )

    if missing_columns:
        raise ValueError(
            f"Daily summary is missing: "
            f"{sorted(missing_columns)}"
        )

    data = (
        daily_summary
        .sort_values("day", kind="stable")
        .reset_index(drop=True)
        .copy()
    )

    if data.duplicated(["day", "data_split"]).any():
        raise ValueError(
            "Daily summary contains duplicate grains."
        )

    if (data["event_count"] <= 0).any():
        raise ValueError(
            "Log-scale volume requires positive counts."
        )

    palette_values = sns.color_palette(
        "colorblind",
        n_colors=3,
    )

    split_colors = dict(
        zip(SPLIT_ORDER, palette_values)
    )

    figure, axis = plt.subplots(
        figsize=(12, 5.8)
    )

    for split_name in SPLIT_ORDER:
        split_data = data[
            data["data_split"] == split_name
        ]

        axis.plot(
            split_data["day"],
            split_data["event_count"],
            label=split_name.capitalize(),
            color=split_colors[split_name],
            linewidth=1.6,
        )

        peak_row = split_data.loc[
            split_data["event_count"].idxmax()
        ]

        axis.scatter(
            peak_row["day"],
            peak_row["event_count"],
            color=split_colors[split_name],
            s=32,
            zorder=3,
        )

        axis.annotate(
            (
                f"{split_name.capitalize()} peak\n"
                f"{int(peak_row['event_count']):,}"
            ),
            xy=(
                peak_row["day"],
                peak_row["event_count"],
            ),
            xytext=(0, 9),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    for boundary in [
        pd.Timestamp("2024-01-01"),
        pd.Timestamp("2024-02-01"),
    ]:
        axis.axvline(
            boundary,
            color="0.35",
            linestyle="--",
            linewidth=1,
            alpha=0.8,
        )

    axis.set_yscale("log")

    axis.yaxis.set_major_formatter(
        FuncFormatter(
            lambda value, position: f"{value:,.0f}"
        )
    )

    date_locator = mdates.AutoDateLocator(
        minticks=6,
        maxticks=10,
    )

    axis.xaxis.set_major_locator(date_locator)
    axis.xaxis.set_major_formatter(
        mdates.ConciseDateFormatter(date_locator)
    )

    axis.set_title(
        "Daily event volume reveals extreme temporal bursts"
    )
    axis.set_xlabel("Calendar date")
    axis.set_ylabel("Events per day (logarithmic scale)")
    axis.legend(
        title="Temporal split",
        frameon=False,
    )

    figure.tight_layout()
    save_figure(figure, output_path)

    return figure, axis