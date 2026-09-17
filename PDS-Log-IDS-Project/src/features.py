import numpy as np
import pandas as pd


FEATURE_VERSION = "feature-v1"
NULL_SENTINEL = r"\N"

EVENT_LOCAL_FEATURES = [
    "hour_sin",
    "hour_cos",
    "weekday_sin",
    "weekday_cos",
    "is_weekend",
    "source_port_value",
    "is_privileged_port",
    "is_registered_port",
    "is_dynamic_port",
    "language_present",
    "language_length",
]


def build_event_local_features(dataframe):
    required_columns = {
        "timestamp_normalized",
        "source_port_normalized",
        "language",
    }

    missing_columns = required_columns - set(dataframe.columns)

    if missing_columns:
        raise ValueError(
            f"Missing event-local source columns: "
            f"{sorted(missing_columns)}"
        )

    timestamp = pd.to_datetime(
        dataframe["timestamp_normalized"],
        format="%Y-%m-%d %H:%M:%S",
        errors="raise",
    )

    source_port = pd.to_numeric(
        dataframe["source_port_normalized"],
        errors="raise",
    ).astype("int32")

    language = dataframe["language"].astype("string")

    language_present = (
        language.notna()
        & language.ne("")
        & language.ne(NULL_SENTINEL)
    )

    hour_fraction = (
        timestamp.dt.hour
        + timestamp.dt.minute / 60
        + timestamp.dt.second / 3600
    )

    weekday_fraction = (
        timestamp.dt.dayofweek
        + hour_fraction / 24
    )

    hour_angle = 2 * np.pi * hour_fraction / 24
    weekday_angle = 2 * np.pi * weekday_fraction / 7

    features = pd.DataFrame(
        {
            "hour_sin": np.sin(hour_angle).astype("float32"),
            "hour_cos": np.cos(hour_angle).astype("float32"),
            "weekday_sin": np.sin(weekday_angle).astype("float32"),
            "weekday_cos": np.cos(weekday_angle).astype("float32"),
            "is_weekend": (
                timestamp.dt.dayofweek >= 5
            ).astype("uint8"),
            "source_port_value": source_port,
            "is_privileged_port": (
                source_port <= 1023
            ).astype("uint8"),
            "is_registered_port": (
                source_port.between(1024, 49151)
            ).astype("uint8"),
            "is_dynamic_port": (
                source_port >= 49152
            ).astype("uint8"),
            "language_present": (
                language_present.astype("uint8")
            ),
            "language_length": (
                language.where(language_present, "")
                .str.len()
                .astype("int32")
            ),
        },
        index=dataframe.index,
    )

    if list(features.columns) != EVENT_LOCAL_FEATURES:
        raise RuntimeError(
            "Event-local output violates the feature contract."
        )

    if features.isna().any().any():
        raise RuntimeError(
            "Event-local features contain missing values."
        )

    return features

DECAY_WINDOWS_SECONDS = (
    60.0,
    300.0,
    3600.0,
)

PAST_ONLY_FEATURES = [
    "client_prior_event_count_log1p",
    "has_previous_event",
    "seconds_since_previous_log1p",
    "timestamp_reversal_flag",
    "same_port_as_previous",
    "source_port_seen_before",
    "prior_unique_ports_log1p",
    "activity_decay_60s",
    "activity_decay_300s",
    "activity_decay_3600s",
]

ALL_PRIMARY_FEATURES = (
    EVENT_LOCAL_FEATURES
    + PAST_ONLY_FEATURES
)


class _ClientState:
    __slots__ = (
        "event_count",
        "last_arrival_timestamp",
        "decay_reference_timestamp",
        "last_port",
        "seen_ports",
        "activities",
    )

    def __init__(self, timestamp_seconds, source_port):
        self.event_count = 1
        self.last_arrival_timestamp = timestamp_seconds
        self.decay_reference_timestamp = timestamp_seconds
        self.last_port = source_port
        self.seen_ports = {source_port}

        # The first event becomes past evidence for later events.
        self.activities = np.ones(
            len(DECAY_WINDOWS_SECONDS),
            dtype=np.float64,
        )


class CausalClientFeatureTransformer:
    """
    Maintains client state in source-arrival order.

    transform_chunk() may be called repeatedly. State is preserved
    between chunks, making the output invariant to CSV chunk size.
    """

    def __init__(self):
        self._states = {}

        self._decay_windows = np.asarray(
            DECAY_WINDOWS_SECONDS,
            dtype=np.float64,
        )

    def reset(self):
        self._states.clear()

    def state_summary(self):
        return {
            "client_count": len(self._states),
            "processed_events": sum(
                state.event_count
                for state in self._states.values()
            ),
            "client_port_pairs": sum(
                len(state.seen_ports)
                for state in self._states.values()
            ),
        }

    def transform_chunk(self, dataframe):
        required_columns = {
            "client_ip_canonical",
            "timestamp_normalized",
            "source_port_normalized",
        }

        missing_columns = (
            required_columns - set(dataframe.columns)
        )

        if missing_columns:
            raise ValueError(
                f"Missing causal-feature columns: "
                f"{sorted(missing_columns)}"
            )

        clients = dataframe[
            "client_ip_canonical"
        ].astype("string")

        invalid_clients = (
            clients.isna()
            | clients.eq("")
            | clients.eq(NULL_SENTINEL)
        )

        if invalid_clients.any():
            raise ValueError(
                "Client grouping key contains missing values."
            )

        timestamps = pd.to_datetime(
            dataframe["timestamp_normalized"],
            format="%Y-%m-%d %H:%M:%S",
            errors="raise",
        )

        timestamp_seconds = (
        timestamps
        .to_numpy(dtype="datetime64[s]")
        .astype("int64")
        )

        source_ports = pd.to_numeric(
            dataframe["source_port_normalized"],
            errors="raise",
        ).astype("int32").to_numpy()

        client_values = clients.astype(str).to_numpy()

        row_count = len(dataframe)

        prior_event_count = np.zeros(
            row_count,
            dtype=np.float32,
        )

        has_previous_event = np.zeros(
            row_count,
            dtype=np.uint8,
        )

        seconds_since_previous = np.zeros(
            row_count,
            dtype=np.float32,
        )

        timestamp_reversal = np.zeros(
            row_count,
            dtype=np.uint8,
        )

        same_port_as_previous = np.zeros(
            row_count,
            dtype=np.uint8,
        )

        source_port_seen_before = np.zeros(
            row_count,
            dtype=np.uint8,
        )

        prior_unique_ports = np.zeros(
            row_count,
            dtype=np.float32,
        )

        activity_values = np.zeros(
            (
                row_count,
                len(self._decay_windows),
            ),
            dtype=np.float32,
        )

        for position, (
            client,
            current_timestamp,
            current_port,
        ) in enumerate(
            zip(
                client_values,
                timestamp_seconds,
                source_ports,
            )
        ):
            current_timestamp = int(current_timestamp)
            current_port = int(current_port)

            state = self._states.get(client)

            if state is None:
                self._states[client] = _ClientState(
                    current_timestamp,
                    current_port,
                )
                continue

            has_previous_event[position] = 1

            prior_event_count[position] = np.log1p(
                state.event_count
            )

            raw_gap = (
                current_timestamp
                - state.last_arrival_timestamp
            )

            if raw_gap < 0:
                timestamp_reversal[position] = 1
                effective_gap = 0
            else:
                effective_gap = raw_gap

            seconds_since_previous[position] = np.log1p(
                effective_gap
            )

            same_port_as_previous[position] = int(
                current_port == state.last_port
            )

            source_port_seen_before[position] = int(
                current_port in state.seen_ports
            )

            prior_unique_ports[position] = np.log1p(
                len(state.seen_ports)
            )

            decay_gap = max(
                0,
                current_timestamp
                - state.decay_reference_timestamp,
            )

            decayed_activity = (
                state.activities
                * np.exp(
                    -decay_gap / self._decay_windows
                )
            )

            activity_values[position] = decayed_activity

            # Update state only after producing current features.
            state.event_count += 1
            state.last_arrival_timestamp = current_timestamp
            state.last_port = current_port
            state.seen_ports.add(current_port)
            state.activities = decayed_activity + 1.0

            state.decay_reference_timestamp = max(
                state.decay_reference_timestamp,
                current_timestamp,
            )

        features = pd.DataFrame(
            {
                "client_prior_event_count_log1p":
                    prior_event_count,
                "has_previous_event":
                    has_previous_event,
                "seconds_since_previous_log1p":
                    seconds_since_previous,
                "timestamp_reversal_flag":
                    timestamp_reversal,
                "same_port_as_previous":
                    same_port_as_previous,
                "source_port_seen_before":
                    source_port_seen_before,
                "prior_unique_ports_log1p":
                    prior_unique_ports,
                "activity_decay_60s":
                    activity_values[:, 0],
                "activity_decay_300s":
                    activity_values[:, 1],
                "activity_decay_3600s":
                    activity_values[:, 2],
            },
            index=dataframe.index,
        )

        if list(features.columns) != PAST_ONLY_FEATURES:
            raise RuntimeError(
                "Past-only output violates the feature contract."
            )

        if not np.isfinite(
            features.to_numpy(dtype=np.float64)
        ).all():
            raise RuntimeError(
                "Past-only features contain non-finite values."
            )

        return features