from __future__ import annotations

from ipaddress import ip_address

import pandas as pd

from .ingestion.cj_parser import FIELD_NAMES


PROVENANCE_COLUMNS = (
    "event_id",
    "record_hash",
    "source_line",
    "array_position",
)

REQUIRED_COLUMNS = (
    *PROVENANCE_COLUMNS,
    *FIELD_NAMES,
)

DERIVED_COLUMNS = (
    "timestamp_normalized",
    "client_ip_canonical",
    "ip_version",
    "source_port_normalized",
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def clean_structured_chunk(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """Create validated canonical fields without altering raw evidence."""

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Required columns are missing: {missing_columns}"
        )

    base_columns = [
        column
        for column in dataframe.columns
        if column not in DERIVED_COLUMNS
    ]

    cleaned = dataframe[base_columns].copy()

    parsed_time = pd.to_datetime(
        cleaned["timestamp"],
        format=TIMESTAMP_FORMAT,
        errors="coerce",
    )

    if parsed_time.isna().any():
        raise ValueError(
            "One or more timestamps cannot be normalized."
        )

    cleaned["timestamp_normalized"] = (
        parsed_time.dt.strftime(TIMESTAMP_FORMAT)
    )

    if (
        cleaned["client_ip"].isna().any()
        or cleaned["client_ip"].eq("").any()
    ):
        raise ValueError("A client IP is missing or empty.")

    canonical_ip_lookup = {}
    ip_version_lookup = {}

    for raw_ip in cleaned["client_ip"].unique():
        try:
            parsed_ip = ip_address(str(raw_ip))
        except ValueError as error:
            raise ValueError(
                "An invalid client IP was encountered."
            ) from error

        canonical_ip_lookup[raw_ip] = str(parsed_ip)
        ip_version_lookup[raw_ip] = parsed_ip.version

    cleaned["client_ip_canonical"] = (
        cleaned["client_ip"].map(canonical_ip_lookup)
    )

    cleaned["ip_version"] = (
        cleaned["client_ip"]
        .map(ip_version_lookup)
        .astype("Int8")
    )

    numeric_ports = pd.to_numeric(
        cleaned["source_port"],
        errors="coerce",
    )

    invalid_ports = (
        numeric_ports.isna()
        | numeric_ports.mod(1).ne(0)
        | ~numeric_ports.between(0, 65535)
    )

    if invalid_ports.any():
        raise ValueError(
            "An invalid source port was encountered."
        )

    cleaned["source_port_normalized"] = (
        numeric_ports.astype("Int64")
    )

    return cleaned[
        [*base_columns, *DERIVED_COLUMNS]
    ]