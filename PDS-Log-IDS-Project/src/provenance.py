"""Functions for dataset and event provenance."""

from pathlib import Path
import hashlib
import json


def calculate_file_sha256(
    file_path: Path,
    block_size: int = 1024 * 1024,
) -> str:
    """Calculate the complete SHA-256 fingerprint of a file."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while block := file.read(block_size):
            sha256.update(block)

    return sha256.hexdigest()


def calculate_record_hash(record: object) -> str:
    """
    Calculate a stable fingerprint from raw record content.

    The fingerprint is truncated to 128 bits for efficient storage.
    """
    canonical_record = json.dumps(
        record,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )

    full_hash = hashlib.sha256(
        canonical_record.encode("utf-8")
    ).hexdigest()

    return full_hash[:32]


def create_event_id(
    dataset_id: str,
    source_line: int,
    array_position: int,
) -> str:
    """Create a stable identifier for one event occurrence."""
    return (
        f"{dataset_id}:"
        f"{source_line}:"
        f"{array_position}"
    )