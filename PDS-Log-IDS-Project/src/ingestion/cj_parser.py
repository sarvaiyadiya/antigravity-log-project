"""Streaming parser for the supplied cj.log JSON-array format."""

from collections.abc import Iterator
from pathlib import Path
from typing import Literal, TypedDict
import json


FIELD_NAMES = (
    "category_type",
    "sub_key",
    "timestamp",
    "client_ip",
    "source_port",
    "user_agent",
    "language",
    "metadata",
)

EXPECTED_FIELD_COUNT = len(FIELD_NAMES)

ParseStatus = Literal[
    "valid",
    "blank",
    "invalid_json",
    "not_an_array",
    "invalid_field_count",
]


class ParsedEvent(TypedDict):
    """Result produced while parsing one raw event."""

    source_line: int
    array_position: int | None
    parse_status: ParseStatus
    record: object | None
    error: str | None


JSON_DECODER = json.JSONDecoder()


def decode_json_values(
    text: str,
) -> Iterator[tuple[int, object | None, str | None]]:
    """
    Decode one or more adjacent JSON values.

    Yields:
        array_position, decoded_value, error_message
    """
    position = 0
    array_position = 0
    text_length = len(text)

    while position < text_length:
        while position < text_length and text[position].isspace():
            position += 1

        if position >= text_length:
            break

        array_position += 1

        try:
            value, ending_position = JSON_DECODER.raw_decode(
                text,
                position,
            )
        except json.JSONDecodeError as error:
            yield array_position, None, str(error)
            break

        yield array_position, value, None
        position = ending_position


def stream_log_events(
    file_path: Path,
) -> Iterator[ParsedEvent]:
    """Stream validated events from the supplied raw log."""
    with file_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line_number, line in enumerate(file, start=1):
            text = line.strip()

            if not text:
                yield {
                    "source_line": line_number,
                    "array_position": None,
                    "parse_status": "blank",
                    "record": None,
                    "error": None,
                }
                continue

            for array_position, value, error in decode_json_values(text):
                if error is not None:
                    yield {
                        "source_line": line_number,
                        "array_position": array_position,
                        "parse_status": "invalid_json",
                        "record": None,
                        "error": error,
                    }
                    continue

                if not isinstance(value, list):
                    yield {
                        "source_line": line_number,
                        "array_position": array_position,
                        "parse_status": "not_an_array",
                        "record": value,
                        "error": "Decoded JSON value is not an array.",
                    }
                    continue

                if len(value) != EXPECTED_FIELD_COUNT:
                    yield {
                        "source_line": line_number,
                        "array_position": array_position,
                        "parse_status": "invalid_field_count",
                        "record": value,
                        "error": (
                            f"Expected {EXPECTED_FIELD_COUNT} fields, "
                            f"but found {len(value)}."
                        ),
                    }
                    continue

                yield {
                    "source_line": line_number,
                    "array_position": array_position,
                    "parse_status": "valid",
                    "record": value,
                    "error": None,
                }


def record_to_mapping(
    record: object,
) -> dict[str, object]:
    """Convert one validated positional record into named fields."""
    if not isinstance(record, list):
        raise TypeError("The supplied record is not a list.")

    if len(record) != EXPECTED_FIELD_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FIELD_COUNT} fields, "
            f"but found {len(record)}."
        )

    return dict(zip(FIELD_NAMES, record, strict=True))