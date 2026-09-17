from __future__ import annotations

import pandas as pd


LABEL_VERSION = "weak-label-v1"

EVIDENCE_SOURCE_COLUMNS = (
    "user_agent",
    "category_type",
    "sub_key",
    "language",
    "metadata",
)

LABEL_COLUMNS = (
    "weak_label",
    "label_confidence",
    "evidence_codes",
    "evidence_count",
    "label_conflict",
    "label_version",
)

SCANNER_TOKENS = (
    "gobuster",
    "dirbuster",
    "nmap scripting engine",
    "zgrab",
    "sqlmap",
    "nikto",
    "masscan",
    "nuclei",
    "wpscan",
    "ffuf",
)


def detect_candidate_evidence(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """Detect event-local evidence without assigning a label."""

    missing_columns = [
        column
        for column in EVIDENCE_SOURCE_COLUMNS
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Evidence columns are missing: {missing_columns}"
        )

    user_agent = dataframe["user_agent"].fillna("")

    payload_text = dataframe["category_type"].fillna("")

    for column in ["sub_key", "language", "metadata"]:
        payload_text = payload_text.str.cat(
            dataframe[column].fillna(""),
            sep=" ",
        )

    evidence = pd.DataFrame(index=dataframe.index)

    scanner_masks = [
        user_agent.str.contains(
            token,
            case=False,
            regex=False,
        )
        for token in SCANNER_TOKENS
    ]

    evidence["declared_scanner"] = scanner_masks[0]

    for mask in scanner_masks[1:]:
        evidence["declared_scanner"] |= mask

    evidence["browser_style"] = user_agent.str.startswith(
        ("Mozilla/", "Opera/")
    )

    evidence["missing_user_agent"] = (
        dataframe["user_agent"].isna()
        | user_agent.eq("")
    )

    evidence["payload_shell"] = payload_text.str.contains(
        r"(?:rm(?:_|\s)+-rf|"
        r"(?:wget|curl)(?:_|\s)+[^;|&]*"
        r"(?:;|%3b)(?:_|\s)*(?:sh|bash))",
        case=False,
        regex=True,
    )

    evidence["payload_traversal"] = payload_text.str.contains(
        r"(?:\.\./|%2e%2e(?:%2f|/))",
        case=False,
        regex=True,
    )

    evidence["payload_sqli"] = payload_text.str.contains(
        r"(?:union(?:_|\s)+select|"
        r"(?:%27|')(?:_|\s)*(?:or|and)"
        r"(?:_|\s)+\d+(?:_|\s)*=(?:_|\s)*\d+)",
        case=False,
        regex=True,
    )

    evidence["payload_xss"] = payload_text.str.contains(
        r"(?:<script|%3cscript)",
        case=False,
        regex=True,
    )

    evidence["payload_attack_pattern"] = evidence[
        [
            "payload_shell",
            "payload_traversal",
            "payload_sqli",
            "payload_xss",
        ]
    ].any(axis=1)

    return evidence


def _build_evidence_codes(
    evidence: pd.DataFrame,
) -> pd.Series:
    code_map = (
        ("declared_scanner", "UA_DECLARED_SCANNER"),
        ("browser_style", "UA_BROWSER_STYLE"),
        ("missing_user_agent", "UA_MISSING"),
        ("payload_shell", "PAYLOAD_SHELL"),
        ("payload_traversal", "PAYLOAD_PATH_TRAVERSAL"),
        ("payload_sqli", "PAYLOAD_SQLI"),
        ("payload_xss", "PAYLOAD_XSS"),
    )

    codes = pd.Series(
        "",
        index=evidence.index,
        dtype="string",
    )

    for column, code in code_map:
        mask = evidence[column]
        previously_empty = codes.eq("")

        codes.loc[mask & previously_empty] = code

        append_mask = mask & ~previously_empty
        codes.loc[append_mask] = (
            codes.loc[append_mask] + "|" + code
        )

    codes.loc[codes.eq("")] = "NO_MATCHING_EVIDENCE"

    return codes


def apply_weak_labels(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """Apply versioned, event-local weak-label rules."""

    evidence = detect_candidate_evidence(dataframe)

    scanner = evidence["declared_scanner"]
    payload = evidence["payload_attack_pattern"]
    browser = evidence["browser_style"]

    scanner_and_payload = scanner & payload
    payload_only = payload & ~scanner
    scanner_only = scanner & ~payload
    browser_only = browser & ~scanner & ~payload

    output = dataframe.copy()

    output["weak_label"] = pd.Series(
        "uncertain",
        index=dataframe.index,
        dtype="string",
    )

    output["label_confidence"] = 0.0

    output.loc[
        browser_only,
        ["weak_label", "label_confidence"],
    ] = ["benign", 0.55]

    output.loc[
        scanner_only,
        ["weak_label", "label_confidence"],
    ] = ["attack", 0.85]

    output.loc[
        payload_only,
        ["weak_label", "label_confidence"],
    ] = ["attack", 0.95]

    output.loc[
        scanner_and_payload,
        ["weak_label", "label_confidence"],
    ] = ["attack", 0.99]

    output["evidence_codes"] = _build_evidence_codes(
        evidence
    )

    counted_evidence_columns = [
        "declared_scanner",
        "browser_style",
        "missing_user_agent",
        "payload_shell",
        "payload_traversal",
        "payload_sqli",
        "payload_xss",
    ]

    output["evidence_count"] = (
        evidence[counted_evidence_columns]
        .sum(axis=1)
        .astype("int8")
    )

    output["label_conflict"] = (
        browser & (scanner | payload)
    )

    output["label_version"] = LABEL_VERSION

    return output