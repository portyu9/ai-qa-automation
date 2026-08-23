from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_qa_automation.io_safety import read_text_bounded

MAX_SCENARIO_BYTES = 64 * 1024


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is forbidden in evaluation catalog: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is forbidden in evaluation catalog: {value}")


def load_catalog_object(path: Path, *, label: str) -> dict[str, Any]:
    """Load one small repository-owned evaluation case through a strict bounded boundary."""

    text = read_text_bounded(path, max_bytes=MAX_SCENARIO_BYTES, label=label)
    raw = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(raw, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return raw
