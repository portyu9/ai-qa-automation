from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

MAX_TOOL_INPUT_UTF8_BYTES = 2_100_000
MAX_TOOL_INPUT_NODES = 20_000
MAX_TOOL_INPUT_DEPTH = 16
MAX_TOOL_CONTAINER_ITEMS = 10_000

MAX_JSON_TEXT_UTF8_BYTES = 1_000_000
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 64
MAX_JSON_CONTAINER_ITEMS = 50_000
MAX_INTEGER_BITS = 4096


class ToolInputBoundsError(ValueError):
    """A tool request exceeded a deterministic ingestion or shape boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class InputShape:
    utf8_bytes: int
    nodes: int
    max_depth: int


def _utf8_size_bounded(value: str, *, remaining: int, label: str) -> int:
    total = 0
    for character in value:
        codepoint = ord(character)
        if codepoint <= 0x7F:
            total += 1
        elif codepoint <= 0x7FF:
            total += 2
        elif codepoint <= 0xFFFF:
            total += 3
        else:
            total += 4
        if total > remaining:
            raise ToolInputBoundsError(
                "utf8_bytes",
                f"{label} exceeds the deterministic UTF-8 byte limit",
            )
    return total


def validate_json_value(
    value: Any,
    *,
    max_utf8_bytes: int,
    max_nodes: int,
    max_depth: int,
    max_container_items: int,
    label: str,
    require_dict_root: bool = False,
) -> InputShape:
    """Validate a JSON-compatible value iteratively before canonical serialization."""

    if require_dict_root and not isinstance(value, dict):
        raise ToolInputBoundsError("root_type", f"{label} must be a JSON object")

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    utf8_bytes = 0
    observed_depth = 0

    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise ToolInputBoundsError(
                "depth",
                f"{label} exceeds the deterministic nesting-depth limit",
            )
        observed_depth = max(observed_depth, depth)
        nodes += 1
        if nodes > max_nodes:
            raise ToolInputBoundsError(
                "nodes",
                f"{label} exceeds the deterministic structural-node limit",
            )

        if isinstance(item, str):
            utf8_bytes += _utf8_size_bounded(
                item,
                remaining=max_utf8_bytes - utf8_bytes,
                label=label,
            )
            continue
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if item.bit_length() > MAX_INTEGER_BITS:
                raise ToolInputBoundsError(
                    "integer_bits",
                    f"{label} contains an integer outside the deterministic numeric bound",
                )
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ToolInputBoundsError(
                    "non_finite_float",
                    f"{label} contains a non-finite JSON number",
                )
            continue
        if isinstance(item, dict):
            if len(item) > max_container_items:
                raise ToolInputBoundsError(
                    "container_items",
                    f"{label} contains an oversized JSON object",
                )
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ToolInputBoundsError(
                        "dict_key_type",
                        f"{label} contains a non-string JSON object key",
                    )
                utf8_bytes += _utf8_size_bounded(
                    key,
                    remaining=max_utf8_bytes - utf8_bytes,
                    label=label,
                )
                stack.append((nested, depth + 1))
            continue
        if isinstance(item, list):
            if len(item) > max_container_items:
                raise ToolInputBoundsError(
                    "container_items",
                    f"{label} contains an oversized JSON array",
                )
            for nested in reversed(item):
                stack.append((nested, depth + 1))
            continue

        raise ToolInputBoundsError(
            "value_type",
            f"{label} contains a value outside the JSON-compatible input contract",
        )

    return InputShape(utf8_bytes=utf8_bytes, nodes=nodes, max_depth=observed_depth)


def validate_tool_input(tool_input: Any) -> InputShape:
    return validate_json_value(
        tool_input,
        max_utf8_bytes=MAX_TOOL_INPUT_UTF8_BYTES,
        max_nodes=MAX_TOOL_INPUT_NODES,
        max_depth=MAX_TOOL_INPUT_DEPTH,
        max_container_items=MAX_TOOL_CONTAINER_ITEMS,
        label="tool input",
        require_dict_root=True,
    )


def _preflight_json_depth(raw: str, *, max_depth: int, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > max_depth:
                raise ToolInputBoundsError(
                    "json_depth",
                    f"{label} exceeds the deterministic JSON nesting-depth limit",
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def bounded_json_loads(
    raw: str,
    *,
    label: str,
    max_utf8_bytes: int = MAX_JSON_TEXT_UTF8_BYTES,
    max_nodes: int = MAX_JSON_NODES,
    max_depth: int = MAX_JSON_DEPTH,
    max_container_items: int = MAX_JSON_CONTAINER_ITEMS,
) -> Any:
    """Bound raw JSON text before parsing, then validate the parsed structure iteratively."""

    if not isinstance(raw, str):
        raise ToolInputBoundsError("json_text_type", f"{label} must be a JSON string")
    _utf8_size_bounded(raw, remaining=max_utf8_bytes, label=label)
    _preflight_json_depth(raw, max_depth=max_depth, label=label)
    try:
        parsed = json.loads(raw)
    except RecursionError as exc:
        raise ToolInputBoundsError(
            "json_depth",
            f"{label} exceeded the parser recursion boundary",
        ) from exc
    validate_json_value(
        parsed,
        max_utf8_bytes=max_utf8_bytes,
        max_nodes=max_nodes,
        max_depth=max_depth,
        max_container_items=max_container_items,
        label=label,
    )
    return parsed


_JSON_FIELDS_BY_TOOL: dict[str, tuple[str, ...]] = {
    "plan_tests": ("existing_coverage_json",),
    "prioritize_regression": ("candidates_json",),
    "verify_locator_candidates": ("candidates_json",),
    "propose_locator_heal": ("candidates_json",),
    "validate_json_contract": ("instance_json", "schema_json"),
}
_BROWSER_CANDIDATE_TOOLS = {"verify_locator_candidates", "propose_locator_heal"}


def _internal_tool_name(tool_name: str) -> str:
    prefix = "mcp__qa__"
    return tool_name[len(prefix) :] if tool_name.startswith(prefix) else tool_name


def validate_tool_request(tool_name: str, tool_input: Any) -> InputShape:
    """Validate generic request shape plus raw JSON fields before live tool execution."""

    shape = validate_tool_input(tool_input)
    internal_name = _internal_tool_name(str(tool_name))
    if not isinstance(tool_input, dict):  # pragma: no cover - guaranteed by validate_tool_input
        return shape
    for field in _JSON_FIELDS_BY_TOOL.get(internal_name, ()):
        if field not in tool_input:
            continue
        parsed = bounded_json_loads(tool_input[field], label=f"{internal_name}.{field}")
        if internal_name in _BROWSER_CANDIDATE_TOOLS and field == "candidates_json":
            if not isinstance(parsed, list):
                raise ToolInputBoundsError(
                    "browser_candidate_type",
                    "locator candidates_json must contain a JSON list",
                )
            if len(parsed) > 20:
                raise ToolInputBoundsError(
                    "browser_candidate_count",
                    "locator candidates_json exceeds the 20-candidate execution bound",
                )
    return shape
