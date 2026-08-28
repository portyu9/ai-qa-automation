from __future__ import annotations

import importlib
import json
import math
import re
from pathlib import PurePosixPath
from typing import Any

_MAX_CONTRACT_DEPTH = 64
_MAX_CONTRACT_NODES = 100_000
_MAX_CONTRACT_CONTAINER_ITEMS = 50_000
_MAX_CONTRACT_INTEGER_BITS = 4096
_MAX_YAML_TOKENS = 200_000
_MAX_YAML_ALIASES = 1024
_MAX_YAML_ANCHORS = 1024
_YAML_MERGE_TAG = "tag:yaml.org,2002:merge"
_YAML_BOOL_TAG = "tag:yaml.org,2002:bool"
_YAML_INT_TAG = "tag:yaml.org,2002:int"
_YAML_FLOAT_TAG = "tag:yaml.org,2002:float"
_YAML_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_YAML_JSON_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_YAML_JSON_INT = re.compile(r"^[+-]?(?:0|[1-9][0-9]*)$")
_YAML_JSON_FLOAT = re.compile(
    r"^[+-]?(?:(?:0|[1-9][0-9]*)\.[0-9]+(?:[eE][+-]?[0-9]+)?|(?:0|[1-9][0-9]*)[eE][+-]?[0-9]+)$"
)

MAX_CONTRACT_DOCUMENT_BYTES = 2_000_000


def _preflight_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
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
            if depth > _MAX_CONTRACT_DEPTH:
                raise ValueError("contract JSON exceeds the deterministic nesting-depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                return


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("contract JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"contract JSON contains non-standard numeric constant: {value}")


def _load_json(text: str) -> Any:
    _preflight_json_nesting(text)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except RecursionError as exc:
        raise ValueError("contract JSON exceeded parser recursion safety") from exc


def _preflight_yaml_tokens(yaml_module: Any, text: str) -> None:
    open_tokens = (
        yaml_module.tokens.BlockMappingStartToken,
        yaml_module.tokens.BlockSequenceStartToken,
        yaml_module.tokens.FlowMappingStartToken,
        yaml_module.tokens.FlowSequenceStartToken,
    )
    close_tokens = (
        yaml_module.tokens.BlockEndToken,
        yaml_module.tokens.FlowMappingEndToken,
        yaml_module.tokens.FlowSequenceEndToken,
    )
    depth = 0
    token_count = 0
    alias_count = 0
    anchor_count = 0
    try:
        for token in yaml_module.scan(text, Loader=yaml_module.SafeLoader):
            token_count += 1
            if token_count > _MAX_YAML_TOKENS:
                raise ValueError("contract YAML exceeds the deterministic token limit")
            if isinstance(token, yaml_module.tokens.AliasToken):
                alias_count += 1
                if alias_count > _MAX_YAML_ALIASES:
                    raise ValueError("contract YAML exceeds the deterministic alias limit")
            elif isinstance(token, yaml_module.tokens.AnchorToken):
                anchor_count += 1
                if anchor_count > _MAX_YAML_ANCHORS:
                    raise ValueError("contract YAML exceeds the deterministic anchor limit")
            if isinstance(token, open_tokens):
                depth += 1
                if depth > _MAX_CONTRACT_DEPTH:
                    raise ValueError("contract YAML exceeds the deterministic nesting-depth limit")
            elif isinstance(token, close_tokens):
                depth = max(0, depth - 1)
    except Exception as exc:
        if isinstance(exc, yaml_module.YAMLError):
            raise ValueError(f"invalid contract YAML: {type(exc).__name__}") from exc
        raise


def _load_yaml(text: str) -> Any:
    try:
        yaml_module = importlib.import_module("yaml")
    except ImportError as exc:
        raise ValueError(
            "YAML OpenAPI drift requires PyYAML; JSON contracts remain supported"
        ) from exc

    _preflight_yaml_tokens(yaml_module, text)
    loader_class: Any = type("StrictOpenAPIContractLoader", (yaml_module.SafeLoader,), {})
    loader_class.yaml_implicit_resolvers = {
        key: [
            (tag, resolver)
            for tag, resolver in resolvers
            if tag not in {_YAML_BOOL_TAG, _YAML_INT_TAG, _YAML_FLOAT_TAG, _YAML_TIMESTAMP_TAG}
        ]
        for key, resolvers in yaml_module.SafeLoader.yaml_implicit_resolvers.items()
    }
    loader_class.add_implicit_resolver(_YAML_BOOL_TAG, _YAML_JSON_BOOL, list("tTfF"))
    loader_class.add_implicit_resolver(
        _YAML_INT_TAG,
        _YAML_JSON_INT,
        list("-+0123456789"),
    )
    loader_class.add_implicit_resolver(
        _YAML_FLOAT_TAG,
        _YAML_JSON_FLOAT,
        list("-+0123456789"),
    )

    def construct_json_int(loader: Any, node: Any) -> int:
        value = str(loader.construct_scalar(node)).replace("_", "")
        try:
            return int(value, 10)
        except ValueError as exc:
            raise ValueError("contract YAML contains an invalid explicit integer") from exc

    def construct_json_float(loader: Any, node: Any) -> float:
        value = str(loader.construct_scalar(node)).replace("_", "")
        try:
            return float(value)
        except ValueError as exc:
            raise ValueError("contract YAML contains an invalid explicit number") from exc

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, Any]:
        if len(node.value) > _MAX_CONTRACT_CONTAINER_ITEMS:
            raise ValueError("contract YAML contains an oversized object")
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if getattr(key_node, "tag", None) == _YAML_MERGE_TAG:
                raise ValueError("contract YAML merge keys are not supported by bounded analysis")
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError("contract YAML mapping keys must be strings")
            if key in result:
                raise ValueError("contract YAML contains a duplicate mapping key")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    def construct_sequence(loader: Any, node: Any, deep: bool = False) -> list[Any]:
        if len(node.value) > _MAX_CONTRACT_CONTAINER_ITEMS:
            raise ValueError("contract YAML contains an oversized array")
        return [loader.construct_object(child, deep=deep) for child in node.value]

    loader_class.add_constructor(_YAML_INT_TAG, construct_json_int)
    loader_class.add_constructor(_YAML_FLOAT_TAG, construct_json_float)
    loader_class.add_constructor(
        yaml_module.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    loader_class.add_constructor(
        yaml_module.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
        construct_sequence,
    )
    try:
        return yaml_module.load(text, Loader=loader_class)
    except RecursionError as exc:
        raise ValueError("contract YAML exceeded parser recursion safety") from exc
    except Exception as exc:
        if isinstance(exc, yaml_module.YAMLError):
            raise ValueError(f"invalid contract YAML: {type(exc).__name__}") from exc
        raise


def _validate_json_compatible_shape(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_CONTRACT_DEPTH:
            raise ValueError("contract document exceeds the deterministic nesting-depth limit")
        nodes += 1
        if nodes > _MAX_CONTRACT_NODES:
            raise ValueError("contract document exceeds the deterministic structural-node limit")

        if item is None or isinstance(item, (str, bool)):
            continue
        if isinstance(item, int):
            if item.bit_length() > _MAX_CONTRACT_INTEGER_BITS:
                raise ValueError("contract document contains an oversized integer")
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("contract document contains a non-finite number")
            continue
        if isinstance(item, dict):
            identity = id(item)
            if identity in seen_containers:
                raise ValueError("contract document contains a shared or circular container graph")
            seen_containers.add(identity)
            if len(item) > _MAX_CONTRACT_CONTAINER_ITEMS:
                raise ValueError("contract document contains an oversized object")
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError("contract document contains a non-string object key")
                stack.append((nested, depth + 1))
            continue
        if isinstance(item, list):
            identity = id(item)
            if identity in seen_containers:
                raise ValueError("contract document contains a shared or circular container graph")
            seen_containers.add(identity)
            if len(item) > _MAX_CONTRACT_CONTAINER_ITEMS:
                raise ValueError("contract document contains an oversized array")
            stack.extend((nested, depth + 1) for nested in item)
            continue
        raise ValueError(
            f"contract document contains non-JSON value type: {type(item).__name__}"
        )


def load_contract_document(path: str, content: bytes) -> dict[str, Any]:
    """Parse a bounded OpenAPI/Swagger JSON-or-YAML document without ambiguous semantics."""

    if len(content) > MAX_CONTRACT_DOCUMENT_BYTES:
        raise ValueError(
            f"contract document exceeds {MAX_CONTRACT_DOCUMENT_BYTES} byte ingestion limit"
        )
    text = content.decode("utf-8")
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix == ".json":
        value = _load_json(text)
    elif suffix in {".yaml", ".yml"}:
        value = _load_yaml(text)
    else:
        stripped = text.lstrip()
        if stripped.startswith("{"):
            value = _load_json(text)
        else:
            raise ValueError("unsupported contract serialization")
    _validate_json_compatible_shape(value)
    if not isinstance(value, dict):
        raise ValueError("contract root must be an object")
    return value
