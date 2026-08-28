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
_COMPARISON_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
_OPENAPI_RESPONSE_KEY = re.compile(r"^(?:default|[1-5](?:[0-9]{2}|XX))$")
_SWAGGER_RESPONSE_KEY = re.compile(r"^(?:default|[1-5][0-9]{2})$")
_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "number", "object", "string"})
_SCHEMA_TYPES_31 = _SCHEMA_TYPES | {"null"}
_OPENAPI_PARAMETER_LOCATIONS = frozenset({"query", "header", "path", "cookie"})
_SWAGGER_PARAMETER_LOCATIONS = frozenset({"query", "header", "path", "formData", "body"})
_SWAGGER_PARAMETER_TYPES = frozenset({"string", "number", "integer", "boolean", "array", "file"})
_SWAGGER_ITEM_TYPES = frozenset({"string", "number", "integer", "boolean", "array"})

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
    loader_class.add_implicit_resolver(_YAML_INT_TAG, _YAML_JSON_INT, list("-+0123456789"))
    loader_class.add_implicit_resolver(_YAML_FLOAT_TAG, _YAML_JSON_FLOAT, list("-+0123456789"))

    def construct_json_bool(loader: Any, node: Any) -> bool:
        value = str(loader.construct_scalar(node))
        normalized = value.casefold()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        raise ValueError("contract YAML contains an invalid explicit boolean")

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

    loader_class.add_constructor(_YAML_BOOL_TAG, construct_json_bool)
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
        raise ValueError(f"contract document contains non-JSON value type: {type(item).__name__}")


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"contract OpenAPI field {field} must be an object for bounded comparison")
    return value


def _enum_identity(value: str | int | float | bool | None) -> tuple[str, object]:
    if value is None:
        return ("null", "")
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, str):
        return ("string", value)
    return ("number", value)


def _decode_pointer_token(token: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(token):
        if token[index] != "~":
            output.append(token[index])
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise ValueError("contract OpenAPI schema $ref contains invalid JSON Pointer escaping")
        output.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(output)


def _path_template_names(path_name: str) -> set[str]:
    if "?" in path_name or "#" in path_name:
        raise ValueError("contract OpenAPI path keys may not contain query or fragment syntax")
    names = re.findall(r"\{([^{}]+)\}", path_name)
    remainder = re.sub(r"\{[^{}]+\}", "", path_name)
    if "{" in remainder or "}" in remainder or any(not name or "/" in name for name in names):
        raise ValueError("contract OpenAPI path template syntax is invalid for bounded comparison")
    return set(names)


def _validate_swagger_items(
    value: Any,
    *,
    depth: int = 0,
) -> None:
    if depth > 12:
        raise ValueError("contract Swagger array items exceed the bounded nesting-depth limit")
    items = _require_object(value, "Swagger array items")
    item_type = items.get("type")
    if not isinstance(item_type, str) or item_type not in _SWAGGER_ITEM_TYPES:
        raise ValueError("contract Swagger array items require a supported type")
    if item_type == "array":
        if "items" not in items:
            raise ValueError("contract Swagger nested array items require an items object")
        _validate_swagger_items(items["items"], depth=depth + 1)
    elif "items" in items:
        raise ValueError("contract Swagger non-array items may not contain nested items")


def _schema_context(document: dict[str, Any]) -> tuple[str, str, dict[str, Any], bool]:
    has_openapi = "openapi" in document
    has_swagger = "swagger" in document
    if has_openapi and has_swagger:
        raise ValueError("contract document may not mix OpenAPI and Swagger dialect markers")
    if has_openapi:
        openapi = document["openapi"]
        if not isinstance(openapi, str):
            raise ValueError("contract OpenAPI dialect marker must be a string")
        if "definitions" in document:
            raise ValueError("contract OpenAPI 3.x definitions are not supported by bounded comparison")
        components = _require_object(document["components"], "components") if "components" in document else {}
        schemas = _require_object(components["schemas"], "components schemas") if "schemas" in components else {}
        return ("openapi", "#/components/schemas/", schemas, openapi.startswith("3.1."))
    if has_swagger:
        swagger = document["swagger"]
        if not isinstance(swagger, str):
            raise ValueError("contract Swagger dialect marker must be a string")
        if "components" in document:
            raise ValueError("contract Swagger 2.0 components are not supported by bounded comparison")
        definitions = _require_object(document["definitions"], "definitions") if "definitions" in document else {}
        return ("swagger", "#/definitions/", definitions, False)
    return ("unknown", "", {}, False)


def _validate_security_shape(value: Any) -> None:
    if not isinstance(value, list):
        raise ValueError("contract OpenAPI security must be an array for bounded comparison")
    for requirement in value:
        if not isinstance(requirement, dict):
            raise ValueError("contract OpenAPI security entries must be objects for bounded comparison")
        for scopes in requirement.values():
            if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes):
                raise ValueError("contract OpenAPI security scopes must be string arrays for bounded comparison")


def _validate_schema_shape(
    root: dict[str, Any],
    *,
    ref_prefix: str,
    named_schemas: dict[str, Any],
    allow_type_array: bool,
) -> None:
    allowed_types = _SCHEMA_TYPES_31 if allow_type_array else _SCHEMA_TYPES
    stack = [root]
    while stack:
        schema = stack.pop()
        reference = schema.get("$ref")
        if reference is not None:
            if not isinstance(reference, str):
                raise ValueError("contract OpenAPI schema $ref must be a string for bounded comparison")
            if not ref_prefix or not reference.startswith(ref_prefix):
                raise ValueError(
                    "contract OpenAPI schema $ref must target a local named schema for bounded comparison"
                )
            token = reference[len(ref_prefix) :]
            if not token or "/" in token:
                raise ValueError(
                    "contract OpenAPI schema $ref must target a local named schema for bounded comparison"
                )
            target_name = _decode_pointer_token(token)
            target = named_schemas.get(target_name)
            if not isinstance(target, dict):
                raise ValueError(
                    "contract OpenAPI schema $ref target must resolve to a named schema object"
                )

        if "type" in schema:
            schema_type = schema["type"]
            if isinstance(schema_type, list):
                if not allow_type_array:
                    raise ValueError(
                        "contract OpenAPI schema type arrays require OpenAPI 3.1 for bounded comparison"
                    )
                if not schema_type or any(not isinstance(item, str) for item in schema_type):
                    raise ValueError(
                        "contract OpenAPI schema type arrays must contain strings for bounded comparison"
                    )
                if len(set(schema_type)) != len(schema_type):
                    raise ValueError("contract OpenAPI schema type array contains duplicate entries")
                if any(item not in allowed_types for item in schema_type):
                    raise ValueError("contract OpenAPI schema contains an unsupported type")
            elif not isinstance(schema_type, str):
                raise ValueError(
                    "contract OpenAPI schema type must be a string or string array for bounded comparison"
                )
            elif schema_type not in allowed_types:
                raise ValueError("contract OpenAPI schema contains an unsupported type")

        if "enum" in schema:
            enum = schema["enum"]
            if (
                not isinstance(enum, list)
                or not enum
                or any(item is not None and not isinstance(item, (str, bool, int, float)) for item in enum)
            ):
                raise ValueError("contract OpenAPI schema enum must be a non-empty scalar array for bounded comparison")
            seen_enum: set[tuple[str, object]] = set()
            for item in enum:
                identity = _enum_identity(item)
                if identity in seen_enum:
                    raise ValueError("contract OpenAPI schema enum contains duplicate values")
                seen_enum.add(identity)

        if "required" in schema:
            required = schema["required"]
            if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
                raise ValueError("contract OpenAPI schema required must be a string array for bounded comparison")
            if len(set(required)) != len(required):
                raise ValueError("contract OpenAPI schema required contains duplicate entries")

        if "properties" in schema:
            properties = _require_object(schema["properties"], "schema properties")
            for nested in properties.values():
                stack.append(_require_object(nested, "property schema"))

        if "items" in schema:
            stack.append(_require_object(schema["items"], "schema items"))


def _validate_parameter_list(
    value: Any,
    *,
    path_level: bool,
    dialect: str,
    ref_prefix: str,
    named_schemas: dict[str, Any],
    allow_type_array: bool,
) -> set[tuple[str, str]]:
    if not isinstance(value, list):
        raise ValueError("contract OpenAPI parameters must be an array for bounded comparison")
    if path_level and value:
        raise ValueError("contract OpenAPI path-level parameters are not supported by bounded comparison")
    seen: set[tuple[str, str]] = set()
    swagger_body_count = 0
    swagger_has_form_data = False
    for parameter_value in value:
        parameter = _require_object(parameter_value, "parameter")
        if "$ref" in parameter:
            raise ValueError("contract OpenAPI referenced parameters are not supported by bounded comparison")
        name = parameter.get("name")
        location = parameter.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            raise ValueError(
                "contract OpenAPI parameters require string name and in fields for bounded comparison"
            )
        allowed_locations = (
            _SWAGGER_PARAMETER_LOCATIONS if dialect == "swagger" else _OPENAPI_PARAMETER_LOCATIONS
        )
        if location not in allowed_locations:
            raise ValueError("contract OpenAPI parameter location is unsupported for bounded comparison")
        identity = (location, name)
        if identity in seen:
            raise ValueError("contract OpenAPI parameters contain a duplicate name/in identity")
        seen.add(identity)
        if "required" in parameter and not isinstance(parameter["required"], bool):
            raise ValueError("contract OpenAPI parameter required must be boolean for bounded comparison")
        if location == "path" and parameter.get("required") is not True:
            raise ValueError("contract OpenAPI path parameters must be explicitly required")

        if dialect == "swagger":
            if location == "body":
                swagger_body_count += 1
                if swagger_body_count > 1:
                    raise ValueError("contract Swagger operations may contain at most one body parameter")
                if any(
                    key in parameter for key in ("type", "format", "items", "collectionFormat")
                ):
                    raise ValueError(
                        "contract Swagger body parameters may not use non-body type fields"
                    )
                if "schema" not in parameter:
                    raise ValueError("contract Swagger body parameters require a schema")
                _validate_schema_shape(
                    _require_object(parameter["schema"], "parameter schema"),
                    ref_prefix=ref_prefix,
                    named_schemas=named_schemas,
                    allow_type_array=allow_type_array,
                )
                continue
            if location == "formData":
                swagger_has_form_data = True
            if "schema" in parameter:
                raise ValueError("contract Swagger non-body parameters may not use schema")
            parameter_type = parameter.get("type")
            if not isinstance(parameter_type, str) or parameter_type not in _SWAGGER_PARAMETER_TYPES:
                raise ValueError("contract Swagger non-body parameters require a supported type")
            if parameter_type == "file" and location != "formData":
                raise ValueError("contract Swagger file parameters require formData location")
            if parameter_type == "array":
                if "items" not in parameter:
                    raise ValueError("contract Swagger array parameters require an items object")
                _validate_swagger_items(parameter["items"])
            elif "items" in parameter:
                raise ValueError("contract Swagger non-array parameters may not contain items")
            continue

        if any(key in parameter for key in ("type", "format", "items", "collectionFormat")):
            raise ValueError(
                "contract OpenAPI 3.x parameters may not use Swagger type fields"
            )
        has_schema = "schema" in parameter
        has_content = "content" in parameter
        if has_schema == has_content:
            raise ValueError(
                "contract OpenAPI parameters require exactly one of schema or content for bounded comparison"
            )
        if has_schema:
            _validate_schema_shape(
                _require_object(parameter["schema"], "parameter schema"),
                ref_prefix=ref_prefix,
                named_schemas=named_schemas,
                allow_type_array=allow_type_array,
            )
        else:
            content = _require_object(parameter["content"], "parameter content")
            if len(content) != 1:
                raise ValueError(
                    "contract OpenAPI parameter content must contain exactly one media type"
                )
            _validate_media_content(
                content,
                field="parameter content",
                ref_prefix=ref_prefix,
                named_schemas=named_schemas,
                allow_type_array=allow_type_array,
            )

    if dialect == "swagger" and swagger_body_count and swagger_has_form_data:
        raise ValueError("contract Swagger operations may not mix body and formData parameters")
    return seen


def _validate_media_content(
    value: Any,
    *,
    field: str,
    ref_prefix: str,
    named_schemas: dict[str, Any],
    allow_type_array: bool,
) -> None:
    content = _require_object(value, field)
    if not content:
        raise ValueError(f"contract OpenAPI {field} must not be empty for bounded comparison")
    for media_type in content.values():
        media = _require_object(media_type, "media type")
        if "schema" in media:
            _validate_schema_shape(
                _require_object(media["schema"], "media schema"),
                ref_prefix=ref_prefix,
                named_schemas=named_schemas,
                allow_type_array=allow_type_array,
            )


def _validate_operation_shape(
    operation: dict[str, Any],
    *,
    dialect: str,
    ref_prefix: str,
    named_schemas: dict[str, Any],
    allow_type_array: bool,
    path_template_names: set[str],
) -> None:
    parameter_identities: set[tuple[str, str]] = set()
    if "parameters" in operation:
        parameter_identities = _validate_parameter_list(
            operation["parameters"],
            path_level=False,
            dialect=dialect,
            ref_prefix=ref_prefix,
            named_schemas=named_schemas,
            allow_type_array=allow_type_array,
        )
    actual_path_parameters = {
        name for location, name in parameter_identities if location == "path"
    }
    if actual_path_parameters != path_template_names:
        raise ValueError(
            "contract OpenAPI operation path parameters must exactly match path template variables"
        )
    if "requestBody" in operation:
        if dialect == "swagger":
            raise ValueError("contract Swagger 2.0 requestBody is not supported by bounded comparison")
        request_body = _require_object(operation["requestBody"], "requestBody")
        if "$ref" in request_body:
            raise ValueError(
                "contract OpenAPI referenced request bodies are not supported by bounded comparison"
            )
        if "required" in request_body and not isinstance(request_body["required"], bool):
            raise ValueError("contract OpenAPI requestBody required must be boolean for bounded comparison")
        if "content" not in request_body:
            raise ValueError("contract OpenAPI requestBody content is required for bounded comparison")
        _validate_media_content(
            request_body["content"],
            field="requestBody content",
            ref_prefix=ref_prefix,
            named_schemas=named_schemas,
            allow_type_array=allow_type_array,
        )

    if "responses" not in operation:
        raise ValueError("contract OpenAPI operation responses are required for bounded comparison")
    responses = _require_object(operation["responses"], "responses")
    if not responses:
        raise ValueError("contract OpenAPI responses must not be empty for bounded comparison")
    response_key = _SWAGGER_RESPONSE_KEY if dialect == "swagger" else _OPENAPI_RESPONSE_KEY
    for status, response_value in responses.items():
        if response_key.fullmatch(status) is None:
            raise ValueError("contract OpenAPI response status key is unsupported for bounded comparison")
        response = _require_object(response_value, "response")
        if "$ref" in response:
            raise ValueError(
                "contract OpenAPI referenced responses are not supported by bounded comparison"
            )
        description = response.get("description")
        if not isinstance(description, str):
            raise ValueError(
                "contract OpenAPI response description is required for bounded comparison"
            )
        if dialect == "swagger":
            if "schema" in response:
                _validate_schema_shape(
                    _require_object(response["schema"], "response schema"),
                    ref_prefix=ref_prefix,
                    named_schemas=named_schemas,
                    allow_type_array=allow_type_array,
                )
        elif "content" in response:
            _validate_media_content(
                response["content"],
                field="response content",
                ref_prefix=ref_prefix,
                named_schemas=named_schemas,
                allow_type_array=allow_type_array,
            )
    if "security" in operation:
        _validate_security_shape(operation["security"])


def _validate_comparison_shape(document: dict[str, Any]) -> None:
    dialect, ref_prefix, named_schemas, allow_type_array = _schema_context(document)
    if "security" in document:
        _validate_security_shape(document["security"])
    if "paths" in document:
        paths = _require_object(document["paths"], "paths")
        for path_name, path_item_value in paths.items():
            if not path_name.startswith("/"):
                raise ValueError("contract OpenAPI path keys must begin with '/' for bounded comparison")
            path_template_names = _path_template_names(path_name)
            path_item = _require_object(path_item_value, "path item")
            if "$ref" in path_item:
                raise ValueError("contract OpenAPI referenced path items are not supported by bounded comparison")
            if "parameters" in path_item:
                _validate_parameter_list(
                    path_item["parameters"],
                    path_level=True,
                    dialect=dialect,
                    ref_prefix=ref_prefix,
                    named_schemas=named_schemas,
                    allow_type_array=allow_type_array,
                )
            for key, operation_value in path_item.items():
                normalized = key.casefold()
                if normalized in _COMPARISON_METHODS:
                    if key != normalized:
                        raise ValueError("contract OpenAPI method keys must use canonical lowercase spelling")
                    _validate_operation_shape(
                        _require_object(operation_value, "operation"),
                        dialect=dialect,
                        ref_prefix=ref_prefix,
                        named_schemas=named_schemas,
                        allow_type_array=allow_type_array,
                        path_template_names=path_template_names,
                    )
    for schema_value in named_schemas.values():
        _validate_schema_shape(
            _require_object(schema_value, "named schema"),
            ref_prefix=ref_prefix,
            named_schemas=named_schemas,
            allow_type_array=allow_type_array,
        )


def load_contract_document(path: str, content: bytes) -> dict[str, Any]:
    """Parse a bounded OpenAPI/Swagger JSON-or-YAML document without ambiguous semantics."""
    if len(content) > MAX_CONTRACT_DOCUMENT_BYTES:
        raise ValueError(f"contract document exceeds {MAX_CONTRACT_DOCUMENT_BYTES} byte ingestion limit")
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
    if "openapi" in value or "swagger" in value:
        _validate_comparison_shape(value)
    return value
