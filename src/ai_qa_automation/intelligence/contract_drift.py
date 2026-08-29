from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar

from .contract_document import load_contract_document

_MAX_COMPARISON_CHANGES = 250
_OPENAPI_VERSION = re.compile(r"^3\.(?:0|1)\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class ContractDriftSeverity(StrEnum):
    BREAKING = "BREAKING"
    RISKY = "RISKY"
    NON_BREAKING = "NON_BREAKING"
    NOT_ANALYZED = "NOT_ANALYZED"


@dataclass(frozen=True)
class ContractChange:
    severity: ContractDriftSeverity
    location: str
    rule_id: str
    summary: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity.value,
            "location": self.location,
            "rule_id": self.rule_id,
            "summary": self.summary,
        }


class _BoundedChanges(list[ContractChange]):
    """Retain reportable findings while tracking omitted authority-relevant truth."""

    def __init__(self) -> None:
        super().__init__()
        self.incomplete = False
        self.suppressed_breaking = False

    def append(self, item: ContractChange) -> None:
        if len(self) < _MAX_COMPARISON_CHANGES:
            super().append(item)
            return
        self.incomplete = True
        if item.severity == ContractDriftSeverity.BREAKING:
            self.suppressed_breaking = True
            for index in range(len(self) - 1, -1, -1):
                if self[index].severity != ContractDriftSeverity.BREAKING:
                    self[index] = item
                    break

    def mark_incomplete(self) -> None:
        self.incomplete = True


@dataclass(frozen=True)
class ContractDriftReport:
    path: str
    contract_kind: str
    severity: ContractDriftSeverity
    changes: tuple[ContractChange, ...]
    analyzed: bool
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "contract_kind": self.contract_kind,
            "severity": self.severity.value,
            "changes": [item.as_dict() for item in self.changes],
            "analyzed": self.analyzed,
            "reason": self.reason,
        }


class OpenAPIContractDriftAnalyzer:
    """Conservative bounded OpenAPI/Swagger structural drift analysis."""

    _METHODS: ClassVar[set[str]] = {
        "get",
        "put",
        "post",
        "delete",
        "options",
        "head",
        "patch",
        "trace",
    }
    _SCHEMA_MODELED_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"$ref", "type", "enum", "required", "properties", "items"}
    )
    _SCHEMA_ANNOTATION_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"title", "description", "example", "examples", "externalDocs", "xml"}
    )

    def analyze(self, *, path: str, baseline: bytes, current: bytes) -> ContractDriftReport:
        try:
            old = self._load_document(path, baseline)
            new = self._load_document(path, current)
        except (ValueError, UnicodeError) as exc:
            return ContractDriftReport(
                path=path,
                contract_kind="openapi",
                severity=ContractDriftSeverity.NOT_ANALYZED,
                changes=(),
                analyzed=False,
                reason=str(exc),
            )

        old_identity = self._contract_identity(old)
        new_identity = self._contract_identity(new)
        if old_identity is None or new_identity is None:
            reason = (
                "document is not recognized as OpenAPI/Swagger"
                if not self._has_contract_marker(old) or not self._has_contract_marker(new)
                else "document has an unsupported or ambiguous OpenAPI/Swagger dialect"
            )
            return ContractDriftReport(
                path=path,
                contract_kind="unknown-json-yaml",
                severity=ContractDriftSeverity.NOT_ANALYZED,
                changes=(),
                analyzed=False,
                reason=reason,
            )
        if old_identity != new_identity:
            return ContractDriftReport(
                path=path,
                contract_kind="openapi",
                severity=ContractDriftSeverity.NOT_ANALYZED,
                changes=(),
                analyzed=False,
                reason="cross-dialect or cross-version contract comparison is not supported",
            )

        changes = _BoundedChanges()
        self._compare_document_remainder(old, new, changes)
        self._compare_paths(old, new, changes)
        self._compare_components(old, new, changes)
        comparison_incomplete = changes.incomplete or any(
            item.severity == ContractDriftSeverity.NOT_ANALYZED for item in changes
        )
        severity = self._max_severity(changes)
        if comparison_incomplete and severity != ContractDriftSeverity.BREAKING:
            severity = ContractDriftSeverity.NOT_ANALYZED
        return ContractDriftReport(
            path=path,
            contract_kind="openapi",
            severity=severity,
            changes=tuple(changes),
            analyzed=not comparison_incomplete,
            reason=(
                "contract comparison exceeded a deterministic analysis bound"
                if comparison_incomplete
                else None
            ),
        )

    @staticmethod
    def _load_document(path: str, content: bytes) -> dict[str, Any]:
        return load_contract_document(path, content)

    @staticmethod
    def _has_contract_marker(document: dict[str, Any]) -> bool:
        return "openapi" in document or "swagger" in document

    @staticmethod
    def _contract_identity(document: dict[str, Any]) -> tuple[str, str] | None:
        openapi = document.get("openapi")
        swagger = document.get("swagger")
        has_openapi = isinstance(openapi, str)
        has_swagger = isinstance(swagger, str)
        if has_openapi == has_swagger:
            return None
        if has_openapi:
            if not isinstance(openapi, str):
                return None
            if _OPENAPI_VERSION.fullmatch(openapi) is None:
                return None
            return ("openapi", openapi)
        if not isinstance(swagger, str):
            return None
        if swagger != "2.0":
            return None
        return ("swagger", swagger)

    def _compare_document_remainder(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        changes: _BoundedChanges,
    ) -> None:
        ignored = {"openapi", "swagger", "info", "paths", "components", "definitions"}
        if self._without_keys(old, ignored) != self._without_keys(new, ignored):
            changes.append(
                self._change(
                    ContractDriftSeverity.NOT_ANALYZED,
                    "document",
                    "OAS-DOCUMENT-SEMANTICS-UNMODELED",
                    "Contract-level semantics outside the bounded comparison model changed",
                )
            )

    def _compare_paths(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        changes: _BoundedChanges,
    ) -> None:
        old_paths = self._mapping(old.get("paths"))
        new_paths = self._mapping(new.get("paths"))
        for path_name in sorted(set(old_paths) - set(new_paths)):
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"paths.{path_name}",
                    "OAS-PATH-REMOVED",
                    "API path removed",
                )
            )
        for path_name in sorted(set(new_paths) - set(old_paths)):
            changes.append(
                self._change(
                    ContractDriftSeverity.NON_BREAKING,
                    f"paths.{path_name}",
                    "OAS-PATH-ADDED",
                    "API path added",
                )
            )
        for path_name in sorted(set(old_paths) & set(new_paths)):
            old_path = self._mapping(old_paths[path_name])
            new_path = self._mapping(new_paths[path_name])
            self._compare_mapping_remainder(
                old_path,
                new_path,
                handled=self._METHODS | {"parameters"},
                ignored={"summary", "description"},
                location=f"paths.{path_name}",
                rule_id="OAS-PATH-SEMANTICS-UNMODELED",
                summary="Path-item semantics outside the bounded comparison model changed",
                changes=changes,
            )
            old_methods = {key for key in old_path if key in self._METHODS}
            new_methods = {key for key in new_path if key in self._METHODS}
            for method in sorted(old_methods - new_methods):
                changes.append(
                    self._change(
                        ContractDriftSeverity.BREAKING,
                        f"paths.{path_name}.{method}",
                        "OAS-OPERATION-REMOVED",
                        "HTTP operation removed",
                    )
                )
            for method in sorted(new_methods - old_methods):
                changes.append(
                    self._change(
                        ContractDriftSeverity.NON_BREAKING,
                        f"paths.{path_name}.{method}",
                        "OAS-OPERATION-ADDED",
                        "HTTP operation added",
                    )
                )
            for method in sorted(old_methods & new_methods):
                self._compare_operation(
                    self._mapping(old_path[method]),
                    self._mapping(new_path[method]),
                    f"paths.{path_name}.{method}",
                    changes,
                )

    def _compare_operation(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        location: str,
        changes: _BoundedChanges,
    ) -> None:
        self._compare_mapping_remainder(
            old,
            new,
            handled={"parameters", "requestBody", "responses", "security"},
            ignored={"summary", "description", "operationId", "tags"},
            location=location,
            rule_id="OAS-OPERATION-SEMANTICS-UNMODELED",
            summary="Operation semantics outside the bounded comparison model changed",
            changes=changes,
        )
        old_params = self._parameter_index(old.get("parameters"))
        new_params = self._parameter_index(new.get("parameters"))
        for key in sorted(set(old_params) - set(new_params)):
            changes.append(
                self._change(
                    ContractDriftSeverity.RISKY,
                    f"{location}.parameters.{key}",
                    "OAS-PARAMETER-REMOVED",
                    "Operation parameter removed",
                )
            )
        for key in sorted(set(new_params) - set(old_params)):
            param = new_params[key]
            severity = (
                ContractDriftSeverity.BREAKING
                if bool(param.get("required"))
                else ContractDriftSeverity.NON_BREAKING
            )
            changes.append(
                self._change(
                    severity,
                    f"{location}.parameters.{key}",
                    "OAS-REQUIRED-PARAMETER-ADDED"
                    if severity == ContractDriftSeverity.BREAKING
                    else "OAS-OPTIONAL-PARAMETER-ADDED",
                    "Required parameter added"
                    if severity == ContractDriftSeverity.BREAKING
                    else "Optional parameter added",
                )
            )
        for key in sorted(set(old_params) & set(new_params)):
            old_param = old_params[key]
            new_param = new_params[key]
            self._compare_mapping_remainder(
                old_param,
                new_param,
                handled={"name", "in", "required", "schema"},
                ignored={"description"},
                location=f"{location}.parameters.{key}",
                rule_id="OAS-PARAMETER-SEMANTICS-UNMODELED",
                summary="Parameter semantics outside the bounded comparison model changed",
                changes=changes,
            )
            if not bool(old_param.get("required")) and bool(new_param.get("required")):
                changes.append(
                    self._change(
                        ContractDriftSeverity.BREAKING,
                        f"{location}.parameters.{key}",
                        "OAS-PARAMETER-BECAME-REQUIRED",
                        "Existing parameter became required",
                    )
                )
            self._compare_schema(
                self._mapping(old_param.get("schema")),
                self._mapping(new_param.get("schema")),
                f"{location}.parameters.{key}.schema",
                changes,
            )

        old_request = self._mapping(old.get("requestBody"))
        new_request = self._mapping(new.get("requestBody"))
        if old_request and not new_request:
            changes.append(
                self._change(
                    ContractDriftSeverity.RISKY,
                    f"{location}.requestBody",
                    "OAS-REQUEST-BODY-REMOVED",
                    "Request body removed",
                )
            )
        elif new_request and not old_request:
            severity = (
                ContractDriftSeverity.BREAKING
                if bool(new_request.get("required"))
                else ContractDriftSeverity.NON_BREAKING
            )
            changes.append(
                self._change(
                    severity,
                    f"{location}.requestBody",
                    "OAS-REQUEST-BODY-ADDED",
                    "Request body added",
                )
            )
        elif old_request and new_request:
            self._compare_mapping_remainder(
                old_request,
                new_request,
                handled={"required"},
                ignored={"description"},
                location=f"{location}.requestBody",
                rule_id="OAS-REQUEST-BODY-SEMANTICS-UNMODELED",
                summary="Request-body semantics outside the bounded comparison model changed",
                changes=changes,
            )
            if not bool(old_request.get("required")) and bool(new_request.get("required")):
                changes.append(
                    self._change(
                        ContractDriftSeverity.BREAKING,
                        f"{location}.requestBody",
                        "OAS-REQUEST-BODY-BECAME-REQUIRED",
                        "Request body became required",
                    )
                )

        old_responses = self._mapping(old.get("responses"))
        new_responses = self._mapping(new.get("responses"))
        for status in sorted(set(old_responses) - set(new_responses)):
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING
                    if self._is_success_status(status)
                    else ContractDriftSeverity.RISKY,
                    f"{location}.responses.{status}",
                    "OAS-RESPONSE-REMOVED",
                    "Response status removed",
                )
            )
        for status in sorted(set(new_responses) - set(old_responses)):
            changes.append(
                self._change(
                    ContractDriftSeverity.RISKY,
                    f"{location}.responses.{status}",
                    "OAS-RESPONSE-ADDED",
                    "Response status added; consumers may need to handle a new outcome",
                )
            )
        for status in sorted(set(old_responses) & set(new_responses)):
            old_response = self._mapping(old_responses[status])
            new_response = self._mapping(new_responses[status])
            if self._without_keys(old_response, {"description"}) != self._without_keys(
                new_response, {"description"}
            ):
                changes.append(
                    self._change(
                        ContractDriftSeverity.NOT_ANALYZED,
                        f"{location}.responses.{status}",
                        "OAS-RESPONSE-SEMANTICS-UNMODELED",
                        "Response semantics outside the bounded comparison model changed",
                    )
                )

        old_security = old.get("security")
        new_security = new.get("security")
        if not old_security and new_security:
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"{location}.security",
                    "OAS-SECURITY-REQUIRED",
                    "Operation now declares security requirements",
                )
            )
        elif old_security != new_security:
            changes.append(
                self._change(
                    ContractDriftSeverity.NOT_ANALYZED,
                    f"{location}.security",
                    "OAS-SECURITY-SEMANTICS-UNMODELED",
                    "Operation security requirements changed outside the bounded comparison model",
                )
            )

    def _compare_components(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        changes: _BoundedChanges,
    ) -> None:
        old_components = self._mapping(old.get("components"))
        new_components = self._mapping(new.get("components"))
        if self._without_keys(old_components, {"schemas"}) != self._without_keys(
            new_components, {"schemas"}
        ):
            changes.append(
                self._change(
                    ContractDriftSeverity.NOT_ANALYZED,
                    "components",
                    "OAS-COMPONENT-SEMANTICS-UNMODELED",
                    "Non-schema component semantics changed outside the bounded comparison model",
                )
            )

        old_schemas = self._schemas(old)
        new_schemas = self._schemas(new)
        for name in sorted(set(old_schemas) - set(new_schemas)):
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"schemas.{name}",
                    "OAS-SCHEMA-REMOVED",
                    "Named schema removed",
                )
            )
        for name in sorted(set(new_schemas) - set(old_schemas)):
            changes.append(
                self._change(
                    ContractDriftSeverity.NON_BREAKING,
                    f"schemas.{name}",
                    "OAS-SCHEMA-ADDED",
                    "Named schema added",
                )
            )
        for name in sorted(set(old_schemas) & set(new_schemas)):
            self._compare_schema(old_schemas[name], new_schemas[name], f"schemas.{name}", changes)

    def _compare_schema(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        location: str,
        changes: _BoundedChanges,
        *,
        depth: int = 0,
    ) -> None:
        if not old and not new:
            return
        if len(changes) >= _MAX_COMPARISON_CHANGES:
            changes.mark_incomplete()
            return
        if depth > 12:
            changes.append(
                self._change(
                    ContractDriftSeverity.NOT_ANALYZED,
                    location,
                    "OAS-SCHEMA-DEPTH-LIMIT",
                    "Nested schema comparison exceeded the bounded depth limit",
                )
            )
            return

        if self._schema_remainder(old) != self._schema_remainder(new):
            changes.append(
                self._change(
                    ContractDriftSeverity.NOT_ANALYZED,
                    location,
                    "OAS-SCHEMA-SEMANTICS-UNMODELED",
                    "Schema semantics outside the bounded comparison model changed",
                )
            )

        old_ref = old.get("$ref")
        new_ref = new.get("$ref")
        if old_ref != new_ref:
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    location,
                    "OAS-SCHEMA-REF-CHANGED",
                    "Schema reference target changed",
                )
            )

        old_types = self._type_set(old.get("type"))
        new_types = self._type_set(new.get("type"))
        if old_types != new_types:
            if old_types is None and new_types is not None:
                severity = ContractDriftSeverity.BREAKING
                rule = "OAS-TYPE-CONSTRAINT-ADDED"
                summary = "Schema type constraint added"
            elif old_types is not None and new_types is None:
                severity = ContractDriftSeverity.RISKY
                rule = "OAS-TYPE-CONSTRAINT-REMOVED"
                summary = "Schema type constraint removed"
            elif old_types is not None and new_types is not None:
                removed = old_types - new_types
                severity = (
                    ContractDriftSeverity.BREAKING if removed else ContractDriftSeverity.RISKY
                )
                rule = "OAS-TYPE-NARROWED" if removed else "OAS-TYPE-WIDENED"
                summary = (
                    "Schema type choices removed or replaced"
                    if removed
                    else "Schema type choices expanded"
                )
            else:
                changes.mark_incomplete()
                return
            changes.append(self._change(severity, location, rule, summary))

        old_enum = self._enum_map(old.get("enum"))
        new_enum = self._enum_map(new.get("enum"))
        if old_enum != new_enum:
            if old_enum is None and new_enum is not None:
                changes.append(
                    self._change(
                        ContractDriftSeverity.BREAKING,
                        f"{location}.enum",
                        "OAS-ENUM-CONSTRAINT-ADDED",
                        "Allowed values were newly constrained by an enum",
                    )
                )
            elif old_enum is not None and new_enum is None:
                changes.append(
                    self._change(
                        ContractDriftSeverity.RISKY,
                        f"{location}.enum",
                        "OAS-ENUM-CONSTRAINT-REMOVED",
                        "Enum constraint removed; exhaustive consumers may need review",
                    )
                )
            elif old_enum is not None and new_enum is not None:
                removed_keys = old_enum.keys() - new_enum.keys()
                added_keys = new_enum.keys() - old_enum.keys()
                if removed_keys:
                    changes.append(
                        self._change(
                            ContractDriftSeverity.BREAKING,
                            f"{location}.enum",
                            "OAS-ENUM-NARROWED",
                            "Allowed enum values removed or replaced",
                        )
                    )
                elif added_keys:
                    changes.append(
                        self._change(
                            ContractDriftSeverity.RISKY,
                            f"{location}.enum",
                            "OAS-ENUM-WIDENED",
                            "Allowed enum values expanded; consumers with exhaustive handling may need review",
                        )
                    )
            else:
                changes.mark_incomplete()
                return

        old_required = set(self._string_list(old.get("required")))
        new_required = set(self._string_list(new.get("required")))
        for name in sorted(new_required - old_required):
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"{location}.required.{name}",
                    "OAS-REQUIRED-PROPERTY-ADDED",
                    "Schema property became required",
                )
            )
        for name in sorted(old_required - new_required):
            changes.append(
                self._change(
                    ContractDriftSeverity.RISKY,
                    f"{location}.required.{name}",
                    "OAS-REQUIRED-PROPERTY-REMOVED",
                    "Schema property is no longer required; consumers may need review",
                )
            )

        old_props = self._mapping(old.get("properties"))
        new_props = self._mapping(new.get("properties"))
        for name in sorted(set(old_props) - set(new_props)):
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"{location}.properties.{name}",
                    "OAS-PROPERTY-REMOVED",
                    "Schema property removed",
                )
            )
        for name in sorted(set(new_props) - set(old_props)):
            required = name in new_required
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING if required else ContractDriftSeverity.RISKY,
                    f"{location}.properties.{name}",
                    "OAS-PROPERTY-ADDED",
                    "Required schema property added"
                    if required
                    else "Optional schema property added; response consumers may need review",
                )
            )
        for name in sorted(set(old_props) & set(new_props)):
            self._compare_schema(
                self._mapping(old_props[name]),
                self._mapping(new_props[name]),
                f"{location}.properties.{name}",
                changes,
                depth=depth + 1,
            )

        old_items = self._mapping(old.get("items"))
        new_items = self._mapping(new.get("items"))
        if old_items or new_items:
            self._compare_schema(
                old_items,
                new_items,
                f"{location}.items",
                changes,
                depth=depth + 1,
            )

    @staticmethod
    def _schemas(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
        components = OpenAPIContractDriftAnalyzer._mapping(document.get("components"))
        raw = components.get("schemas") if components else None
        if raw is None:
            definitions = document.get("definitions")
            raw = definitions if isinstance(definitions, dict) else {}
        mapping = OpenAPIContractDriftAnalyzer._mapping(raw)
        return {
            str(name): OpenAPIContractDriftAnalyzer._mapping(value)
            for name, value in mapping.items()
        }

    @staticmethod
    def _parameter_index(value: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(value, list):
            return {}
        result: dict[str, dict[str, Any]] = {}
        for raw in value:
            if not isinstance(raw, dict) or "$ref" in raw:
                continue
            name = raw.get("name")
            location = raw.get("in")
            if isinstance(name, str) and isinstance(location, str):
                result[f"{location}:{name}"] = raw
        return result

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []

    @staticmethod
    def _type_set(value: Any) -> frozenset[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            return frozenset({value})
        if isinstance(value, list):
            return frozenset(item for item in value if isinstance(item, str))
        return None

    @staticmethod
    def _enum_identity(value: str | int | float | bool | None) -> tuple[str, object]:
        if value is None:
            return ("null", "")
        if isinstance(value, bool):
            return ("boolean", value)
        if isinstance(value, str):
            return ("string", value)
        return ("number", value)

    @classmethod
    def _enum_map(
        cls, value: Any
    ) -> dict[tuple[str, object], str | int | float | bool | None] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            return None
        result: dict[tuple[str, object], str | int | float | bool | None] = {}
        for item in value:
            if item is None or isinstance(item, (str, int, float, bool)):
                result[cls._enum_identity(item)] = item
        return result

    @classmethod
    def _schema_remainder(cls, value: dict[str, Any]) -> dict[str, Any]:
        return cls._without_keys(value, cls._SCHEMA_MODELED_KEYS | cls._SCHEMA_ANNOTATION_KEYS)

    @staticmethod
    def _without_keys(value: dict[str, Any], keys: set[str] | frozenset[str]) -> dict[str, Any]:
        return {key: item for key, item in value.items() if key not in keys}

    def _compare_mapping_remainder(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        *,
        handled: set[str],
        ignored: set[str],
        location: str,
        rule_id: str,
        summary: str,
        changes: _BoundedChanges,
    ) -> None:
        excluded = handled | ignored
        if self._without_keys(old, excluded) != self._without_keys(new, excluded):
            changes.append(
                self._change(ContractDriftSeverity.NOT_ANALYZED, location, rule_id, summary)
            )

    @staticmethod
    def _is_success_status(value: str) -> bool:
        normalized = str(value).upper()
        return normalized.startswith("2") or normalized == "DEFAULT"

    @staticmethod
    def _change(
        severity: ContractDriftSeverity, location: str, rule_id: str, summary: str
    ) -> ContractChange:
        return ContractChange(
            severity=severity, location=location, rule_id=rule_id, summary=summary
        )

    @staticmethod
    def _max_severity(changes: _BoundedChanges) -> ContractDriftSeverity:
        if changes.suppressed_breaking or any(
            item.severity == ContractDriftSeverity.BREAKING for item in changes
        ):
            return ContractDriftSeverity.BREAKING
        if any(item.severity == ContractDriftSeverity.NOT_ANALYZED for item in changes):
            return ContractDriftSeverity.NOT_ANALYZED
        if any(item.severity == ContractDriftSeverity.RISKY for item in changes):
            return ContractDriftSeverity.RISKY
        return ContractDriftSeverity.NON_BREAKING
