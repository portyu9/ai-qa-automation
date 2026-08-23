from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, ClassVar


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
    """Conservative OpenAPI/Swagger structural drift analysis.

    This analyzer intentionally treats several schema removals/narrowings as
    breaking even when a particular consumer might tolerate them. It is a QA
    risk detector, not a substitute for a full protocol-compatibility proof.
    """

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

    def analyze(self, *, path: str, baseline: bytes, current: bytes) -> ContractDriftReport:
        try:
            old = self._load_document(path, baseline)
            new = self._load_document(path, current)
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            return ContractDriftReport(
                path=path,
                contract_kind="openapi",
                severity=ContractDriftSeverity.NOT_ANALYZED,
                changes=(),
                analyzed=False,
                reason=str(exc),
            )
        if not self._is_openapi(old) or not self._is_openapi(new):
            return ContractDriftReport(
                path=path,
                contract_kind="unknown-json-yaml",
                severity=ContractDriftSeverity.NOT_ANALYZED,
                changes=(),
                analyzed=False,
                reason="document is not recognized as OpenAPI/Swagger",
            )

        changes: list[ContractChange] = []
        self._compare_paths(old, new, changes)
        self._compare_components(old, new, changes)
        severity = self._max_severity(changes)
        return ContractDriftReport(
            path=path,
            contract_kind="openapi",
            severity=severity,
            changes=tuple(changes[:250]),
            analyzed=True,
        )

    @staticmethod
    def _load_document(path: str, content: bytes) -> dict[str, Any]:
        text = content.decode("utf-8")
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix == ".json":
            value = json.loads(text)
        elif suffix in {".yaml", ".yml"}:
            try:
                yaml = importlib.import_module("yaml")
            except ImportError as exc:
                raise ValueError(
                    "YAML OpenAPI drift requires optional PyYAML; JSON contracts remain supported"
                ) from exc
            value = yaml.safe_load(text)
        else:
            stripped = text.lstrip()
            if stripped.startswith("{"):
                value = json.loads(text)
            else:
                raise ValueError("unsupported contract serialization")
        if not isinstance(value, dict):
            raise ValueError("contract root must be an object")
        return value

    @staticmethod
    def _is_openapi(document: dict[str, Any]) -> bool:
        return isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str)

    def _compare_paths(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        changes: list[ContractChange],
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
            old_methods = {key for key in old_path if key.casefold() in self._METHODS}
            new_methods = {key for key in new_path if key.casefold() in self._METHODS}
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
                location = f"paths.{path_name}.{method}"
                self._compare_operation(
                    self._mapping(old_path[method]),
                    self._mapping(new_path[method]),
                    location,
                    changes,
                )

    def _compare_operation(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        location: str,
        changes: list[ContractChange],
    ) -> None:
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
            rule = (
                "OAS-REQUIRED-PARAMETER-ADDED"
                if severity == ContractDriftSeverity.BREAKING
                else "OAS-OPTIONAL-PARAMETER-ADDED"
            )
            changes.append(
                self._change(
                    severity,
                    f"{location}.parameters.{key}",
                    rule,
                    "Required parameter added"
                    if severity == ContractDriftSeverity.BREAKING
                    else "Optional parameter added",
                )
            )
        for key in sorted(set(old_params) & set(new_params)):
            old_param = old_params[key]
            new_param = new_params[key]
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
        elif (
            old_request
            and new_request
            and not bool(old_request.get("required"))
            and bool(new_request.get("required"))
        ):
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
            severity = (
                ContractDriftSeverity.BREAKING
                if self._is_success_status(status)
                else ContractDriftSeverity.RISKY
            )
            changes.append(
                self._change(
                    severity,
                    f"{location}.responses.{status}",
                    "OAS-RESPONSE-REMOVED",
                    "Response status removed",
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

    def _compare_components(
        self,
        old: dict[str, Any],
        new: dict[str, Any],
        changes: list[ContractChange],
    ) -> None:
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
        changes: list[ContractChange],
        *,
        depth: int = 0,
    ) -> None:
        if len(changes) >= 500:
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
        if not old and not new:
            return
        old_type = old.get("type")
        new_type = new.get("type")
        if old_type is not None and new_type is not None and old_type != new_type:
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    location,
                    "OAS-TYPE-CHANGED",
                    f"Schema type changed from {old_type!r} to {new_type!r}",
                )
            )

        old_enum = set(self._scalar_list(old.get("enum")))
        new_enum = set(self._scalar_list(new.get("enum")))
        removed_enum = sorted(old_enum - new_enum, key=str)
        if removed_enum:
            changes.append(
                self._change(
                    ContractDriftSeverity.BREAKING,
                    f"{location}.enum",
                    "OAS-ENUM-NARROWED",
                    f"Allowed enum values removed: {removed_enum[:10]}",
                )
            )
        elif new_enum - old_enum and old_enum:
            changes.append(
                self._change(
                    ContractDriftSeverity.RISKY,
                    f"{location}.enum",
                    "OAS-ENUM-WIDENED",
                    "Allowed enum values expanded; consumers with exhaustive handling may need review",
                )
            )

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
            severity = (
                ContractDriftSeverity.BREAKING
                if name in new_required
                else ContractDriftSeverity.NON_BREAKING
            )
            changes.append(
                self._change(
                    severity,
                    f"{location}.properties.{name}",
                    "OAS-PROPERTY-ADDED",
                    "Schema property added",
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
    def _scalar_list(value: Any) -> list[str | int | float | bool | None]:
        if not isinstance(value, list):
            return []
        return [item for item in value if item is None or isinstance(item, (str, int, float, bool))]

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
    def _max_severity(changes: list[ContractChange]) -> ContractDriftSeverity:
        if any(item.severity == ContractDriftSeverity.BREAKING for item in changes):
            return ContractDriftSeverity.BREAKING
        if any(item.severity == ContractDriftSeverity.RISKY for item in changes):
            return ContractDriftSeverity.RISKY
        return ContractDriftSeverity.NON_BREAKING
