from __future__ import annotations

import json
from typing import Any

from ...intelligence.ci_analysis import analyze_ci_failure
from ...intelligence.failure_analysis import FailureAnalyzer
from ...redaction import redact_text
from ...tools.contracts import validate_json_schema
from ...tools.mobile import MobileRuntimeInspector
from .common import RuntimeServices, ToolDecorator, stable_gate_id


def register_validation_tools(services: RuntimeServices, tool: ToolDecorator) -> dict[str, Any]:
    @tool(
        "classify_failure",
        "Classify currently collected evidence with a deterministic first-pass classifier.",
        {},
    )
    async def classify_failure(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("classify_failure", args)
        result = FailureAnalyzer().classify(services.evidence.all())
        services.state.classification = result.classification
        services.state.classification_confidence = result.confidence
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "validate_json_contract",
        "Validate a JSON instance against a JSON Schema deterministically.",
        {"instance_json": str, "schema_json": str},
    )
    async def validate_json_contract(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("validate_json_contract", args)
        try:
            if len(args["instance_json"]) > 1_000_000 or len(args["schema_json"]) > 1_000_000:
                raise ValueError("JSON contract inputs exceed 1 MB limit")
            instance = json.loads(args["instance_json"])
            schema = json.loads(args["schema_json"])
            result = validate_json_schema(instance, schema)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        result = result.model_copy(
            update={
                "gate_id": stable_gate_id(
                    "json_schema",
                    {"instance": instance, "schema": schema},
                ),
                "revision": services.state.change_revision,
            }
        )
        services.state.validation_results.append(result)
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "analyze_ci_failure",
        "Classify a CI command failure from an exit code and sanitized log tail.",
        {"exit_code": int, "log_tail": str},
    )
    async def analyze_ci_failure_tool(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("analyze_ci_failure", args)
        signal = analyze_ci_failure(
            exit_code=int(args["exit_code"]), log_tail=redact_text(args["log_tail"][-12000:])
        )
        return {"content": [{"type": "text", "text": json.dumps(signal.__dict__)}]}

    @tool(
        "inspect_mobile_runtime",
        "Report whether an Appium mobile runtime is actually configured.",
        {},
    )
    async def inspect_mobile_runtime(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_mobile_runtime", args)
        result = MobileRuntimeInspector().inspect()
        result = result.model_copy(
            update={"gate_id": "mobile_runtime", "revision": services.state.change_revision}
        )
        services.state.validation_results.append(result)
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    return {
        "classify_failure": classify_failure,
        "validate_json_contract": validate_json_contract,
        "analyze_ci_failure": analyze_ci_failure_tool,
        "inspect_mobile_runtime": inspect_mobile_runtime,
    }
