from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...intelligence.performance import PerformanceAssessor
from ...models import EvidenceItem, EvidenceKind, ValidationResult, ValidationStatus
from ...redaction import redact_text
from ...tools.performance import K6Runner
from ..k6_authority import k6_gate_payload
from .common import RuntimeServices, stable_gate_id


def register_performance_tools(services: RuntimeServices, tool: Any) -> dict[str, Any]:
    @tool(
        "run_k6",
        "Run a target-bound k6 script against an explicitly non-production environment and assess thresholds.",
        {
            "script": str,
            "target_url": str,
            "environment": str,
            "max_p95_ms": float,
            "max_error_rate": float,
            "min_request_rate": float,
        },
    )
    async def run_k6(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("run_k6", args)
        try:
            gate_payload = k6_gate_payload(args)
        except ValueError as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        try:
            services.network_hosts(str(gate_payload["target_url"]))
        except PermissionError as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        if not services.k6_external_egress_enforced:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: k6 execution requires trusted infrastructure-level egress enforcement for every target, including localhost",
                    }
                ],
                "is_error": True,
            }
        runner = K6Runner(
            services.workspace,
            services.policy,
            external_egress_enforced=services.k6_external_egress_enforced,
        )
        try:
            metrics = runner.run(
                Path(str(gate_payload["script"])),
                target_url=str(gate_payload["target_url"]),
                environment=str(gate_payload["environment"]),
            )
            assessment = PerformanceAssessor().assess(
                metrics,
                max_p95_ms=float(gate_payload["max_p95_ms"]),
                max_error_rate=float(gate_payload["max_error_rate"]),
                min_request_rate=float(gate_payload["min_request_rate"]),
            )
        except PermissionError as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        except (RuntimeError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            status = ValidationStatus.NOT_VERIFIED
            services.state.validation_results.append(
                ValidationResult(
                    name="k6",
                    gate_id=stable_gate_id("k6", gate_payload),
                    revision=services.state.change_revision,
                    status=status,
                    summary=redact_text(str(exc)),
                )
            )
            services.checkpoint()
            return {
                "content": [{"type": "text", "text": f"{status.value}: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.PERFORMANCE_METRIC,
                source="k6",
                summary=assessment.summary,
                structured_data={
                    "metrics": metrics.model_dump(mode="json"),
                    "threshold_breached": assessment.status == ValidationStatus.FAIL,
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.validation_results.append(
            ValidationResult(
                name="k6",
                gate_id=stable_gate_id("k6", gate_payload),
                revision=services.state.change_revision,
                status=assessment.status,
                summary=assessment.summary,
                evidence_ids=[item.id],
                details={
                    "metrics": metrics.model_dump(mode="json"),
                    "breached_thresholds": assessment.breached_thresholds,
                },
            )
        )
        services.checkpoint()
        return {"content": [{"type": "text", "text": assessment.model_dump_json()}]}

    return {"run_k6": run_k6}
