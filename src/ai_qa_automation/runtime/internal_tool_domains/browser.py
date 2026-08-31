from __future__ import annotations

import json
from typing import Any

from ...intelligence.self_healing import SelfHealingEngine
from ...models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    FailureClass,
    LocatorCandidate,
    RiskLevel,
    ValidationStatus,
)
from ...redaction import redact_text
from ...tools.browser_evidence import BrowserProbe, BrowserProbeExecutionError
from ...tools.safe_patch import SafeTestPatcher
from ..browser_validation import (
    browser_inspection_subject,
    browser_locator_verification_subject,
    browser_validation_result,
)
from .common import (
    RuntimeServices,
    ToolDecorator,
    record_patch_safety_validation,
    require_closed_revision_before_mutation,
)


def register_browser_tools(services: RuntimeServices, tool: ToolDecorator) -> dict[str, Any]:
    @tool(
        "inspect_browser",
        "Collect allowlisted browser accessibility, screenshot, console, and network evidence.",
        {"url": str},
    )
    async def inspect_browser(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_browser", args)
        subject = browser_inspection_subject(args["url"])
        allow_hosts = services.network_hosts(args["url"])
        try:
            result = await BrowserProbe(services.evidence, allow_hosts=allow_hosts).inspect(
                args["url"]
            )
        except BrowserProbeExecutionError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            services.state.validation_results.append(
                browser_validation_result(
                    subject,
                    revision=services.state.change_revision,
                    status=ValidationStatus.NOT_VERIFIED,
                    summary="Browser evidence collection did not complete deterministically.",
                    evidence_ids=[exc.evidence_id],
                    details={"failure_kind": "browser_execution"},
                )
            )
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "BROWSER_ERROR",
                                "error": str(exc),
                                "evidence_id": exc.evidence_id,
                                "gate_id": subject.gate_id,
                            }
                        ),
                    }
                ],
                "is_error": True,
            }
        except RuntimeError as exc:
            services.state.validation_results.append(
                browser_validation_result(
                    subject,
                    revision=services.state.change_revision,
                    status=ValidationStatus.NOT_VERIFIED,
                    summary=redact_text(str(exc)),
                    details={"failure_kind": "browser_runtime"},
                )
            )
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED gate_id={subject.gate_id}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        ids = [
            evidence_id
            for evidence_id in [
                result.screenshot_evidence_id,
                result.dom_evidence_id,
                result.network_evidence_id,
            ]
            if evidence_id
        ]
        services.state.evidence_ids.extend(
            eid for eid in ids if eid not in services.state.evidence_ids
        )
        services.state.validation_results.append(
            browser_validation_result(
                subject,
                revision=services.state.change_revision,
                status=ValidationStatus.PASS,
                summary="Playwright Chromium collected browser evidence for the exact request subject.",
                evidence_ids=ids,
            )
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "url": result.url,
                            "title": result.title,
                            "accessibility_snapshot": result.accessibility_snapshot,
                            "console_errors": result.console_errors,
                            "failed_requests": result.failed_requests,
                            "http_errors": result.http_errors,
                            "evidence_ids": ids,
                            "gate_id": subject.gate_id,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "verify_locator_candidates",
        "Use Playwright to deterministically measure locator candidate uniqueness in the current DOM.",
        {"url": str, "original_locator": str, "candidates_json": str},
    )
    async def verify_locator_candidates(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("verify_locator_candidates", args)
        subject = None
        try:
            payload = json.loads(args["candidates_json"])
            if not isinstance(payload, list):
                raise ValueError("candidates_json must contain a JSON list")
            candidates = [LocatorCandidate.model_validate(item) for item in payload]
            subject = browser_locator_verification_subject(
                args["url"], args["original_locator"], candidates
            )
            allow_hosts = services.network_hosts(args["url"])
            verified, evidence_id = await BrowserProbe(
                services.evidence, allow_hosts=allow_hosts
            ).verify_locator_candidates(args["url"], args["original_locator"], candidates)
        except BrowserProbeExecutionError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            if subject is not None:
                services.state.validation_results.append(
                    browser_validation_result(
                        subject,
                        revision=services.state.change_revision,
                        status=ValidationStatus.NOT_VERIFIED,
                        summary="Browser locator verification did not complete deterministically.",
                        evidence_ids=[exc.evidence_id],
                        details={"failure_kind": "browser_execution"},
                    )
                )
            services.checkpoint()
            gate_text = f" gate_id={subject.gate_id}" if subject is not None else ""
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED{gate_text}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        except (ValueError, PermissionError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        except RuntimeError as exc:
            if subject is not None:
                services.state.validation_results.append(
                    browser_validation_result(
                        subject,
                        revision=services.state.change_revision,
                        status=ValidationStatus.NOT_VERIFIED,
                        summary=redact_text(str(exc)),
                        details={"failure_kind": "browser_runtime"},
                    )
                )
                services.checkpoint()
            gate_text = f" gate_id={subject.gate_id}" if subject is not None else ""
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED{gate_text}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        verification_item = services.evidence.get(evidence_id)
        context_ids = verification_item.structured_data.get("context_evidence_ids", [])
        registered_context_ids: list[str] = []
        if isinstance(context_ids, list):
            for context_id in context_ids:
                context_id = str(context_id)
                registered_context_ids.append(context_id)
                if context_id not in services.state.evidence_ids:
                    services.state.evidence_ids.append(context_id)
        if evidence_id not in services.state.evidence_ids:
            services.state.evidence_ids.append(evidence_id)
        if subject is None:  # pragma: no cover - assigned before browser execution
            raise RuntimeError("browser locator verification lost deterministic subject identity")
        services.state.validation_results.append(
            browser_validation_result(
                subject,
                revision=services.state.change_revision,
                status=ValidationStatus.PASS,
                summary="Playwright verified locator candidates for the exact request subject.",
                evidence_ids=[evidence_id, *registered_context_ids],
            )
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "verification_evidence_id": evidence_id,
                            "candidates": [item.model_dump(mode="json") for item in verified],
                            "gate_id": subject.gate_id,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "propose_locator_heal",
        "Evaluate only browser-verified semantic locator candidates; does not change test code.",
        {
            "path": str,
            "expected_sha256": str,
            "original_locator": str,
            "candidates_json": str,
            "verification_evidence_id": str,
        },
    )
    async def propose_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("propose_locator_heal", args)
        classification = services.state.classification
        confidence = services.state.classification_confidence or 0.0
        if (
            classification
            not in {
                FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
                FailureClass.TEST_AUTOMATION_DEFECT,
            }
            or confidence < 0.75
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: current deterministic failure classification does not support a sufficiently confident locator repair",
                    }
                ],
                "is_error": True,
            }
        try:
            verification = services.evidence.get(args["verification_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification evidence does not exist in this run",
                    }
                ],
                "is_error": True,
            }
        if (
            verification.kind != EvidenceKind.SOURCE_OBSERVATION
            or verification.nature != EvidenceNature.OBSERVED_FACT
            or verification.source != "playwright_locator_verification"
            or verification.id not in services.state.evidence_ids
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: supplied evidence is not authoritative Playwright locator verification from this run",
                    }
                ],
                "is_error": True,
            }

        all_items = {item.id: item for item in services.evidence.all()}
        context_ids = verification.structured_data.get("context_evidence_ids", [])
        if not isinstance(context_ids, list) or len(context_ids) != 2:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification is missing same-DOM context evidence",
                    }
                ],
                "is_error": True,
            }
        try:
            context_items = [all_items[str(eid)] for eid in context_ids]
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification context evidence is unavailable in this run",
                    }
                ],
                "is_error": True,
            }
        if any(item.id not in services.state.evidence_ids for item in context_items):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification context is not registered in canonical run state",
                    }
                ],
                "is_error": True,
            }
        context_kinds = {item.kind for item in context_items}
        if context_kinds != {EvidenceKind.SCREENSHOT, EvidenceKind.ACCESSIBILITY_SNAPSHOT} or any(
            item.source != "playwright_locator_verification"
            or item.source_identifier != verification.source_identifier
            for item in context_items
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator repair requires screenshot and accessibility evidence captured by the same Playwright verification",
                    }
                ],
                "is_error": True,
            }

        if (
            str(verification.structured_data.get("original_locator") or "")
            != args["original_locator"]
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: original locator does not match the browser verification evidence",
                    }
                ],
                "is_error": True,
            }
        observed_rows = verification.structured_data.get("candidates", [])
        observed_map = {
            (str(row.get("locator")), str(row.get("strategy"))): row
            for row in observed_rows
            if isinstance(row, dict)
        }
        try:
            requested = json.loads(args["candidates_json"])
            if not isinstance(requested, list):
                raise ValueError("candidates_json must contain a JSON list")
            bound: list[LocatorCandidate] = []
            for raw in requested:
                candidate = LocatorCandidate.model_validate(raw)
                observed = observed_map.get((candidate.locator, candidate.strategy))
                if observed is None:
                    raise ValueError(
                        "candidate was not measured by the supplied Playwright verification evidence"
                    )
                bound.append(
                    candidate.model_copy(
                        update={
                            "uniqueness_count": int(observed.get("uniqueness_count", 0)),
                            "rejected_reason": observed.get("rejected_reason"),
                        }
                    )
                )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }

        proposal = SelfHealingEngine().propose(
            classification=classification,
            original_locator=args["original_locator"],
            candidates=bound,
            evidence_ids=[verification.id],
            policy=services.policy,
        )
        proposal_item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.HEALING_PROPOSAL,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="self_healing_engine",
                source_identifier=verification.id,
                summary="Locator healing proposal evaluated against browser-verified candidates",
                structured_data={
                    **proposal.model_dump(mode="json"),
                    "path": args["path"],
                    "expected_sha256": args["expected_sha256"],
                    "classification": classification.value,
                    "classification_confidence": confidence,
                    "verification_evidence_id": verification.id,
                },
            )
        )
        services.state.evidence_ids.append(proposal_item.id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "proposal_evidence_id": proposal_item.id,
                            "proposal": proposal.model_dump(mode="json"),
                        }
                    ),
                }
            ],
            "is_error": not proposal.allowed,
        }

    @tool(
        "apply_locator_heal",
        "Apply one previously approved, browser-verified locator proposal to its bound test file.",
        {"proposal_evidence_id": str, "path": str},
    )
    async def apply_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("apply_locator_heal", args)
        if reason := require_closed_revision_before_mutation(services):
            return {"content": [{"type": "text", "text": f"DENIED: {reason}"}], "is_error": True}
        try:
            proposal_item = services.evidence.get(args["proposal_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: healing proposal evidence does not exist in this run",
                    }
                ],
                "is_error": True,
            }
        data = proposal_item.structured_data
        if (
            proposal_item.kind != EvidenceKind.HEALING_PROPOSAL
            or proposal_item.nature != EvidenceNature.MODEL_INTERPRETATION
            or proposal_item.id not in services.state.evidence_ids
            or data.get("allowed") is not True
            or data.get("risk") not in {RiskLevel.LOW.value, RiskLevel.MEDIUM.value}
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: proposal is not an approved low/medium-risk healing decision from this run",
                    }
                ],
                "is_error": True,
            }
        path = str(data.get("path") or "")
        if str(args.get("path") or "") != path:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: requested path does not match the path bound into the healing proposal",
                    }
                ],
                "is_error": True,
            }
        expected_sha256 = str(data.get("expected_sha256") or "")
        original_locator = str(data.get("original_locator") or "")
        proposed_locator = str(data.get("proposed_locator") or "")
        if not all((path, expected_sha256, original_locator, proposed_locator)):
            return {
                "content": [{"type": "text", "text": "DENIED: healing proposal is incomplete"}],
                "is_error": True,
            }
        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.replace_locator_once(
                relative_path=path,
                expected_sha256=expected_sha256,
                old_locator=original_locator,
                new_locator=proposed_locator,
            )
        except (PermissionError, RuntimeError, ValueError, FileNotFoundError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        services.state.change_revision += 1
        services.state.files_modified.append(result.path)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.GIT_DIFF,
                source="safe_test_patcher",
                source_identifier=proposal_item.id,
                summary="Browser-verified locator replacement applied; execution validation still required",
                structured_data={
                    "path": result.path,
                    "old_sha256": result.old_sha256,
                    "new_sha256": result.new_sha256,
                    "diff": result.diff[:12000],
                    "proposal_evidence_id": proposal_item.id,
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        record_patch_safety_validation(
            services,
            path=result.path,
            evidence_id=item.id,
            summary="Locator-only patch passed deterministic path, syntax, quality, and unsafe-diff checks.",
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"LOCATOR_PATCH_APPLIED evidence_id={item.id} revision={services.state.change_revision}; run targeted test and relevant regression next",
                }
            ]
        }

    return {
        "inspect_browser": inspect_browser,
        "verify_locator_candidates": verify_locator_candidates,
        "propose_locator_heal": propose_locator_heal,
        "apply_locator_heal": apply_locator_heal,
    }
