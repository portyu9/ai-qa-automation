from __future__ import annotations

import json
from typing import Any

from ...intelligence.self_healing import SelfHealingEngine
from ...models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
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
from ..locator_repair import (
    LocatorRepairAuthority,
    LocatorRepairAuthorityError,
    build_locator_repair_subject,
    prepare_locator_repair_binding,
    resolve_locator_repair_authority,
)
from .common import (
    RuntimeServices,
    ToolDecorator,
    record_patch_safety_validation,
    require_closed_revision_before_mutation,
)

_MAX_LOCATOR_CANDIDATES = 20
_MAX_CANDIDATES_JSON_BYTES = 100_000


def _parse_candidates_json(value: str) -> list[LocatorCandidate]:
    if len(value.encode("utf-8")) > _MAX_CANDIDATES_JSON_BYTES:
        raise ValueError("candidates_json exceeds the bounded locator-candidate input limit")
    payload = json.loads(value)
    if not isinstance(payload, list) or len(payload) > _MAX_LOCATOR_CANDIDATES:
        raise ValueError("candidates_json must contain at most 20 candidates")
    return [LocatorCandidate.model_validate(item) for item in payload]


def _bind_requested_candidates(
    authority: LocatorRepairAuthority,
    requested: list[LocatorCandidate],
) -> list[LocatorCandidate]:
    observed_rows = authority.verification.structured_data.get("candidates")
    if not isinstance(observed_rows, list) or len(observed_rows) > _MAX_LOCATOR_CANDIDATES:
        raise ValueError("repair subject contains malformed locator-candidate observations")

    bound: list[LocatorCandidate] = []
    for candidate in requested:
        matches = [
            row
            for row in observed_rows
            if isinstance(row, dict)
            and row.get("locator") == candidate.locator
            and row.get("strategy") == candidate.strategy
        ]
        if len(matches) != 1:
            raise ValueError(
                "candidate does not resolve uniquely in the repair subject's Playwright observation"
            )
        observed = matches[0]
        count = observed.get("uniqueness_count")
        rejected = observed.get("rejected_reason")
        if type(count) is not int or count < 0:
            raise ValueError("observed locator uniqueness count is malformed")
        if rejected is not None and not isinstance(rejected, str):
            raise ValueError("observed locator rejection reason is malformed")
        bound.append(
            candidate.model_copy(
                update={
                    "uniqueness_count": count,
                    "rejected_reason": rejected,
                }
            )
        )
    return bound


def _revalidate_proposed_locator(
    services: RuntimeServices,
    authority: LocatorRepairAuthority,
    *,
    proposed_locator: str,
    expected_risk: object,
) -> None:
    rows = authority.verification.structured_data.get("candidates")
    if not isinstance(rows, list):
        raise ValueError("repair subject lost locator-candidate observations")
    matches = [
        row for row in rows if isinstance(row, dict) and row.get("locator") == proposed_locator
    ]
    if len(matches) != 1:
        raise ValueError("proposed locator does not resolve uniquely in Playwright evidence")
    row = matches[0]
    strategy = row.get("strategy")
    count = row.get("uniqueness_count")
    rejected = row.get("rejected_reason")
    if not isinstance(strategy, str) or type(count) is not int or count < 0:
        raise ValueError("proposed locator observation is malformed")
    if rejected is not None and not isinstance(rejected, str):
        raise ValueError("proposed locator rejection state is malformed")

    candidate = LocatorCandidate(
        locator=proposed_locator,
        strategy=strategy,
        uniqueness_count=count,
        semantic_match=0.0,
        stability_score=0.0,
        rejected_reason=rejected,
    )
    replay = SelfHealingEngine().propose(
        classification=authority.classification,
        original_locator=authority.original_locator,
        candidates=[candidate],
        evidence_ids=list(authority.validation.evidence_ids),
        policy=services.policy,
    )
    if (
        replay.allowed is not True
        or replay.proposed_locator != proposed_locator
        or replay.risk.value != expected_risk
    ):
        raise ValueError(
            "stored healing proposal no longer reproduces under deterministic locator policy"
        )


def register_browser_tools(
    services: RuntimeServices,
    tool: ToolDecorator,
    *,
    browser_probe_cls: Any = BrowserProbe,
) -> dict[str, Any]:
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
            result = await browser_probe_cls(services.evidence, allow_hosts=allow_hosts).inspect(
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
        "Bind one failing targeted pytest node, then use Playwright to verify locator candidates against its exact repair authority.",
        {
            "url": str,
            "failure_validation_id": str,
            "original_locator": str,
            "candidates_json": str,
        },
    )
    async def verify_locator_candidates(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("verify_locator_candidates", args)
        try:
            candidates = _parse_candidates_json(args["candidates_json"])
            binding = prepare_locator_repair_binding(
                workspace=services.workspace,
                expected_root_identity=services.workspace_root_identity,
                state=services.state,
                evidence=services.evidence,
                policy=services.policy,
                failure_validation_id=args["failure_validation_id"],
                original_locator=args["original_locator"],
            )
            subject = browser_locator_verification_subject(
                args["url"], args["original_locator"], candidates
            )
            allow_hosts = services.network_hosts(args["url"])
        except (
            LocatorRepairAuthorityError,
            ValueError,
            PermissionError,
            RuntimeError,
            OSError,
            UnicodeError,
        ) as exc:
            services.checkpoint()
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }

        try:
            verified, evidence_id = await browser_probe_cls(
                services.evidence, allow_hosts=allow_hosts
            ).verify_locator_candidates(args["url"], args["original_locator"], candidates)
        except BrowserProbeExecutionError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
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
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED gate_id={subject.gate_id}: {redact_text(str(exc))}",
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

        verification_item = services.evidence.get(evidence_id)
        context_ids = verification_item.structured_data.get("context_evidence_ids", [])
        registered_context_ids: list[str] = []
        if isinstance(context_ids, list):
            for context_id in context_ids:
                if not isinstance(context_id, str) or not context_id:
                    continue
                registered_context_ids.append(context_id)
                if context_id not in services.state.evidence_ids:
                    services.state.evidence_ids.append(context_id)
        if evidence_id not in services.state.evidence_ids:
            services.state.evidence_ids.append(evidence_id)

        browser_evidence_ids = [evidence_id, *registered_context_ids]
        try:
            repair_subject = build_locator_repair_subject(
                binding,
                workspace=services.workspace,
                expected_root_identity=services.workspace_root_identity,
                state=services.state,
                evidence=services.evidence,
                verification=verification_item,
                browser_gate_id=subject.gate_id,
                browser_subject_details=subject.details,
            )
        except (LocatorRepairAuthorityError, RuntimeError, OSError, UnicodeError) as exc:
            services.state.validation_results.append(
                browser_validation_result(
                    subject,
                    revision=services.state.change_revision,
                    status=ValidationStatus.PASS,
                    summary="Playwright verified locator candidates for the exact request subject.",
                    evidence_ids=browser_evidence_ids,
                )
            )
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"NOT_VERIFIED locator_repair_subject browser_gate_id={subject.gate_id}: "
                            f"{redact_text(str(exc))}"
                        ),
                    }
                ],
                "is_error": True,
            }

        browser_validation = browser_validation_result(
            subject,
            revision=services.state.change_revision,
            status=ValidationStatus.PASS,
            summary="Playwright verified locator candidates for the exact request subject.",
            evidence_ids=browser_evidence_ids,
            details={
                "repair_subject_id": repair_subject.gate_id,
                "failure_validation_id": binding.failure_validation_id,
                "failing_node_id": binding.failing_node_id,
                "path": binding.path,
                "workspace_revision": binding.revision,
                "workspace_git_sha": binding.git_sha,
                "workspace_fingerprint": binding.workspace_fingerprint,
                "expected_sha256": binding.expected_sha256,
            },
        )
        services.state.validation_results.extend([browser_validation, repair_subject])
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
                            "repair_subject_id": repair_subject.gate_id,
                            "repair_subject_status": repair_subject.status.value,
                            "failure_validation_id": binding.failure_validation_id,
                            "failing_node_id": binding.failing_node_id,
                            "path": binding.path,
                        }
                    )[:16000],
                }
            ],
            "is_error": repair_subject.status is not ValidationStatus.PASS,
        }

    @tool(
        "propose_locator_heal",
        "Evaluate browser-measured candidates only for one active subject-bound locator repair; does not change test code.",
        {"repair_subject_id": str, "candidates_json": str},
    )
    async def propose_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("propose_locator_heal", args)
        try:
            authority = resolve_locator_repair_authority(
                subject_id=args["repair_subject_id"],
                workspace=services.workspace,
                expected_root_identity=services.workspace_root_identity,
                state=services.state,
                evidence=services.evidence,
            )
            requested = _parse_candidates_json(args["candidates_json"])
            bound = _bind_requested_candidates(authority, requested)
        except (
            LocatorRepairAuthorityError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            RuntimeError,
            OSError,
            UnicodeError,
        ) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }

        proposal = SelfHealingEngine().propose(
            classification=authority.classification,
            original_locator=authority.original_locator,
            candidates=bound,
            evidence_ids=list(authority.validation.evidence_ids),
            policy=services.policy,
        )
        subject_details = authority.validation.details
        proposal_item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.HEALING_PROPOSAL,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="self_healing_engine",
                source_identifier=args["repair_subject_id"],
                summary="Locator healing proposal evaluated against one subject-bound browser verification",
                structured_data={
                    **proposal.model_dump(mode="json"),
                    "repair_subject_id": args["repair_subject_id"],
                    "path": authority.path,
                    "expected_sha256": authority.expected_sha256,
                    "workspace_revision": subject_details.get("workspace_revision"),
                    "workspace_git_sha": subject_details.get("workspace_git_sha"),
                    "workspace_fingerprint": subject_details.get("workspace_fingerprint"),
                    "classification": authority.classification.value,
                    "classification_confidence": authority.classification_confidence,
                    "verification_evidence_id": authority.verification.id,
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
                            "repair_subject_id": args["repair_subject_id"],
                            "proposal": proposal.model_dump(mode="json"),
                        }
                    ),
                }
            ],
            "is_error": not proposal.allowed,
        }

    @tool(
        "apply_locator_heal",
        "Apply one approved locator proposal only to the exact still-current test subject bound before browser verification.",
        {"proposal_evidence_id": str},
    )
    async def apply_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("apply_locator_heal", args)
        if reason := require_closed_revision_before_mutation(services):
            return {
                "content": [{"type": "text", "text": f"DENIED: {reason}"}],
                "is_error": True,
            }
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
            proposal_item.kind is not EvidenceKind.HEALING_PROPOSAL
            or proposal_item.nature is not EvidenceNature.MODEL_INTERPRETATION
            or proposal_item.source != "self_healing_engine"
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

        repair_subject_id = data.get("repair_subject_id")
        if not isinstance(repair_subject_id, str) or not repair_subject_id:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: healing proposal lost repair subject identity",
                    }
                ],
                "is_error": True,
            }
        try:
            authority = resolve_locator_repair_authority(
                subject_id=repair_subject_id,
                workspace=services.workspace,
                expected_root_identity=services.workspace_root_identity,
                state=services.state,
                evidence=services.evidence,
            )
            subject_details = authority.validation.details
            if (
                proposal_item.source_identifier != repair_subject_id
                or data.get("path") != authority.path
                or data.get("expected_sha256") != authority.expected_sha256
                or data.get("workspace_revision") != subject_details.get("workspace_revision")
                or data.get("workspace_git_sha") != subject_details.get("workspace_git_sha")
                or data.get("workspace_fingerprint") != subject_details.get("workspace_fingerprint")
                or data.get("classification") != authority.classification.value
                or data.get("classification_confidence") != authority.classification_confidence
                or data.get("verification_evidence_id") != authority.verification.id
                or data.get("original_locator") != authority.original_locator
                or data.get("evidence_ids") != authority.validation.evidence_ids
            ):
                raise ValueError(
                    "healing proposal authority does not match the active locator repair subject"
                )
            proposed_locator = data.get("proposed_locator")
            if not isinstance(proposed_locator, str) or not proposed_locator:
                raise ValueError("healing proposal is incomplete")
            _revalidate_proposed_locator(
                services,
                authority,
                proposed_locator=proposed_locator,
                expected_risk=data.get("risk"),
            )
        except (
            LocatorRepairAuthorityError,
            ValueError,
            TypeError,
            RuntimeError,
            OSError,
            UnicodeError,
        ) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }

        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.replace_locator_once(
                relative_path=authority.path,
                expected_sha256=authority.expected_sha256,
                old_locator=authority.original_locator,
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
                summary="Subject-bound browser-verified locator replacement applied; execution validation still required",
                structured_data={
                    "path": result.path,
                    "old_sha256": result.old_sha256,
                    "new_sha256": result.new_sha256,
                    "diff": result.diff[:12000],
                    "proposal_evidence_id": proposal_item.id,
                    "repair_subject_id": repair_subject_id,
                    "originating_revision": authority.validation.revision,
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
                    "text": f"LOCATOR_PATCH_APPLIED evidence_id={item.id} revision={services.state.change_revision}; run exact-path targeted test and full regression next",
                }
            ]
        }

    return {
        "inspect_browser": inspect_browser,
        "verify_locator_candidates": verify_locator_candidates,
        "propose_locator_heal": propose_locator_heal,
        "apply_locator_heal": apply_locator_heal,
    }
