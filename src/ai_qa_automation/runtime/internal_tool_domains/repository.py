from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...models import EvidenceItem, EvidenceKind, EvidenceNature
from ...redaction import redact_text
from ...tools.repository import RepositoryInspector
from ..model_source_observation import read_model_source_confined
from .common import MAX_MODEL_SOURCE_CHARS, RuntimeServices, ToolDecorator, coverage_search


def register_repository_tools(services: RuntimeServices, tool: ToolDecorator) -> dict[str, Any]:
    @tool("inspect_repository", "Inspect target Git metadata without modifying it.", {})
    async def inspect_repository(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_repository", args)
        snapshot = RepositoryInspector(services.workspace).snapshot()
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                nature=EvidenceNature.OBSERVED_FACT,
                source="repository",
                summary="Observed target repository state",
                structured_data={
                    "git_sha": snapshot.git_sha,
                    "branch": snapshot.branch,
                    "dirty": bool(snapshot.status),
                    "changed_files": list(snapshot.changed_files),
                    "fingerprint_complete": snapshot.fingerprint_complete,
                    "fingerprint_incomplete_reasons": list(snapshot.fingerprint_incomplete_reasons),
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.target_git_sha = snapshot.git_sha
        services.checkpoint()
        return {"content": [{"type": "text", "text": item.model_dump_json()}]}

    @tool(
        "read_test_file",
        "Read a UTF-8 test file after deterministic path authorization.",
        {"path": str},
    )
    async def read_test_file(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("read_test_file", args)
        relative = Path(args["path"])
        decision = services.policy.authorize_path(relative, write=False)
        services.state.policy_decisions.append(decision)
        if decision.decision.value != "ALLOW":
            return {
                "content": [
                    {"type": "text", "text": f"DENIED {decision.rule_id}: {decision.reason}"}
                ],
                "is_error": True,
            }
        if relative.suffix.lower() not in {".py", ".ts", ".js", ".java", ".cs"}:
            return {
                "content": [
                    {"type": "text", "text": "DENIED: file is not an approved test-code type"}
                ],
                "is_error": True,
            }
        try:
            observed = read_model_source_confined(
                services.workspace,
                relative,
                expected_root_identity=services.workspace_root_identity,
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        text = redact_text(observed.text[:MAX_MODEL_SOURCE_CHARS])
        services.state.files_read.append(relative.as_posix())
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "path": relative.as_posix(),
                            "sha256": observed.sha256,
                            "content": text,
                            "truncated": len(observed.text) > MAX_MODEL_SOURCE_CHARS,
                            "size_bytes": observed.size_bytes,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "search_test_coverage",
        "Search bounded test-code paths/content and record observed repository coverage evidence.",
        {"query": str, "max_results": int},
    )
    async def search_test_coverage(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("search_test_coverage", args)
        raw_query = str(args.get("query", ""))
        try:
            observed = coverage_search(
                services.workspace,
                query=raw_query,
                max_results=int(args.get("max_results", 100)),
                expected_root_identity=services.workspace_root_identity,
            )
        except (ValueError, OSError, RuntimeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        redacted_query = redact_text(raw_query)
        structured = observed.as_structured_data(query=redacted_query)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                nature=EvidenceNature.OBSERVED_FACT,
                source="repository_test_coverage_search",
                source_identifier=redacted_query,
                summary=(
                    f"Observed {len(observed.results)} bounded test coverage search result(s); "
                    f"complete={observed.complete}"
                ),
                structured_data=structured,
            )
        )
        services.state.evidence_ids.append(item.id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "coverage_evidence_id": item.id,
                            "results": structured["results"],
                            "complete": observed.complete,
                            "incomplete_reasons": list(observed.incomplete_reasons),
                        }
                    )[:16000],
                }
            ]
        }

    return {
        "inspect_repository": inspect_repository,
        "read_test_file": read_test_file,
        "search_test_coverage": search_test_coverage,
    }
