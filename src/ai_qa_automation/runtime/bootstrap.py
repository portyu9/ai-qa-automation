from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..evidence import EvidenceStore
from ..intelligence.change_impact import ChangeImpactAnalyzer
from ..intelligence.codeowners import CodeownersResolver
from ..intelligence.contract_drift import OpenAPIContractDriftAnalyzer
from ..intelligence.repository_profile import RepositoryProfiler
from ..intelligence.test_impact import TestImpactMapper
from ..models import AgentRunState, EvidenceItem, EvidenceKind, EvidenceNature
from ..state import StateStore
from ..tools.repository import RepositoryChangeSet, RepositoryInspector
from .run_control import RuntimeControl

_DEPENDENCY_MANIFESTS = {
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
}


def _dependency_inventory(workspace: Path, *, max_files: int = 100) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ignored = {".git", ".venv", "venv", "node_modules", "dist", "build", ".tox"}
    for path in sorted(workspace.rglob("*")):
        if len(rows) >= max_files:
            break
        if path.is_symlink() or not path.is_file() or path.name not in _DEPENDENCY_MANIFESTS:
            continue
        relative = path.relative_to(workspace)
        if any(part in ignored for part in relative.parts):
            continue
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(chunk)
                    digest.update(chunk)
        except OSError:
            continue
        rows.append({"path": relative.as_posix(), "size": size, "sha256": digest.hexdigest()})
    return rows


def bootstrap_runtime_context(
    *,
    workspace: Path,
    state: AgentRunState,
    evidence: EvidenceStore,
    state_store: StateStore,
    control: RuntimeControl,
    baseline_ref: str | None = None,
) -> str:
    """Capture deterministic repository/change/ownership/contract/dependency context."""
    inspector = RepositoryInspector(workspace)
    if baseline_ref is None:
        baseline_ref = os.environ.get("AI_QA_BASE_REF") or None
    snapshot = inspector.snapshot()
    state.target_git_sha = snapshot.git_sha
    control.set_workspace_fingerprint(snapshot.fingerprint)

    change_set: RepositoryChangeSet | None = None
    baseline_error: str | None = None
    changed_files = snapshot.changed_files
    if baseline_ref:
        try:
            change_set = inspector.change_set(baseline_ref)
        except (OSError, RuntimeError, ValueError) as exc:
            baseline_error = f"{type(exc).__name__}: {str(exc)[:500]}"
        else:
            changed_files = change_set.changed_files

    impact = ChangeImpactAnalyzer().assess(changed_files)
    impact_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_change_impact",
            source_identifier=snapshot.fingerprint,
            summary=f"Deterministic change impact assessed as {impact.risk.value}",
            structured_data={
                "assessment": impact.as_dict(),
                "baseline": change_set.as_dict() if change_set else None,
                "baseline_error": baseline_error,
            },
        )
    )

    profile = RepositoryProfiler().profile(workspace)
    profile_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_repository_profile",
            summary="Observed bounded repository technology/test topology",
            structured_data={"profile": profile.as_dict()},
        )
    )

    dependencies = _dependency_inventory(workspace)
    dependency_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_dependency_inventory",
            summary=f"Observed {len(dependencies)} dependency manifest(s)",
            structured_data={"manifests": dependencies},
        )
    )

    test_impact = TestImpactMapper().map(workspace, changed_files)
    test_impact_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_test_impact",
            summary=f"Mapped {len(test_impact.candidates)} deterministic test-impact candidate(s)",
            structured_data={"test_impact": test_impact.as_dict()},
        )
    )

    ownership = CodeownersResolver.from_workspace(workspace).resolve(changed_files)
    ownership_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_codeowners",
            summary=(
                f"Resolved CODEOWNERS for {len(ownership.ownership_by_file)} changed file(s)"
                if ownership.source_path
                else "No CODEOWNERS file observed"
            ),
            structured_data={"ownership": ownership.as_dict()},
        )
    )

    contract_reports = _contract_drift_reports(
        workspace=workspace,
        inspector=inspector,
        change_set=change_set,
        changed_files=changed_files,
    )
    contract_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_contract_drift",
            source_identifier=change_set.merge_base_sha if change_set else None,
            summary=f"Evaluated {len(contract_reports)} changed interface contract(s)",
            structured_data={"reports": contract_reports},
        )
    )

    items = (impact_item, profile_item, dependency_item, test_impact_item, ownership_item, contract_item)
    for item in items:
        if item.id not in state.evidence_ids:
            state.evidence_ids.append(item.id)

    breaking_contracts = sum(
        1 for item in contract_reports if item.get("severity") == "BREAKING"
    )
    control.journal.append(
        "runtime_bootstrap",
        workspace_fingerprint=snapshot.fingerprint,
        git_sha=snapshot.git_sha,
        baseline_ref=baseline_ref,
        baseline_resolved=change_set is not None,
        baseline_error=baseline_error,
        changed_file_count=len(changed_files),
        change_risk=impact.risk.value,
        dependency_manifest_count=len(dependencies),
        test_impact_candidate_count=len(test_impact.candidates),
        test_impact_confidence=test_impact.confidence,
        codeowners_source=ownership.source_path,
        owned_changed_file_count=len(ownership.ownership_by_file),
        unowned_changed_file_count=len(ownership.unowned_files),
        contract_report_count=len(contract_reports),
        breaking_contract_count=breaking_contracts,
        repository_languages=list(profile.languages),
        repository_test_surfaces=list(profile.test_surfaces),
    )
    state_store.save(state)
    control.persist()

    context = {
        "repository": {
            "git_sha": snapshot.git_sha,
            "dirty": bool(snapshot.status),
            "worktree_changed_files": list(snapshot.changed_files[:100]),
            "workspace_fingerprint": snapshot.fingerprint,
        },
        "baseline_change_set": change_set.as_dict() if change_set else None,
        "baseline_resolution_error": baseline_error,
        "change_impact": impact.as_dict(),
        "test_impact": test_impact.as_dict(),
        "ownership": ownership.as_dict(),
        "contract_drift": contract_reports[:25],
        "repository_profile": profile.as_dict(),
        "dependency_manifests": [row["path"] for row in dependencies],
        "evidence_ids": [item.id for item in items],
    }
    rendered = json.dumps(context, sort_keys=True, default=str)
    return rendered[:24000]


def _contract_drift_reports(
    *,
    workspace: Path,
    inspector: RepositoryInspector,
    change_set: RepositoryChangeSet | None,
    changed_files: tuple[str, ...],
    max_files: int = 20,
    max_bytes: int = 2_000_000,
) -> list[dict[str, object]]:
    if change_set is None:
        return []
    analyzer = OpenAPIContractDriftAnalyzer()
    reports: list[dict[str, object]] = []
    candidates = [path for path in changed_files if _looks_like_openapi_contract(path)]
    for relative in candidates[:max_files]:
        current_path = (workspace / relative).resolve()
        try:
            current_path.relative_to(workspace)
        except ValueError:
            continue
        try:
            baseline = inspector.read_file_at(change_set.merge_base_sha, relative, max_bytes=max_bytes)
        except FileNotFoundError:
            if current_path.is_file() and not current_path.is_symlink():
                reports.append(
                    {
                        "path": relative,
                        "contract_kind": "openapi",
                        "severity": "NON_BREAKING",
                        "changes": [
                            {
                                "severity": "NON_BREAKING",
                                "location": relative,
                                "rule_id": "OAS-CONTRACT-ADDED",
                                "summary": "OpenAPI contract file added relative to baseline",
                            }
                        ],
                        "analyzed": True,
                        "reason": None,
                    }
                )
            continue
        except (OSError, RuntimeError, ValueError) as exc:
            reports.append(
                {
                    "path": relative,
                    "contract_kind": "openapi",
                    "severity": "NOT_ANALYZED",
                    "changes": [],
                    "analyzed": False,
                    "reason": f"baseline read failed: {type(exc).__name__}",
                }
            )
            continue
        if not current_path.exists():
            reports.append(
                {
                    "path": relative,
                    "contract_kind": "openapi",
                    "severity": "BREAKING",
                    "changes": [
                        {
                            "severity": "BREAKING",
                            "location": relative,
                            "rule_id": "OAS-CONTRACT-REMOVED",
                            "summary": "OpenAPI contract file removed relative to baseline",
                        }
                    ],
                    "analyzed": True,
                    "reason": None,
                }
            )
            continue
        if current_path.is_symlink() or not current_path.is_file():
            reports.append(
                {
                    "path": relative,
                    "contract_kind": "openapi",
                    "severity": "NOT_ANALYZED",
                    "changes": [],
                    "analyzed": False,
                    "reason": "current contract is not a regular file",
                }
            )
            continue
        try:
            if current_path.stat().st_size > max_bytes:
                raise ValueError("current contract exceeds analysis size limit")
            current = current_path.read_bytes()
        except (OSError, ValueError) as exc:
            reports.append(
                {
                    "path": relative,
                    "contract_kind": "openapi",
                    "severity": "NOT_ANALYZED",
                    "changes": [],
                    "analyzed": False,
                    "reason": f"current read failed: {type(exc).__name__}",
                }
            )
            continue
        reports.append(analyzer.analyze(path=relative, baseline=baseline, current=current).as_dict())
    if len(candidates) > max_files:
        reports.append(
            {
                "path": "<contract-overflow>",
                "contract_kind": "openapi",
                "severity": "NOT_ANALYZED",
                "changes": [],
                "analyzed": False,
                "reason": f"contract analysis limited to {max_files} changed files",
            }
        )
    return reports


def _looks_like_openapi_contract(relative: str) -> bool:
    lower = relative.casefold().replace("\\", "/")
    suffix = Path(lower).suffix
    return suffix in {".json", ".yaml", ".yml"} and (
        "openapi" in lower or "swagger" in lower or lower.endswith(("/oas.json", "/oas.yaml", "/oas.yml"))
    )
