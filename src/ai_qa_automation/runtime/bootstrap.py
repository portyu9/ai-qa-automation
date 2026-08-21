from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..evidence import EvidenceStore
from ..intelligence.change_impact import ChangeImpactAnalyzer
from ..intelligence.repository_profile import RepositoryProfiler
from ..models import AgentRunState, EvidenceItem, EvidenceKind, EvidenceNature
from ..state import StateStore
from ..tools.repository import RepositoryInspector
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
) -> str:
    """Capture deterministic repository/change/dependency context before model execution."""
    snapshot = RepositoryInspector(workspace).snapshot()
    state.target_git_sha = snapshot.git_sha
    control.set_workspace_fingerprint(snapshot.fingerprint)

    impact = ChangeImpactAnalyzer().assess(snapshot.changed_files)
    impact_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="runtime_bootstrap_change_impact",
            source_identifier=snapshot.fingerprint,
            summary=f"Deterministic change impact assessed as {impact.risk.value}",
            structured_data={"assessment": impact.as_dict()},
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
    for item in (impact_item, profile_item, dependency_item):
        if item.id not in state.evidence_ids:
            state.evidence_ids.append(item.id)

    control.journal.append(
        "runtime_bootstrap",
        workspace_fingerprint=snapshot.fingerprint,
        git_sha=snapshot.git_sha,
        changed_file_count=len(snapshot.changed_files),
        change_risk=impact.risk.value,
        dependency_manifest_count=len(dependencies),
        repository_languages=list(profile.languages),
        repository_test_surfaces=list(profile.test_surfaces),
    )
    state_store.save(state)
    control.persist()

    context = {
        "repository": {
            "git_sha": snapshot.git_sha,
            "dirty": bool(snapshot.status),
            "changed_files": list(snapshot.changed_files[:100]),
            "workspace_fingerprint": snapshot.fingerprint,
        },
        "change_impact": impact.as_dict(),
        "repository_profile": profile.as_dict(),
        "dependency_manifests": [row["path"] for row in dependencies],
        "evidence_ids": [impact_item.id, profile_item.id, dependency_item.id],
    }
    rendered = json.dumps(context, sort_keys=True, default=str)
    return rendered[:16000]
