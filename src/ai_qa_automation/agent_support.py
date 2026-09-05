from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from .config import Settings
from .models import AgentRunState, TerminalStatus
from .reporting import build_final_report
from .runtime.run_control import RuntimeControl
from .state import StateStore
from .tools.repository import RepositoryInspector

_DEFAULT_LIMITATIONS = [
    "A model response is not a test result; only deterministic validations can produce verified success.",
    "External MCP capability remains NOT_VERIFIED unless authenticated and exercised in this environment.",
    "Crash recovery verifies persisted state/journal integrity and starts a new model session; it does not replay a prior conversation.",
]


def _may_recompute_terminal_outcome(status: TerminalStatus | None) -> bool:
    """Allow generic SDK-success evaluation only without prior failure truth.

    Candidate SUCCESS remains recomputable so later deterministic evidence can demote
    it. Every non-success terminal state is monotonic by default, including future
    enum additions, unless a separately reviewed recovery path explicitly changes it.
    """

    return status is None or status is TerminalStatus.SUCCESS


def validate_runtime_roots(
    control_root: Path,
    workspace: Path,
    *,
    artifact_root: Path | None = None,
) -> None:
    """Require trusted control, target, and artifact roots to remain disjoint."""

    control = control_root.expanduser().resolve()
    target = workspace.expanduser().resolve()
    if _paths_overlap(control, target):
        raise ValueError("control_root and target workspace must be disjoint")
    if artifact_root is not None:
        artifacts = artifact_root.expanduser().resolve()
        if _paths_overlap(artifacts, target):
            raise ValueError("artifact_root and target workspace must be disjoint")

    required = [
        control / "CLAUDE.md",
        control / ".claude" / "settings.json",
    ]
    missing = [str(path.relative_to(control)) for path in required if not path.is_file()]
    if missing:
        raise ValueError(
            "control_root is missing trusted runtime configuration: " + ", ".join(missing)
        )


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        right.relative_to(left)
        return True
    except ValueError:
        pass
    try:
        left.relative_to(right)
        return True
    except ValueError:
        return False


def _observe_control_git_subject(control_root: Path) -> tuple[str | None, bool | None]:
    """Record Git identity when safely observable without making it sufficient authority."""

    try:
        snapshot = RepositoryInspector(control_root).snapshot()
    except (OSError, RuntimeError, ValueError):
        return None, None
    if not snapshot.fingerprint_complete or snapshot.git_sha is None:
        return None, None
    return snapshot.git_sha, snapshot.status == ""


def configuration_fingerprint(settings: Settings) -> str:
    """Bind provenance to the complete trusted runtime configuration."""

    payload = settings.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _sync_operational_state(
    state: AgentRunState,
    state_store: StateStore,
    control: RuntimeControl,
) -> None:
    """Persist QA state and runtime authority without duplicating control-plane fields."""

    state_store.save(state)
    control.persist()


def _final_response(
    state: AgentRunState,
    *,
    agent_result: str,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    resolved_limitations = list(_DEFAULT_LIMITATIONS)
    for limitation in limitations or []:
        if limitation not in resolved_limitations:
            resolved_limitations.append(limitation)
    return {
        "report": build_final_report(state, limitations=resolved_limitations).model_dump(
            mode="json"
        ),
        "agent_result": agent_result,
    }


def sdk_exception_outcome(exc: BaseException) -> tuple[TerminalStatus, str]:
    """Classify SDK failures conservatively without depending on private SDK exception types."""

    text = f"{type(exc).__name__}: {exc}".casefold()
    if any(
        marker in text
        for marker in (
            "authentication",
            "unauthorized",
            "401",
            "403",
            "invalid api key",
            "invalid_api_key",
        )
    ):
        return (
            TerminalStatus.BLOCKED,
            f"Agent SDK authentication/authorization failed: {type(exc).__name__}",
        )
    if any(
        marker in text
        for marker in (
            "connection",
            "connecterror",
            "timeout",
            "timed out",
            "network",
            "unavailable",
            "overloaded",
            "rate limit",
            "rate_limit",
            "429",
            "529",
        )
    ):
        return (
            TerminalStatus.INFRASTRUCTURE_FAILURE,
            f"Agent SDK/provider transport failed: {type(exc).__name__}",
        )
    return TerminalStatus.FAILURE, f"Agent SDK execution failed: {type(exc).__name__}"


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        return "NOT_VERIFIED"
