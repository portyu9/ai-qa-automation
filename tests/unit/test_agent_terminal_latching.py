from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.agent import (
    _enforce_terminal_workspace_freshness,
    _may_recompute_terminal_outcome,
)
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)


class _Journal:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def try_append(self, event: str, **details: Any) -> None:
        self.events.append((event, details))


class _Control:
    def __init__(self) -> None:
        self.expected_workspace_fingerprint = "sha256:authorized"
        self.workspace_identity = (1, 2)
        self.journal = _Journal()


@pytest.mark.parametrize("status", [None, TerminalStatus.SUCCESS])
def test_terminal_outcome_recomputation_allows_only_unset_or_candidate_success(
    status: TerminalStatus | None,
) -> None:
    assert _may_recompute_terminal_outcome(status) is True


@pytest.mark.parametrize(
    "status",
    [status for status in TerminalStatus if status is not TerminalStatus.SUCCESS],
    ids=lambda status: status.value,
)
def test_every_non_success_terminal_truth_is_latched(status: TerminalStatus) -> None:
    assert _may_recompute_terminal_outcome(status) is False


def test_workspace_freshness_infrastructure_failure_cannot_be_promoted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = AgentRunState(
        objective="prove terminal freshness",
        workspace=str(tmp_path),
        terminal_status=TerminalStatus.SUCCESS,
        terminal_reason="candidate success",
    )
    control = _Control()
    monkeypatch.setattr(
        "ai_qa_automation.agent.observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE,
            "Workspace subject identity could not be revalidated safely.",
        ),
    )

    _enforce_terminal_workspace_freshness(
        state,
        cast(RuntimeControl, control),
        tmp_path,
    )

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert state.terminal_reason == (
        "Terminal workspace subject identity could not be revalidated safely."
    )
    assert _may_recompute_terminal_outcome(state.terminal_status) is False
    assert control.journal.events == [
        (
            "terminal_workspace_freshness_denied",
            {
                "reason_code": WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE.value,
                "terminal_status": TerminalStatus.INFRASTRUCTURE_FAILURE.value,
            },
        )
    ]
